package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"spectral/internal/adws"
	"spectral/internal/enum"
	"spectral/internal/opsec"
	"spectral/internal/output"
	"spectral/internal/recon"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [options]

Connection:
  -t  string   Target DC address (IP or hostname)  [required]
  -d  string   Domain FQDN (e.g. corp.local — NOT the NetBIOS short name)
  -u  string   Username
  -p  string   Password
  -H  string   NT hash (pass-the-hash)
  -k           Use Kerberos (reads KRB5CCNAME env or -c path)
  -c  string   Kerberos ccache path
  -r  string   ADWS port (default: 9389)
  -l  string   LDAP port for rootdse (default: 389)

Enumeration:
  -m  string   Modes, comma-separated
               Unauthenticated: rootdse
               Sweep:    users, computers, groups, gpos, trusts, domain
               Targeted: kerberoastable, asreproast, unconstrained,
                         constrained, rbcd, admincount, shadowcreds,
                         laps, pwdnoexpire, stale, fgpp, adcs
               Shorthand: all (sweep), attack (targeted), everything (both)

  -T  string   Single object lookup: <type>:<name>
               Types: user, computer, group, ou
               Examples: -T user:jdoe  -T "group:Domain Admins"

  -A  int      Stale threshold in days for -m stale (default: 90)
  -b  string   Base DN (auto-derived from -d if omitted)

Output & pacing:
  -o  string   Output directory (default: .)
  -j  int      Jitter between requests ms (default: 500)
  -P  int      Pause between object types ms (default: 2000)
  -B  int      Batch size per ADWS pull (default: 100)
  -q           Quiet
  -x           Debug SOAP XML
  -bh          Also write BloodHound CE zip (users/computers/groups/gpos/trusts)
`, os.Args[0])
}

func main() {
	var (
		target    = flag.String("t", "", "")
		ldapPort  = flag.String("l", "389", "")
		domain    = flag.String("d", "", "")
		username  = flag.String("u", "", "")
		password  = flag.String("p", "", "")
		ntHash    = flag.String("H", "", "")
		useKerb   = flag.Bool("k", false, "")
		ccache    = flag.String("c", "", "")
		baseDN    = flag.String("b", "", "")
		mode      = flag.String("m", "", "")
		targetObj = flag.String("T", "", "")
		staleDays = flag.Int("A", 90, "")
		outDir    = flag.String("o", "spectral_output", "")
		jitterMs  = flag.Int("j", 500, "")
		pauseMs   = flag.Int("P", 2000, "")
		batch     = flag.Int("B", 100, "")
		port      = flag.String("r", "9389", "")
		quiet     = flag.Bool("q", false, "")
		debugXML  = flag.Bool("x", false, "")
		bhOut     = flag.Bool("bh", false, "")
	)

	flag.Usage = usage
	flag.Parse()

	output.PrintBanner()

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *mode == "" && *targetObj == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		log.Fatalf("[-] Output dir: %v", err)
	}

	w := output.NewWriter(*outDir, !*quiet)
	modes := expandModes(*mode)

	// ── Unauthenticated rootDSE — runs before any ADWS connection ──────
	if contains(modes, "rootdse") {
		if !*quiet {
			log.Printf("[*] Querying rootDSE on %s:%s (no credentials)", *target, *ldapPort)
		}
		dse, err := recon.QueryRootDSE(*target, *ldapPort)
		if err != nil {
			log.Printf("[-] rootDSE: %v", err)
		} else {
			output.PrintRootDSE(dse)
			w.Write("rootdse.json", dse)
		}
		modes = filterOut(modes, "rootdse")
	}

	// If nothing left to do, exit.
	if len(modes) == 0 && *targetObj == "" {
		if !*quiet {
			log.Printf("[+] Done. Output saved to: %s", *outDir)
		}
		return
	}

	// ── ADWS modes require domain + credentials ─────────────────────────
	if *domain == "" {
		log.Fatalf("[-] -d (domain) is required for ADWS enumeration")
	}

	if *ccache == "" {
		if v := os.Getenv("KRB5CCNAME"); v != "" {
			*ccache = v
		}
	}

	cfg := adws.Config{
		Target:   *target,
		Port:     *port,
		Domain:   *domain,
		Username: *username,
		Password: *password,
		NTHash:   *ntHash,
		CCache:   *ccache,
		Kerberos: *useKerb,
		DebugXML: *debugXML,
	}

	pace := opsec.NewPacer(
		time.Duration(*jitterMs)*time.Millisecond,
		time.Duration(*pauseMs)*time.Millisecond,
	)

	client, err := adws.NewClient(cfg)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}
	if err := client.Connect(); err != nil {
		log.Fatalf("[-] Connect: %v", err)
	}
	defer client.Close()

	if !*quiet {
		log.Printf("[+] Connected to %s:%s", *target, *port)
	}

	if *baseDN == "" {
		*baseDN = domainToBaseDN(*domain)
	}

	e := enum.New(client, pace, *batch, *baseDN, !*quiet)

	// collector holds sweep results for optional BH output.
	coll := &collector{}

	// ── Single object lookup ────────────────────────────────────────────
	if *targetObj != "" {
		runLookup(e, w, *targetObj)
	}

	// ── Mode-based enumeration ──────────────────────────────────────────
	for i, m := range modes {
		runModeCollect(e, w, m, *staleDays, coll)
		if i < len(modes)-1 {
			pace.BetweenTypes()
		}
	}

	// ── BloodHound CE output ────────────────────────────────────────────
	if *bhOut {
		domainSID := coll.domainSID
		if domainSID == "" && !*quiet {
			log.Printf("[*] -bh: domain SID not resolved (run with -m all or -m users to populate)")
		}
		if err := output.WriteBHZip(
			*outDir, *domain, domainSID,
			coll.users, coll.computers, coll.groups, coll.gpos, coll.trusts,
		); err != nil {
			log.Printf("[-] BloodHound zip: %v", err)
		}
	}

	if !*quiet {
		log.Printf("[+] Done. Output saved to: %s", *outDir)
	}
}

// collector accumulates sweep results for BloodHound output.
type collector struct {
	users     []adws.ADObject
	computers []adws.ADObject
	groups    []adws.ADObject
	gpos      []adws.ADObject
	trusts    []adws.ADObject
	domainSID string
}

// runModeCollect wraps runMode and captures sweep results into the collector.
func runModeCollect(e *enum.Enumerator, w *output.Writer, m string, staleDays int, coll *collector) {
	type result struct {
		data interface{}
		err  error
	}
	var res result

	switch m {
	case "users":
		data, err := e.Users()
		res.data, res.err = data, err
		if err == nil {
			coll.users = data
			// Derive domainSID from first user SID (strip last RID component).
			if len(data) > 0 && coll.domainSID == "" {
				coll.domainSID = domainSIDFromObject(data[0])
			}
		}
	case "computers":
		data, err := e.Computers()
		res.data, res.err = data, err
		if err == nil {
			coll.computers = data
		}
	case "groups":
		data, err := e.Groups()
		res.data, res.err = data, err
		if err == nil {
			coll.groups = data
		}
	case "gpos":
		data, err := e.GPOs()
		res.data, res.err = data, err
		if err == nil {
			coll.gpos = data
		}
	case "trusts":
		data, err := e.Trusts()
		res.data, res.err = data, err
		if err == nil {
			coll.trusts = data
		}
	default:
		runMode(e, w, m, staleDays)
		return
	}

	if res.err != nil {
		log.Printf("[-] %s: %v", m, res.err)
		return
	}
	w.Write(m+".json", res.data)
}

// runMode dispatches a single mode string to the appropriate enumerator.
func runMode(e *enum.Enumerator, w *output.Writer, m string, staleDays int) {
	type result struct {
		data interface{}
		err  error
	}

	var res result

	switch m {
	case "domain":
		res.data, res.err = e.Domain()
	case "users":
		res.data, res.err = e.Users()
	case "computers":
		res.data, res.err = e.Computers()
	case "groups":
		res.data, res.err = e.Groups()
	case "gpos":
		res.data, res.err = e.GPOs()
	case "trusts":
		res.data, res.err = e.Trusts()
	case "kerberoastable":
		res.data, res.err = e.Kerberoastable()
	case "asreproast":
		res.data, res.err = e.ASREPRoastable()
	case "unconstrained":
		res.data, res.err = e.UnconstrainedDelegation()
	case "constrained":
		res.data, res.err = e.ConstrainedDelegation()
	case "rbcd":
		res.data, res.err = e.RBCD()
	case "admincount":
		res.data, res.err = e.AdminCount()
	case "shadowcreds":
		res.data, res.err = e.ShadowCredentials()
	case "laps":
		res.data, res.err = e.LAPS()
	case "pwdnoexpire":
		res.data, res.err = e.PasswordNeverExpires()
	case "stale":
		res.data, res.err = e.StaleAccounts(staleDays)
	case "fgpp":
		res.data, res.err = e.FineGrainedPasswordPolicies()
	case "adcs":
		adcsResult, adcsErr := e.ADCS()
		res.data, res.err = adcsResult, adcsErr
		if adcsErr == nil {
			output.PrintADCS(adcsResult)
		}
	default:
		log.Printf("[-] Unknown mode: %s", m)
		return
	}

	if res.err != nil {
		log.Printf("[-] %s: %v", m, res.err)
		return
	}

	w.Write(m+".json", res.data)
}

// runLookup handles -T type:name lookups.
func runLookup(e *enum.Enumerator, w *output.Writer, spec string) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		log.Fatalf("[-] -T format: <type>:<name>  e.g. user:jdoe")
	}
	kind, name := strings.ToLower(parts[0]), parts[1]

	var (
		data interface{}
		err  error
		file string
	)

	switch kind {
	case "user":
		data, err = e.LookupUser(name)
		file = "lookup-user-" + sanitise(name) + ".json"
	case "computer":
		data, err = e.LookupComputer(name)
		file = "lookup-computer-" + sanitise(name) + ".json"
	case "group":
		result, gerr := e.LookupGroup(name)
		data, err = result, gerr
		if gerr == nil {
			output.PrintGroupMembers(result)
		}
		file = "lookup-group-" + sanitise(name) + ".json"
	case "ou":
		data, err = e.LookupOU(name)
		file = "lookup-ou.json"
	default:
		log.Fatalf("[-] Unknown -T type: %s (valid: user, computer, group, ou)", kind)
	}

	if err != nil {
		log.Printf("[-] Lookup %s: %v", spec, err)
		return
	}
	w.Write(file, data)
}

// expandModes resolves shorthands.
func expandModes(m string) []string {
	if m == "" {
		return nil
	}
	sweepAll := []string{"domain", "users", "computers", "groups", "gpos", "trusts"}
	attackAll := []string{
		"kerberoastable", "asreproast", "unconstrained", "constrained",
		"rbcd", "admincount", "shadowcreds", "laps", "pwdnoexpire", "fgpp", "adcs",
	}
	switch m {
	case "all":
		return sweepAll
	case "attack":
		return attackAll
	case "everything":
		return append(sweepAll, attackAll...)
	}
	return strings.Split(m, ",")
}

// domainSIDFromObject extracts the domain SID from an AD object's objectSid
// by stripping the last RID component (e.g. S-1-5-21-X-Y-Z-500 → S-1-5-21-X-Y-Z).
func domainSIDFromObject(obj adws.ADObject) string {
	sid := enum.SIDStr(obj, "objectSid")
	if sid == "" {
		return ""
	}
	idx := strings.LastIndex(sid, "-")
	if idx < 0 {
		return sid
	}
	return sid[:idx]
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

func sanitise(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func filterOut(ss []string, exclude string) []string {
	out := ss[:0]
	for _, v := range ss {
		if v != exclude {
			out = append(out, v)
		}
	}
	return out
}
