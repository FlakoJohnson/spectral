package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"spectral/internal/adws"
	"spectral/internal/enum"
	"spectral/internal/opsec"
	"spectral/internal/output"
	"spectral/internal/recon"
)

const (
	reset = "\033[0m"
	bold  = "\033[1m"
	red   = "\033[31m"
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
               Sweep:    users, computers, groups, gpos, trusts, ous, domain
               Targeted: kerberoastable, asreproast, unconstrained,
                         constrained, rbcd, admincount, shadowcreds,
                         laps, pwdnoexpire, stale, fgpp, adcs

               Shorthand:
                 sweep    — all sweep modes (users, computers, groups, gpos, trusts, domain)
                 targeted — all attack-path modes (kerberoastable, asreproast, delegation, etc.)
                 full     — sweep + targeted combined

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

Stealth (enabled by default):
  --no-stealth Disable stealth features (faster but noisier — may trigger MDI)
  -Bmin int    Minimum batch size for randomization (default: 75)
  -Bmax int    Maximum batch size for randomization (default: 125)

Proxy:
  -proxy string  SOCKS5 proxy URL  (e.g. socks5://127.0.0.1:1080)
               Also reads ALL_PROXY / SOCKS5_PROXY env vars if flag is omitted.
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
		proxyURL  = flag.String("proxy", "", "")
		noStealth = flag.Bool("no-stealth", false, "")
		batchMin  = flag.Int("Bmin", 75, "")
		batchMax  = flag.Int("Bmax", 125, "")
	)

	log.SetFlags(0) // disable default timestamp — we use our own

	flag.Usage = usage
	flag.Parse()

	// Fall back to standard proxy env vars if -proxy not set.
	if *proxyURL == "" {
		for _, env := range []string{"SOCKS5_PROXY", "ALL_PROXY", "all_proxy"} {
			if v := os.Getenv(env); v != "" {
				*proxyURL = v
				break
			}
		}
	}

	stealth := !*noStealth

	if stealth {
		output.PrintBannerStealth()
	} else {
		output.PrintBanner()
		fmt.Printf("  %s%s[!] WARNING: Stealth disabled (--no-stealth). Queries may trigger MDI alerts.%s\n\n",
			bold, red, reset)
	}

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *mode == "" && *targetObj == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Build evidence-keeping prefix: IP_YYYYMMDD_HHMMSS
	dateStr := time.Now().Format("20060102_150405")
	filePrefix := fmt.Sprintf("%s_%s", *target, dateStr)

	// Output directory: <base>/<IP>_<YYYYMMDD>/
	if *outDir == "spectral_output" {
		*outDir = filePrefix
	}

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		log.Fatalf("%s [-] Output dir: %v", ts(), err)
	}

	w := output.NewWriter(*outDir, filePrefix, !*quiet)

	// Print target info after banner
	if !*quiet {
		output.PrintTargetInfo(*target, *domain, *username, *outDir, stealth)
	}
	modes := expandModes(*mode)

	// Stealth: randomize enumeration order to avoid behavioral fingerprinting
	if stealth {
		// Separate rootdse (must run first) from other modes
		hasRootDSE := contains(modes, "rootdse")
		modes = filterOut(modes, "rootdse")
		rand.Shuffle(len(modes), func(i, j int) { modes[i], modes[j] = modes[j], modes[i] })
		if hasRootDSE {
			modes = append([]string{"rootdse"}, modes...)
		}
	}

	// ── Unauthenticated rootDSE — runs before any ADWS connection ──────
	if contains(modes, "rootdse") {
		if !*quiet {
			log.Printf("%s [*] Querying rootDSE on %s:%s (no credentials)", ts(), *target, *ldapPort)
		}
		dse, err := recon.QueryRootDSE(*target, *ldapPort, *proxyURL)
		if err != nil {
			log.Printf("%s [-] rootDSE: %v", ts(), err)
		} else {
			output.PrintRootDSE(dse)
			w.Write("rootdse.json", dse)
		}
		modes = filterOut(modes, "rootdse")
	}

	// If nothing left to do, exit.
	if len(modes) == 0 && *targetObj == "" {
		if !*quiet {
			log.Printf("%s [+] Done. Output saved to: %s", ts(), *outDir)
		}
		return
	}

	// ── ADWS modes require domain + credentials ─────────────────────────
	if *domain == "" {
		log.Fatalf("%s [-] -d (domain) is required for ADWS enumeration", ts())
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
		ProxyURL: *proxyURL,
	}

	pace := opsec.NewPacer(
		time.Duration(*jitterMs)*time.Millisecond,
		time.Duration(*pauseMs)*time.Millisecond,
	)

	// Stealth: random delay before ADWS connection (1-5s)
	if stealth {
		delay := time.Duration(1000+rand.Intn(4000)) * time.Millisecond
		time.Sleep(delay)
	}

	client, err := adws.NewClient(cfg)
	if err != nil {
		log.Fatalf("%s [-] %v", ts(), err)
	}
	if err := client.Connect(); err != nil {
		log.Fatalf("%s [-] Connect: %v", ts(), err)
	}
	defer client.Close()

	if !*quiet {
		log.Printf("%s [+] Connected to %s:%s via ADWS", ts(), *target, *port)
	}

	if *baseDN == "" {
		*baseDN = domainToBaseDN(*domain)
	}

	var e *enum.Enumerator
	if stealth {
		e = enum.NewStealth(client, pace, *batchMin, *batchMax, *baseDN, *target, !*quiet)
	} else {
		e = enum.New(client, pace, *batch, *baseDN, *target, !*quiet)
	}

	// collector holds sweep results for optional BH output.
	coll := &collector{}

	// ── Single object lookup ────────────────────────────────────────────
	if *targetObj != "" {
		runLookup(e, w, *targetObj, coll)
	}

	// ── Mode-based enumeration ──────────────────────────────────────────
	for i, m := range modes {
		runModeCollect(e, w, m, *staleDays, coll)
		if i < len(modes)-1 {
			pace.BetweenTypes()
		}
	}

	// ── BloodHound CE output ────────────────────────────────────────────
	// Auto-generate BH zip whenever compatible data was collected,
	// or when explicitly requested with -bh.
	hasBHData := len(coll.users) > 0 || len(coll.computers) > 0 ||
		len(coll.groups) > 0 || len(coll.gpos) > 0 || len(coll.trusts) > 0 ||
		coll.domainInfo != nil
	if *bhOut || hasBHData {
		domainSID := coll.domainSID
		if domainSID == "" && !*quiet {
			log.Printf("%s [*] domain SID not resolved (run with -m sweep or -m users to populate)", ts())
		}
		if err := output.WriteBHZip(
			*outDir, filePrefix, *domain, domainSID,
			coll.users, coll.computers, coll.groups, coll.gpos, coll.trusts,
			coll.domainInfo,
		); err != nil {
			log.Printf("%s [-] BloodHound zip: %v", ts(), err)
		}
	}

	if !*quiet {
		log.Printf("%s [+] Done. Output saved to: %s", ts(), *outDir)
	}
}

// collector accumulates sweep results for BloodHound output.
type collector struct {
	users      []adws.ADObject
	computers  []adws.ADObject
	groups     []adws.ADObject
	gpos       []adws.ADObject
	trusts     []adws.ADObject
	domainSID  string
	domainInfo *enum.DomainResult
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
			output.PrintUsers(data)
		}
	case "domain":
		data, err := e.Domain()
		res.data, res.err = data, err
		if err == nil {
			coll.domainInfo = data
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
			output.PrintGroups(data)
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
		log.Printf("%s [-] %s: %v", ts(), m, res.err)
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
	case "ous":
		data, err := e.OUs()
		res.data, res.err = data, err
		if err == nil {
			output.PrintOUs(data)
		}
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
		log.Printf("%s [-] Unknown mode: %s", ts(), m)
		return
	}

	if res.err != nil {
		log.Printf("%s [-] %s: %v", ts(), m, res.err)
		return
	}

	w.Write(m+".json", res.data)
}

// runLookup handles -T type:name lookups.
// coll is updated with domainSID if it can be derived from the result.
func runLookup(e *enum.Enumerator, w *output.Writer, spec string, coll *collector) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		log.Fatalf("%s [-] -T format: <type>:<name>  e.g. user:jdoe", ts())
	}
	kind, name := strings.ToLower(parts[0]), parts[1]

	var (
		data interface{}
		err  error
		file string
	)

	switch kind {
	case "user":
		result, gerr := e.LookupUser(name)
		data, err = result, gerr
		if gerr == nil {
			output.PrintUserLookup(result)
			if coll.domainSID == "" {
				coll.domainSID = domainSIDFromObject(result.Object)
			}
		}
		file = "lookup-user-" + sanitise(name) + ".json"
	case "computer":
		result, gerr := e.LookupComputer(name)
		data, err = result, gerr
		if gerr == nil {
			output.PrintComputerLookup(result)
			if coll.domainSID == "" {
				coll.domainSID = domainSIDFromObject(result.Object)
			}
		}
		file = "lookup-computer-" + sanitise(name) + ".json"
	case "group":
		result, gerr := e.LookupGroup(name)
		data, err = result, gerr
		if gerr == nil {
			output.PrintGroupMembers(result)
			if coll.domainSID == "" {
				coll.domainSID = domainSIDFromObject(result.Object)
				for _, m := range result.GroupMember {
					if coll.domainSID != "" {
						break
					}
					coll.domainSID = domainSIDFromObject(m)
				}
			}
			// Feed into BH collections so the zip includes full member data.
			coll.groups = append(coll.groups, result.Object)
			for _, m := range result.GroupMember {
				classes := enum.AttrSliceStr(m, "objectClass")
				isComputer := false
				for _, cls := range classes {
					if strings.EqualFold(cls, "computer") {
						isComputer = true
						break
					}
				}
				if isComputer {
					coll.computers = append(coll.computers, m)
				} else {
					coll.users = append(coll.users, m)
				}
			}
		}
		file = "lookup-group-" + sanitise(name) + ".json"
	case "ou":
		data, err = e.LookupOU(name)
		file = "lookup-ou.json"
	default:
		log.Fatalf("%s [-] Unknown -T type: %s (valid: user, computer, group, ou)", ts(), kind)
	}

	if err != nil {
		log.Printf("%s [-] Lookup %s: %v", ts(), spec, err)
		return
	}
	w.Write(file, data)
}

// expandModes resolves shorthands.
func expandModes(m string) []string {
	if m == "" {
		return nil
	}
	sweepAll := []string{"domain", "users", "computers", "groups", "gpos", "trusts", "ous"}
	targetedAll := []string{
		"kerberoastable", "asreproast", "unconstrained", "constrained",
		"rbcd", "admincount", "shadowcreds", "laps", "pwdnoexpire", "stale", "fgpp", "adcs",
	}
	switch m {
	// Current names
	case "sweep":
		return sweepAll
	case "targeted":
		return targetedAll
	case "full":
		return append(sweepAll, targetedAll...)
	// Legacy aliases (backward compat)
	case "all":
		return sweepAll
	case "attack":
		return targetedAll
	case "everything":
		return append(sweepAll, targetedAll...)
	}
	return strings.Split(m, ",")
}

// domainSIDFromObject extracts the domain SID from an AD object's objectSid
// by stripping the last RID component (e.g. S-1-5-21-X-Y-Z-500 → S-1-5-21-X-Y-Z).
// Returns "" for built-in accounts (S-1-5-32-...) that don't carry a domain SID.
func domainSIDFromObject(obj adws.ADObject) string {
	sid := enum.SIDStr(obj, "objectSid")
	if sid == "" {
		return ""
	}
	idx := strings.LastIndex(sid, "-")
	if idx < 0 {
		return sid
	}
	domain := sid[:idx]
	// Only accept proper domain SIDs (S-1-5-21-...), not built-in (S-1-5-32-...).
	if !strings.HasPrefix(domain, "S-1-5-21-") {
		return ""
	}
	return domain
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

func ts() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05 UTC --")
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
