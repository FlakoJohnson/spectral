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
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [options]

Connection:
  -t  string   Target DC address (IP or hostname)
  -d  string   Domain (e.g. corp.local)
  -u  string   Username
  -p  string   Password
  -H  string   NT hash (pass-the-hash)
  -k           Use Kerberos (reads KRB5CCNAME env or -c path)
  -c  string   Kerberos ccache path
  -r  string   Port (default: 9389)

Enumeration:
  -m  string   Sweep modes, comma-separated (default: all)
               Sweep: users, computers, groups, gpos, trusts, domain
               Targeted: kerberoastable, asreproast, unconstrained,
                         constrained, rbcd, admincount, shadowcreds,
                         laps, pwdnoexpire, stale, fgpp
               Shorthand: all (all sweep modes), attack (all targeted)

  -T  string   Single object lookup: <type>:<name>
               Types: user, computer, group, ou
               Examples:
                 -T user:jdoe
                 -T computer:DC01
                 -T group:Domain Admins
                 -T ou:OU=IT,DC=corp,DC=local

  -A  int      Stale threshold in days for -m stale (default: 90)
  -b  string   Base DN (auto-derived from -d if omitted)

Output & pacing:
  -o  string   Output directory (default: .)
  -j  int      Jitter between requests ms (default: 500)
  -P  int      Pause between object types ms (default: 2000)
  -B  int      Batch size per ADWS pull (default: 100)
  -q           Quiet
  -x           Debug SOAP XML
`, os.Args[0])
}

func main() {
	var (
		target    = flag.String("t", "", "")
		domain    = flag.String("d", "", "")
		username  = flag.String("u", "", "")
		password  = flag.String("p", "", "")
		ntHash    = flag.String("H", "", "")
		useKerb   = flag.Bool("k", false, "")
		ccache    = flag.String("c", "", "")
		baseDN    = flag.String("b", "", "")
		mode      = flag.String("m", "", "")
		target1   = flag.String("T", "", "")
		staleDays = flag.Int("A", 90, "")
		outDir    = flag.String("o", ".", "")
		jitterMs  = flag.Int("j", 500, "")
		pauseMs   = flag.Int("P", 2000, "")
		batch     = flag.Int("B", 100, "")
		port      = flag.String("r", "9389", "")
		quiet     = flag.Bool("q", false, "")
		debugXML  = flag.Bool("x", false, "")
	)

	flag.Usage = usage
	flag.Parse()

	if *target == "" || *domain == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *mode == "" && *target1 == "" {
		flag.Usage()
		os.Exit(1)
	}

	// KRB5CCNAME env fallback.
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

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		log.Fatalf("[-] Output dir: %v", err)
	}

	w := output.NewWriter(*outDir, !*quiet)
	e := enum.New(client, pace, *batch, *baseDN, !*quiet)

	// ── Single object lookup ────────────────────────────────────────────
	if *target1 != "" {
		runLookup(e, w, *target1)
	}

	// ── Mode-based enumeration ──────────────────────────────────────────
	if *mode != "" {
		modes := expandModes(*mode)
		for i, m := range modes {
			runMode(e, w, m, *staleDays)
			if i < len(modes)-1 {
				pace.BetweenTypes()
			}
		}
	}

	if !*quiet {
		log.Printf("[+] Done → %s", *outDir)
	}
}

// runMode dispatches a single mode string to the appropriate enumerator.
func runMode(e *enum.Enumerator, w *output.Writer, m string, staleDays int) {
	type result struct {
		data interface{}
		err  error
	}

	var res result

	switch m {
	// ── Sweep ──────────────────────────────────────────────────────────
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

	// ── Targeted ───────────────────────────────────────────────────────
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
		data, err = e.LookupGroup(name)
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

// expandModes resolves shorthands and deduplicates.
func expandModes(m string) []string {
	sweepAll := []string{"domain", "users", "computers", "groups", "gpos", "trusts"}
	attackAll := []string{
		"kerberoastable", "asreproast", "unconstrained", "constrained",
		"rbcd", "admincount", "shadowcreds", "laps", "pwdnoexpire", "fgpp",
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

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// sanitise makes a string safe for use as a filename component.
func sanitise(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}
