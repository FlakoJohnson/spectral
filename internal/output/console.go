package output

import (
	"fmt"
	"strconv"
	"strings"

	"spectral/internal/adws"
	"spectral/internal/enum"
	"spectral/internal/recon"
)

// ANSI colour codes.
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	red       = "\033[31m"
	yellow    = "\033[33m"
	green     = "\033[32m"
	cyan      = "\033[36m"
	grey      = "\033[90m"
	white     = "\033[97m"
	limeGreen = "\033[38;5;118m"
	purple    = "\033[38;5;135m"
)

// PrintADCS writes a human-readable ADCS report to stdout.
func PrintADCS(r *enum.ADCSResult) {
	fmt.Println()
	header("ADCS Enumeration Results")

	// ── Infrastructure summary ─────────────────────────────────────────
	section("Infrastructure")
	fmt.Printf("  Enterprise CAs  : %s%d%s\n", bold, len(r.CAs), reset)
	fmt.Printf("  Templates       : %s%d%s\n", bold, len(r.Templates), reset)
	fmt.Printf("  Root CAs        : %s%d%s\n", bold, len(r.RootCAs), reset)
	fmt.Printf("  NTAuth certs    : %s%d%s\n", bold, len(r.NTAuth), reset)
	fmt.Println()

	// ── Certificate Authorities (certipy-style) ───────────────────────
	if len(r.CAs) > 0 {
		section("Certificate Authorities")
		for i, ca := range r.CAs {
			caName := enum.AttrStr(ca.Object, "cn")
			caHost := enum.AttrStr(ca.Object, "dNSHostName")
			caDN := enum.AttrStr(ca.Object, "cACertificateDN")

			fmt.Printf("  %s%d%s\n", bold+white, i, reset)
			fmt.Printf("    %-36s: %s%s%s\n", "CA Name", bold+cyan, caName, reset)
			if caHost != "" {
				fmt.Printf("    %-36s: %s\n", "DNS Name", caHost)
			}
			if caDN != "" {
				fmt.Printf("    %-36s: %s\n", "Certificate Subject", caDN)
			}

			// Web Enrollment
			fmt.Printf("    %sWeb Enrollment%s\n", bold, reset)
			hasHTTP := false
			hasHTTPS := false
			for _, ep := range ca.WebEndpoints {
				if strings.HasPrefix(ep.URL, "http://") {
					hasHTTP = true
				} else if strings.HasPrefix(ep.URL, "https://") {
					hasHTTPS = true
				}
			}
			fmt.Printf("      HTTP\n")
			if hasHTTP {
				fmt.Printf("        %-32s: %s%sTrue%s\n", "Enabled", bold, red, reset)
				for _, ep := range ca.WebEndpoints {
					if strings.HasPrefix(ep.URL, "http://") {
						authStr := ""
						if ep.NTLM && ep.Negotiate {
							authStr = "NTLM + Negotiate"
						} else if ep.NTLM {
							authStr = "NTLM"
						} else if ep.Negotiate {
							authStr = "Negotiate"
						}
						if authStr != "" {
							fmt.Printf("        %-32s: %s%s%s%s\n", "Auth", bold, red, authStr, reset)
						}
						break
					}
				}
			} else {
				fmt.Printf("        %-32s: False\n", "Enabled")
			}
			fmt.Printf("      HTTPS\n")
			if hasHTTPS {
				fmt.Printf("        %-32s: %s%sTrue%s\n", "Enabled", bold, yellow, reset)
				for _, ep := range ca.WebEndpoints {
					if strings.HasPrefix(ep.URL, "https://") {
						authStr := ""
						if ep.NTLM && ep.Negotiate {
							authStr = "NTLM + Negotiate"
						} else if ep.NTLM {
							authStr = "NTLM"
						} else if ep.Negotiate {
							authStr = "Negotiate"
						}
						if authStr != "" {
							fmt.Printf("        %-32s: %s\n", "Auth", authStr)
						}
						break
					}
				}
			} else {
				fmt.Printf("        %-32s: False\n", "Enabled")
			}

			// Permissions (from parsed ACL)
			sdRaw := enum.AttrStr(ca.Object, "nTSecurityDescriptor")
			if sdRaw != "" {
				caSD := enum.ParseSD(sdRaw)
				if caSD != nil {
					fmt.Printf("    %sPermissions%s\n", bold, reset)
					// Collect permissions by right name
					permMap := map[string][]string{}
					allACEs := append(append(caSD.Enrollers, caSD.Writers...), caSD.FullControl...)
					for _, ace := range allACEs {
						if ace.Type != "Allow" {
							continue
						}
						friendlySID := enum.FriendlySID(ace.SID, r.DomainSID)
						permMap[ace.Rights] = appendUnique(permMap[ace.Rights], friendlySID)
					}
					for right, principals := range permMap {
						fmt.Printf("      %-34s: %s\n", right, strings.Join(principals, ", "))
					}
				}
			}

			// Published templates
			if len(ca.Templates) > 0 {
				fmt.Printf("    %-36s: %s\n", "Published Templates", strings.Join(ca.Templates, ", "))
			}

			// Vulnerabilities for this CA
			caVulns := []enum.ESCFinding{}
			for _, f := range r.Findings {
				if f.CA == caName {
					caVulns = append(caVulns, f)
				}
			}
			if len(caVulns) > 0 {
				fmt.Printf("    %s[!] Vulnerabilities%s\n", bold+red, reset)
				for _, f := range caVulns {
					fmt.Printf("      %-34s: %s\n", f.ESC, f.Description[:min(80, len(f.Description))])
				}
			}
			fmt.Println()
		}
	}

	// ── Findings ───────────────────────────────────────────────────────
	section("Findings")

	if len(r.Findings) == 0 {
		fmt.Printf("  %sNo findings.%s\n\n", green, reset)
		return
	}

	critical := filterByRisk(r.Findings, "CRITICAL")
	high := filterByRisk(r.Findings, "HIGH")
	review := filterByRisk(r.Findings, "REVIEW")

	fmt.Printf("  %d actionable  |  %d for manual review\n\n",
		len(critical)+len(high), len(review))

	if len(critical) > 0 {
		riskHeader("CRITICAL", red)
		for _, f := range critical {
			printFinding(f, red)
		}
	}

	if len(high) > 0 {
		riskHeader("HIGH", yellow)
		for _, f := range high {
			printFinding(f, yellow)
		}
	}

	if len(review) > 0 {
		riskHeader("REVIEW", cyan)
		for _, f := range review {
			printFinding(f, cyan)
		}
	}

	fmt.Println()
}

// PrintUsers prints a summary table of all user objects to stdout.
func PrintUsers(users []adws.ADObject) {
	fmt.Println()
	header(fmt.Sprintf("Users  (%d)", len(users)))

	if len(users) == 0 {
		fmt.Printf("  %sNo users found.%s\n\n", grey, reset)
		return
	}

	const (
		wSAM = 28
		wSID = 48
		wSts = 8
		wAdm = 5
	)

	fmt.Printf("  %s%-*s  %-*s  %-*s  %-*s  %s%s\n",
		bold+white,
		wSAM, "sAMAccountName",
		wSID, "objectSid",
		wSts, "Status",
		wAdm, "Admin",
		"distinguishedName",
		reset,
	)
	fmt.Printf("  %s%s%s\n", grey, strings.Repeat("─", wSAM+2+wSID+2+wSts+2+wAdm+2+60), reset)

	for _, u := range users {
		sam := enum.AttrStr(u, "sAMAccountName")
		sid := enum.SIDStr(u, "objectSid")
		dn := enum.AttrStr(u, "distinguishedName")

		disabled := false
		if uac, err := strconv.Atoi(enum.AttrStr(u, "userAccountControl")); err == nil {
			disabled = uac&0x2 != 0
		}

		// Pre-pad then colourize so ANSI codes don't break column alignment.
		stsPlain, stsColour := "enabled", green
		if disabled {
			stsPlain, stsColour = "disabled", grey
		}
		stsStr := stsColour + fmt.Sprintf("%-*s", wSts, stsPlain) + reset

		admStr := fmt.Sprintf("%-*s", wAdm, "")
		if enum.AttrStr(u, "adminCount") == "1" {
			admStr = red + bold + fmt.Sprintf("%-*s", wAdm, "1") + reset
		}

		fmt.Printf("  %-*s  %-*s  %s  %s  %s%s%s\n",
			wSAM, sam,
			wSID, sid,
			stsStr,
			admStr,
			grey, dn, reset,
		)
	}
	fmt.Println()
}

// PrintGroups prints a summary table of all group objects to stdout.
func PrintGroups(groups []adws.ADObject) {
	fmt.Println()
	header(fmt.Sprintf("Groups  (%d)", len(groups)))

	if len(groups) == 0 {
		fmt.Printf("  %sNo groups found.%s\n\n", grey, reset)
		return
	}

	const (
		wSAM = 30
		wSID = 50
		wMem = 7
	)

	fmt.Printf("  %s%-*s  %-*s  %-*s  %s%s\n",
		bold+white,
		wSAM, "sAMAccountName",
		wSID, "objectSid",
		wMem, "Members",
		"distinguishedName",
		reset,
	)
	fmt.Printf("  %s%s%s\n", grey, strings.Repeat("─", wSAM+2+wSID+2+wMem+2+60), reset)

	for _, g := range groups {
		sam := enum.AttrStr(g, "sAMAccountName")
		sid := enum.SIDStr(g, "objectSid")
		dn := enum.AttrStr(g, "distinguishedName")

		memCount := len(enum.AttrSliceStr(g, "member"))
		memStr := ""
		if memCount > 0 {
			memStr = strconv.Itoa(memCount)
		}

		fmt.Printf("  %-*s  %-*s  %-*s  %s%s%s\n",
			wSAM, sam,
			wSID, sid,
			wMem, memStr,
			grey, dn, reset,
		)
	}
	fmt.Println()
}

// PrintOUs prints a formatted OU listing to stdout.
func PrintOUs(ous []adws.ADObject) {
	fmt.Println()
	header(fmt.Sprintf("Organizational Units  (%d)", len(ous)))

	const (
		wName = 40
		wGPO  = 10
	)

	fmt.Printf("  %s%-*s  %-*s  %s%s\n",
		bold+white,
		wName, "Name",
		wGPO, "GPOs",
		"distinguishedName",
		reset,
	)
	fmt.Printf("  %s%s%s\n", grey,
		strings.Repeat("─", wName+2+wGPO+2+80), reset)

	for _, ou := range ous {
		name := enum.AttrStr(ou, "name")
		dn := enum.AttrStr(ou, "distinguishedName")
		gpLink := enum.AttrStr(ou, "gPLink")
		desc := enum.AttrStr(ou, "description")

		// Count linked GPOs
		gpoCount := 0
		if gpLink != "" {
			gpoCount = strings.Count(gpLink, "[LDAP://")
		}

		gpoStr := ""
		if gpoCount > 0 {
			gpoStr = fmt.Sprintf("%s%d%s", yellow, gpoCount, reset)
		}

		descStr := ""
		if desc != "" {
			descStr = fmt.Sprintf(" %s(%s)%s", grey, desc, reset)
		}

		fmt.Printf("  %-*s  %-*s  %s%s%s%s\n",
			wName, name,
			wGPO, gpoStr,
			grey, dn, reset,
			descStr,
		)
	}
	fmt.Println()
}

// PrintUserLookup prints a user's details and group memberships to stdout.
func PrintUserLookup(result *enum.SingleResult) {
	sam := enum.AttrStr(result.Object, "sAMAccountName")
	sid := enum.SIDStr(result.Object, "objectSid")
	dn := enum.AttrStr(result.Object, "distinguishedName")

	fmt.Println()
	header(fmt.Sprintf("User: %s", sam))

	// Key properties
	fields := []struct{ label, attr string }{
		{"SID", ""},
		{"UPN", "userPrincipalName"},
		{"Display Name", "displayName"},
		{"Description", "description"},
		{"Email", "mail"},
		{"DN", "distinguishedName"},
	}
	for _, f := range fields {
		var val string
		if f.label == "SID" {
			val = sid
		} else if f.label == "DN" {
			val = dn
		} else {
			val = enum.AttrStr(result.Object, f.attr)
		}
		if val != "" {
			fmt.Printf("  %s%-16s%s %s\n", bold, f.label, reset, val)
		}
	}

	// UAC flags
	uacStr := enum.AttrStr(result.Object, "userAccountControl")
	if uacStr != "" {
		uac := parseInt64(uacStr)
		flags := []string{}
		if uac&0x2 != 0 {
			flags = append(flags, red+"DISABLED"+reset)
		} else {
			flags = append(flags, green+"ENABLED"+reset)
		}
		if uac&0x10000 != 0 {
			flags = append(flags, yellow+"PWD_NEVER_EXPIRES"+reset)
		}
		if uac&0x400000 != 0 {
			flags = append(flags, red+"DONT_REQ_PREAUTH"+reset)
		}
		if uac&0x80000 != 0 {
			flags = append(flags, red+"TRUSTED_FOR_DELEGATION"+reset)
		}
		if uac&0x1000000 != 0 {
			flags = append(flags, yellow+"TRUSTED_TO_AUTH_FOR_DELEGATION"+reset)
		}
		fmt.Printf("  %s%-16s%s %s\n", bold, "Status", reset, strings.Join(flags, " | "))
	}

	// AdminCount
	ac := enum.AttrStr(result.Object, "adminCount")
	if ac == "1" {
		fmt.Printf("  %s%-16s%s %s1 ← AdminSDHolder protected%s\n", bold, "AdminCount", reset, red+bold, reset)
	}

	// SPNs
	spns := enum.AttrSliceStr(result.Object, "servicePrincipalName")
	if len(spns) > 0 {
		fmt.Printf("\n  %s%sSPNs (%d):%s\n", bold, yellow, len(spns), reset)
		for _, spn := range spns {
			fmt.Printf("    %s\n", spn)
		}
	}

	// Delegation
	delegateTo := enum.AttrSliceStr(result.Object, "msDS-AllowedToDelegateTo")
	if len(delegateTo) > 0 {
		fmt.Printf("\n  %s%sConstrained Delegation:%s\n", bold, red, reset)
		for _, d := range delegateTo {
			fmt.Printf("    → %s\n", d)
		}
	}

	// Group memberships
	if len(result.MemberOf) > 0 {
		fmt.Printf("\n  %s%sMember of (%d groups):%s\n", bold, white, len(result.MemberOf), reset)
		for _, g := range result.MemberOf {
			gname := enum.AttrStr(g, "sAMAccountName")
			gsid := enum.SIDStr(g, "objectSid")
			fmt.Printf("    %s  %s%s%s\n", gname, grey, gsid, reset)
		}
	}
	fmt.Println()
}

// PrintComputerLookup prints a computer's details to stdout.
func PrintComputerLookup(result *enum.SingleResult) {
	sam := enum.AttrStr(result.Object, "sAMAccountName")
	sid := enum.SIDStr(result.Object, "objectSid")

	fmt.Println()
	header(fmt.Sprintf("Computer: %s", strings.TrimSuffix(sam, "$")))

	fields := []struct{ label, attr string }{
		{"SID", ""},
		{"DNS Name", "dNSHostName"},
		{"OS", "operatingSystem"},
		{"OS Version", "operatingSystemVersion"},
		{"DN", "distinguishedName"},
	}
	for _, f := range fields {
		var val string
		if f.label == "SID" {
			val = sid
		} else {
			val = enum.AttrStr(result.Object, f.attr)
		}
		if val != "" {
			fmt.Printf("  %s%-16s%s %s\n", bold, f.label, reset, val)
		}
	}

	// UAC flags
	uacStr := enum.AttrStr(result.Object, "userAccountControl")
	if uacStr != "" {
		uac := parseInt64(uacStr)
		flags := []string{}
		if uac&0x2 != 0 {
			flags = append(flags, red+"DISABLED"+reset)
		} else {
			flags = append(flags, green+"ENABLED"+reset)
		}
		if uac&0x80000 != 0 {
			flags = append(flags, red+"UNCONSTRAINED_DELEGATION"+reset)
		}
		if uac&0x1000000 != 0 {
			flags = append(flags, yellow+"TRUSTED_TO_AUTH_FOR_DELEGATION"+reset)
		}
		fmt.Printf("  %s%-16s%s %s\n", bold, "Status", reset, strings.Join(flags, " | "))
	}

	// SPNs
	spns := enum.AttrSliceStr(result.Object, "servicePrincipalName")
	if len(spns) > 0 {
		fmt.Printf("\n  %s%sSPNs (%d):%s\n", bold, yellow, len(spns), reset)
		for _, spn := range spns[:min(10, len(spns))] {
			fmt.Printf("    %s\n", spn)
		}
		if len(spns) > 10 {
			fmt.Printf("    %s... and %d more%s\n", grey, len(spns)-10, reset)
		}
	}

	// Delegation
	delegateTo := enum.AttrSliceStr(result.Object, "msDS-AllowedToDelegateTo")
	if len(delegateTo) > 0 {
		fmt.Printf("\n  %s%sConstrained Delegation:%s\n", bold, red, reset)
		for _, d := range delegateTo {
			fmt.Printf("    → %s\n", d)
		}
	}

	// Group memberships
	if len(result.MemberOf) > 0 {
		fmt.Printf("\n  %s%sMember of (%d groups):%s\n", bold, white, len(result.MemberOf), reset)
		for _, g := range result.MemberOf {
			gname := enum.AttrStr(g, "sAMAccountName")
			fmt.Printf("    %s\n", gname)
		}
	}
	fmt.Println()
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// PrintGroupMembers prints a group's members as a formatted table to stdout.
func PrintGroupMembers(result *enum.SingleResult) {
	groupName := enum.AttrStr(result.Object, "sAMAccountName")
	groupSID := enum.SIDStr(result.Object, "objectSid")
	groupDN := enum.AttrStr(result.Object, "distinguishedName")
	groupDesc := enum.AttrStr(result.Object, "description")

	fmt.Println()
	header(fmt.Sprintf("Group: %s", groupName))

	if groupSID != "" {
		fmt.Printf("  %s%-16s%s %s\n", bold, "SID", reset, groupSID)
	}
	if groupDN != "" {
		fmt.Printf("  %s%-16s%s %s\n", bold, "DN", reset, groupDN)
	}
	if groupDesc != "" {
		fmt.Printf("  %s%-16s%s %s\n", bold, "Description", reset, groupDesc)
	}
	fmt.Println()

	if len(result.GroupMember) == 0 {
		fmt.Printf("  %sNo members found.%s\n\n", grey, reset)
		return
	}

	fmt.Printf("  %s%d member(s)%s\n\n", bold, len(result.GroupMember), reset)

	// Column widths.
	const (
		wSAM = 30
		wSID = 50
	)

	// Header row.
	fmt.Printf("  %s%-*s  %-*s  %s%s\n",
		bold+white,
		wSAM, "sAMAccountName",
		wSID, "objectSid",
		"distinguishedName",
		reset,
	)
	fmt.Printf("  %s%s%s\n", grey,
		strings.Repeat("─", wSAM+2+wSID+2+60), reset)

	// Member rows.
	for _, m := range result.GroupMember {
		sam := enum.AttrStr(m, "sAMAccountName")
		sid := enum.SIDStr(m, "objectSid")
		dn := enum.AttrStr(m, "distinguishedName")

		fmt.Printf("  %-*s  %-*s  %s%s%s\n",
			wSAM, sam,
			wSID, sid,
			grey, dn, reset,
		)
	}
	fmt.Println()
}

// PrintRootDSE writes a formatted rootDSE report to stdout.
func PrintRootDSE(dse *recon.RootDSE) {
	fmt.Println()
	header("RootDSE  —  Anonymous LDAP Probe")

	row := func(label, value string) {
		if value != "" {
			fmt.Printf("  %-30s %s%s%s\n", label, bold, value, reset)
		}
	}

	section("Domain")
	row("Default Naming Context", dse.DefaultNamingContext)
	row("Root Domain NC", dse.RootDomainNC)
	row("DNS Host Name", dse.DNSHostName)
	row("Server Name", dse.ServerName)
	fmt.Println()

	section("Functional Levels")
	row("Domain Functionality", dse.DomainFunctionality)
	row("Forest Functionality", dse.ForestFunctionality)
	row("DC Functionality", dse.DCFunctionality)
	fmt.Println()

	section("Naming Contexts")
	row("Configuration NC", dse.ConfigurationNC)
	row("Schema NC", dse.SchemaNamingContext)
	fmt.Println()

	section("Authentication")
	if len(dse.SupportedSASL) > 0 {
		fmt.Printf("  %-30s %s%s%s\n", "Supported SASL",
			bold, strings.Join(dse.SupportedSASL, ", "), reset)
	}
	if len(dse.SupportedLDAPVersions) > 0 {
		fmt.Printf("  %-30s %s%s%s\n", "LDAP Versions",
			bold, strings.Join(dse.SupportedLDAPVersions, ", "), reset)
	}
	fmt.Println()

	section("Misc")
	row("Current Time (UTC)", dse.CurrentTime)
	row("Highest Committed USN", dse.HighestCommittedUSN)
	fmt.Println()
}

// ── Helpers ────────────────────────────────────────────────────────────────

func header(title string) {
	line := strings.Repeat("─", 60)
	fmt.Printf("%s%s%s\n", bold+white, line, reset)
	fmt.Printf("  %s%s%s\n", bold+white, title, reset)
	fmt.Printf("%s%s%s\n\n", bold+white, line, reset)
}

func section(title string) {
	fmt.Printf("%s[ %s ]%s\n", bold, title, reset)
}

func riskHeader(label, colour string) {
	fmt.Printf("\n  %s%s%s\n", colour+bold, label, reset)
	fmt.Printf("  %s%s%s\n", grey, strings.Repeat("·", 40), reset)
}

func printFinding(f enum.ESCFinding, colour string) {
	target := f.Template
	if target == "" {
		target = f.CA
	}

	fmt.Printf("\n    %s%-12s%s %s%s%s\n",
		colour+bold, f.ESC, reset,
		bold, target, reset)

	for _, line := range wrap(f.Description, 68) {
		fmt.Printf("    %s│%s %s\n", grey, reset, line)
	}

	if f.Note != "" {
		fmt.Printf("    %s↳ %s%s\n", grey, f.Note, reset)
	}
}

func filterByRisk(findings []enum.ESCFinding, risk string) []enum.ESCFinding {
	var out []enum.ESCFinding
	for _, f := range findings {
		if f.Risk == risk {
			out = append(out, f)
		}
	}
	return out
}

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur strings.Builder

	for _, w := range words {
		if cur.Len() > 0 && cur.Len()+1+len(w) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
