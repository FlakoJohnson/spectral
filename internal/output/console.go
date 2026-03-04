package output

import (
	"fmt"
	"strings"

	"spectral/internal/enum"
)

// ANSI colour codes.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	grey   = "\033[90m"
	white  = "\033[97m"
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

	// ── Enterprise CAs ─────────────────────────────────────────────────
	if len(r.CAs) > 0 {
		section("Enterprise Certificate Authorities")
		for _, ca := range r.CAs {
			caName := enum.AttrStr(ca.Object, "cn")
			caHost := enum.AttrStr(ca.Object, "dNSHostName")
			fmt.Printf("  %s%s%s", bold+cyan, caName, reset)
			if caHost != "" {
				fmt.Printf("  (%s)", caHost)
			}
			fmt.Println()
			if len(ca.Templates) > 0 {
				fmt.Printf("    %sPublished templates:%s %s\n",
					grey, reset, strings.Join(ca.Templates, ", "))
			}
		}
		fmt.Println()
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
