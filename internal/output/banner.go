package output

import (
	"fmt"
	"time"
)

func PrintBanner() {
	printBannerColored(cyan, bold, grey)
}

func PrintBannerStealth() {
	printBannerColored(limeGreen, bold, purple)
}

func printBannerColored(primary, bld, secondary string) {
	fmt.Printf("%s%s", primary+bld, `
  ░██████╗██████╗░███████╗░█████╗░████████╗██████╗░░█████╗░██╗
  ██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║
  ╚█████╗░██████╔╝█████╗░░██║░░╚═╝░░░██║░░░██████╔╝███████║██║
  ░╚═══██╗██╔═══╝░██╔══╝░░██║░░██╗░░░██║░░░██╔══██╗██╔══██║██║
  ██████╔╝██║░░░░░███████╗╚█████╔╝░░░██║░░░██║░░██║██║░░██║███████╗
  ╚═════╝░╚═╝░░░░░╚══════╝░╚════╝░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝
`)
	fmt.Printf("%s", reset)
	fmt.Printf("  %sADWS-based AD enumeration  //  port 9389  //  no LDAP on the wire%s\n\n",
		secondary, reset)
}

// PrintTargetInfo displays the engagement context after the banner.
func PrintTargetInfo(target, domain, user, outDir string, stealth bool) {
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	label := white
	if stealth {
		label = limeGreen
	}
	fmt.Printf("  %s%sTarget%s  : %s\n", bold, label, reset, target)
	fmt.Printf("  %s%sDomain%s  : %s\n", bold, label, reset, domain)
	fmt.Printf("  %s%sUser%s    : %s\n", bold, label, reset, user)
	fmt.Printf("  %s%sOutput%s  : %s\n", bold, label, reset, outDir)
	fmt.Printf("  %s%sStarted%s : %s\n", bold, label, reset, ts)
	if stealth {
		fmt.Printf("  %s%sMode%s    : %sSTEALTH%s\n", bold, label, reset, limeGreen+bold, reset)
	}
	fmt.Println()
}
