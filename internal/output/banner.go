package output

import (
	"fmt"
	"time"
)

func PrintBanner() {
	fmt.Printf("%s%s", cyan+bold, `
  ░██████╗██████╗░███████╗░█████╗░████████╗██████╗░░█████╗░██╗
  ██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║
  ╚█████╗░██████╔╝█████╗░░██║░░╚═╝░░░██║░░░██████╔╝███████║██║
  ░╚═══██╗██╔═══╝░██╔══╝░░██║░░██╗░░░██║░░░██╔══██╗██╔══██║██║
  ██████╔╝██║░░░░░███████╗╚█████╔╝░░░██║░░░██║░░██║██║░░██║███████╗
  ╚═════╝░╚═╝░░░░░╚══════╝░╚════╝░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝
`)
	fmt.Printf("%s", reset)
	fmt.Printf("  %sADWS-based AD enumeration  //  port 9389  //  no LDAP on the wire%s\n\n",
		grey, reset)
}

// PrintTargetInfo displays the engagement context after the banner.
func PrintTargetInfo(target, domain, user, outDir string) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("  %s%sTarget%s  : %s\n", bold, white, reset, target)
	fmt.Printf("  %s%sDomain%s  : %s\n", bold, white, reset, domain)
	fmt.Printf("  %s%sUser%s    : %s\n", bold, white, reset, user)
	fmt.Printf("  %s%sOutput%s  : %s\n", bold, white, reset, outDir)
	fmt.Printf("  %s%sStarted%s : %s\n\n", bold, white, reset, ts)
}
