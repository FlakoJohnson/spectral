package enum

import (
	"log"

	"spectral/internal/adws"
)

// OPSEC: Target the CN=Policies container directly for GPOs —
// a scoped query rather than a domain-wide sweep.
const gpoFilter = "(objectClass=groupPolicyContainer)"

// GPOs enumerates Group Policy Objects.
func (e *Enumerator) GPOs() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating GPOs", ts())
	}

	gpoDN := "CN=Policies,CN=System," + e.domainDN

	results, err := e.queryWithRetry(gpoDN, gpoFilter, gpoAttrs, 7, nil)
	if err != nil {
		if e.verbose {
			log.Printf("%s [*] GPO container fallback to domain scope", ts())
		}
		results, err = e.queryWithRetry(e.domainDN, gpoFilter, gpoAttrs, 7, nil)
		if err != nil {
			return nil, err
		}
	}

	if e.verbose {
		log.Printf("%s [+] GPOs: %d", ts(), len(results))
	}
	return results, nil
}
