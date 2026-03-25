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
		log.Printf("[*] Enumerating GPOs")
	}

	// Scope to the Policies container to reduce query breadth.
	gpoDN := "CN=Policies,CN=System," + e.baseDN

	var results []adws.ADObject

	err := e.client.QueryBatched(
		gpoDN,
		e.prepFilter(gpoFilter),
		e.prepAttrs(gpoAttrs),
		adws.ScopeSubtree,
		e.batch(),
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		// Fall back to full domain scope if the container isn't accessible.
		if e.verbose {
			log.Printf("[*] GPO container fallback to domain scope")
		}
		results = nil
		err = e.client.QueryBatched(
			e.baseDN,
			e.prepFilter(gpoFilter),
			e.prepAttrs(gpoAttrs),
			adws.ScopeSubtree,
			e.batch(),
			func(batch []adws.ADObject) error {
				results = append(results, batch...)
				e.pace.BetweenRequests()
				return nil
			},
		)
		if err != nil {
			return nil, err
		}
	}

	if e.verbose {
		log.Printf("[+] GPOs: %d", len(results))
	}
	return results, nil
}
