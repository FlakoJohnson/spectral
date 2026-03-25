package enum

import (
	"log"

	"spectral/internal/adws"
)

// OPSEC: (objectCategory=group) — matches RSAT/PowerShell Get-ADGroup behavior.
const groupFilter = "(objectCategory=group)"

// Groups enumerates all group objects in the domain.
func (e *Enumerator) Groups() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating groups", ts())
	}

	var results []adws.ADObject

	err := e.client.QueryBatched(
		e.baseDN,
		e.prepFilter(groupFilter),
		e.prepAttrs(groupAttrs),
		adws.ScopeSubtree,
		e.batch(),
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			if e.verbose {
				log.Printf("%s [*]   groups: %d", ts(), len(results))
			}
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("%s [+] Groups: %d", ts(), len(results))
	}
	return results, nil
}
