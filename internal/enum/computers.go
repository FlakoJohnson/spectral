package enum

import (
	"log"

	"spectral/internal/adws"
)

// OPSEC: (objectClass=computer) — same as PowerShell Get-ADComputer.
const computerFilter = "(objectClass=computer)"

// Computers enumerates all computer objects in the domain.
func (e *Enumerator) Computers() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating computers", ts())
	}

	var results []adws.ADObject

	err := e.client.QueryBatched(
		e.baseDN,
		e.prepFilter(computerFilter),
		e.prepAttrs(computerAttrs),
		adws.ScopeSubtree,
		e.batch(),
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			if e.verbose {
				log.Printf("%s [*]   computers: %d", ts(), len(results))
			}
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("%s [+] Computers: %d", ts(), len(results))
	}
	return results, nil
}
