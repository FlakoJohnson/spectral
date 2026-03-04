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
		log.Printf("[*] Enumerating computers")
	}

	var results []adws.ADObject

	err := e.client.QueryBatched(
		e.baseDN,
		computerFilter,
		computerAttrs,
		adws.ScopeSubtree,
		e.batchSize,
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			if e.verbose {
				log.Printf("[*]   computers: %d", len(results))
			}
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("[+] Computers: %d", len(results))
	}
	return results, nil
}
