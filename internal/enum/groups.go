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

	results, err := e.queryWithRetry(e.baseDN, groupFilter, groupAttrs, 7,
		func(batch []adws.ADObject) error {
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
