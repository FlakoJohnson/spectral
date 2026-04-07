package enum

import (
	"spectral/internal/adws"
	"log"
)

// OPSEC: (objectClass=computer) — same as PowerShell Get-ADComputer.
const computerFilter = "(objectClass=computer)"

// Computers enumerates all computer objects in the domain.
func (e *Enumerator) Computers() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating computers", ts())
	}

	results, err := e.queryWithRetry(e.baseDN, computerFilter, computerAttrs, 7,
		func(batch []adws.ADObject) error {
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
