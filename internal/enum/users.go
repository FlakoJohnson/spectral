package enum

import (
	"log"

	"spectral/internal/adws"
)

// OPSEC: Use (objectCategory=person)(objectClass=user) — the same filter
// PowerShell's Get-ADUser and RSAT use. Avoids (!FALSE) which is signatured.
const userFilter = "(&(objectCategory=person)(objectClass=user))"

// Users enumerates all user objects in the domain.
func (e *Enumerator) Users() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating users", ts())
	}

	var results []adws.ADObject

	err := e.client.QueryBatchedWithSDFlags(
		e.baseDN,
		e.prepFilter(userFilter),
		e.prepAttrs(userAttrs),
		adws.ScopeSubtree,
		e.batch(),
		7, // OWNER + GROUP + DACL
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			if e.verbose {
				log.Printf("%s [*]   users: %d", ts(), len(results))
			}
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("%s [+] Users: %d", ts(), len(results))
	}
	return results, nil
}
