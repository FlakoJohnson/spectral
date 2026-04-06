package enum

import (
	"log"

	"spectral/internal/adws"
)

const ouFilter = "(objectClass=organizationalUnit)"

// OUs enumerates all organizational units in the domain.
func (e *Enumerator) OUs() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating OUs", ts())
	}

	var results []adws.ADObject

	err := e.client.QueryBatched(
		e.baseDN,
		e.prepFilter(ouFilter),
		e.prepAttrs(ouAttrs),
		adws.ScopeSubtree,
		e.batch(),
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			if e.verbose {
				log.Printf("%s [*]   OUs: %d", ts(), len(results))
			}
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("%s [+] OUs: %d", ts(), len(results))
	}
	return results, nil
}
