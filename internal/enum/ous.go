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

	results, err := e.queryWithRetry(e.baseDN, ouFilter, ouAttrs, 7,
		func(batch []adws.ADObject) error {
			if e.verbose {
				log.Printf("%s [*]   OUs: %d", ts(), len(batch))
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
