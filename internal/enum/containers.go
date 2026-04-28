package enum

import (
	"log"
	"spectral/internal/adws"
)

const containerFilter = "(objectClass=container)"

var containerAttrs = []string{
	"name",
	"distinguishedName",
	"objectGUID",
	"description",
	"whenCreated",
	"nTSecurityDescriptor",
}

// Containers enumerates all container objects in the domain.
func (e *Enumerator) Containers() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating containers", ts())
	}

	results, err := e.client.QueryWithSDFlags(
		e.baseDN,
		containerFilter,
		containerAttrs,
		adws.ScopeSubtree,
		7,
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("%s [+] Containers: %d", ts(), len(results))
	}
	return results, nil
}
