package enum

import (
	"fmt"
	"log"

	"spectral/internal/adws"
)

// DomainResult holds domain and forest metadata.
type DomainResult struct {
	Domain interface{} `json:"domain"`
	Forest interface{} `json:"forest"`
}

// Domain collects domain and forest info via MS-ADCAP.
func (e *Enumerator) Domain() (*DomainResult, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating domain info", ts())
	}

	domain, err := e.client.GetDomain()
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	e.pace.BetweenRequests()

	forest, err := e.client.GetForest()
	if err != nil {
		return nil, fmt.Errorf("get forest: %w", err)
	}

	return &DomainResult{Domain: domain, Forest: forest}, nil
}

// DomainObject collects the domain object with full ACL data for BloodHound.
// This is essential for DCSync and domain-level privilege relationships.
func (e *Enumerator) DomainObject() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating domain object (ACLs)", ts())
	}

	domainAttrs := []string{
		"distinguishedName",
		"objectSid",
		"objectGUID",
		"name",
		"description",
		"whenCreated",
		"nTSecurityDescriptor",
	}

	// Query the domain root object directly with full ACL data
	results, err := e.queryWithRetry(e.domainDN, "(objectClass=domainDNS)", domainAttrs, 7, nil)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("%s [+] Domain object: %d", ts(), len(results))
	}
	return results, nil
}

// MachineQuota queries ms-DS-MachineAccountQuota from the domain root.
func (e *Enumerator) MachineQuota() (string, error) {
	objs, err := e.client.Query(
		e.domainDN,
		"(objectClass=domainDNS)",
		[]string{"ms-DS-MachineAccountQuota"},
		adws.ScopeBase,
	)
	if err != nil {
		return "", err
	}
	if len(objs) == 0 {
		return "", fmt.Errorf("domain root not found")
	}
	return AttrStr(objs[0], "ms-DS-MachineAccountQuota"), nil
}
