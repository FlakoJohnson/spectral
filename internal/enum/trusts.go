package enum

import (
	"log"

	"spectral/internal/adws"
)

// Trust direction constants (matches AD trustDirection attribute).
const (
	TrustDisabled  = 0
	TrustInbound   = 1
	TrustOutbound  = 2
	TrustBidirectl = 3
)

const trustFilter = "(objectClass=trustedDomain)"

// Trusts enumerates all domain trust relationships.
// Scoped to CN=System to avoid a full domain sweep.
func (e *Enumerator) Trusts() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Enumerating trusts")
	}

	systemDN := "CN=System," + e.baseDN

	var results []adws.ADObject

	err := e.client.QueryBatched(
		systemDN,
		trustFilter,
		trustAttrs,
		adws.ScopeOneLevel,
		e.batchSize,
		func(batch []adws.ADObject) error {
			results = append(results, batch...)
			e.pace.BetweenRequests()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if e.verbose {
		log.Printf("[+] Trusts: %d", len(results))
	}
	return results, nil
}
