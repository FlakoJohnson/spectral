package enum

import (
	"fmt"
	"log"
)

// DomainResult holds domain and forest metadata.
type DomainResult struct {
	Domain interface{} `json:"domain"`
	Forest interface{} `json:"forest"`
}

// Domain collects domain and forest info via MS-ADCAP.
func (e *Enumerator) Domain() (*DomainResult, error) {
	if e.verbose {
		log.Printf("[*] Enumerating domain info")
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
