// Package enum provides targeted AD object enumeration via ADWS.
package enum

import (
	"fmt"
	"log"
	"strings"
	"time"

	"spectral/internal/adws"
	"spectral/internal/opsec"
)

// ts returns the standardized timestamp prefix for log lines.
func ts() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05 UTC --")
}

// Enumerator holds shared state for all enumeration operations.
type Enumerator struct {
	client   *adws.Client
	pace     *opsec.Pacer
	batchMin int
	batchMax int
	baseDN   string // scoped base DN (may be overridden by -b)
	domainDN string // always the domain root DN (DC=...,DC=...)
	target   string // DC IP/hostname for DNS resolution
	verbose  bool
	stealth  bool
}

// New creates an Enumerator.
func New(client *adws.Client, pace *opsec.Pacer, batchSize int, baseDN, domainDN, target string, verbose bool) *Enumerator {
	return &Enumerator{
		client:   client,
		pace:     pace,
		batchMin: batchSize,
		batchMax: batchSize,
		baseDN:   baseDN,
		domainDN: domainDN,
		target:   target,
		verbose:  verbose,
	}
}

// NewStealth creates an Enumerator with stealth features enabled.
func NewStealth(client *adws.Client, pace *opsec.Pacer, batchMin, batchMax int, baseDN, domainDN, target string, verbose bool) *Enumerator {
	return &Enumerator{
		client:   client,
		pace:     pace,
		batchMin: batchMin,
		batchMax: batchMax,
		target:   target,
		baseDN:   baseDN,
		domainDN: domainDN,
		verbose:  verbose,
		stealth:  true,
	}
}

// batch returns the batch size for the next query.
// In stealth mode, returns a random value in [batchMin, batchMax].
func (e *Enumerator) batch() int {
	if e.stealth && e.batchMin != e.batchMax {
		return opsec.RandomBatch(e.batchMin, e.batchMax)
	}
	return e.batchMin
}

// isADWSTooBig checks if an error is the ADWS "response too large" error.
func isADWSTooBig(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "DIR_ERROR") || strings.Contains(msg, "8224")
}

// queryWithRetry runs a batched query and retries with smaller batch size
// if ADWS rejects the response as too large (DIR_ERROR 5012 / Win32 8224).
// Retry sequence: original batch → batch=10 → batch=10 without nTSecurityDescriptor.
func (e *Enumerator) queryWithRetry(
	baseDN, filter string, attrs []string, sdFlags int,
	callback func([]adws.ADObject) error,
) ([]adws.ADObject, error) {
	var results []adws.ADObject
	cb := func(batch []adws.ADObject) error {
		results = append(results, batch...)
		if callback != nil {
			return callback(batch)
		}
		return nil
	}

	prepF := e.prepFilter(filter)
	prepA := e.prepAttrs(attrs)
	batchSize := e.batch()

	// Attempt 1: normal batch with SD flags
	var err error
	if sdFlags > 0 {
		err = e.client.QueryBatchedWithSDFlags(baseDN, prepF, prepA, adws.ScopeSubtree, batchSize, sdFlags, cb)
	} else {
		err = e.client.QueryBatched(baseDN, prepF, prepA, adws.ScopeSubtree, batchSize, cb)
	}

	if !isADWSTooBig(err) {
		return results, err
	}

	// Attempt 2: small batch (10) with SD flags
	if e.verbose {
		log.Printf("%s [*] ADWS response too large (batch=%d), retrying with batch=10", ts(), batchSize)
	}
	results = nil
	if sdFlags > 0 {
		err = e.client.QueryBatchedWithSDFlags(baseDN, prepF, prepA, adws.ScopeSubtree, 10, sdFlags, cb)
	} else {
		err = e.client.QueryBatched(baseDN, prepF, prepA, adws.ScopeSubtree, 10, cb)
	}

	if !isADWSTooBig(err) {
		return results, err
	}

	// Attempt 3: small batch without nTSecurityDescriptor
	if e.verbose {
		log.Printf("%s [*] Still too large, retrying without nTSecurityDescriptor", ts())
	}
	results = nil
	noSD := make([]string, 0, len(attrs))
	for _, a := range attrs {
		if a != "nTSecurityDescriptor" {
			noSD = append(noSD, a)
		}
	}
	err = e.client.QueryBatched(baseDN, prepF, noSD, adws.ScopeSubtree, 10, cb)
	return results, err
}

// ResolveMembers batch-resolves a list of DNs to full AD objects.
// Uses domain root DN (not scoped -b) and minimal attrs + memberLookupAttrs.
// Single ADWS query with OR filter for stealth.
func (e *Enumerator) ResolveMembers(dns []string) []adws.ADObject {
	if len(dns) == 0 {
		return nil
	}

	// Build OR filter for all DNs. Process in chunks of 50 to avoid
	// oversized SOAP requests.
	var all []adws.ADObject
	chunkSize := 50
	for i := 0; i < len(dns); i += chunkSize {
		end := i + chunkSize
		if end > len(dns) {
			end = len(dns)
		}
		chunk := dns[i:end]

		var parts []string
		for _, dn := range chunk {
			parts = append(parts, fmt.Sprintf("(distinguishedName=%s)", escapeLDAP(dn)))
		}
		filter := fmt.Sprintf("(|%s)", strings.Join(parts, ""))

		objs, err := e.client.Query(e.domainDN, filter, memberLookupAttrs, adws.ScopeSubtree)
		if err != nil {
			if e.verbose {
				log.Printf("%s [*] Member resolve chunk failed: %v", ts(), err)
			}
			continue
		}
		all = append(all, objs...)
		e.pace.BetweenRequests()
	}
	return all
}

// prepFilter applies stealth obfuscation to a filter if enabled.
func (e *Enumerator) prepFilter(filter string) string {
	if e.stealth {
		return opsec.Obfuscate(filter)
	}
	return filter
}

// prepAttrs shuffles attribute order if stealth is enabled.
func (e *Enumerator) prepAttrs(attrs []string) []string {
	if e.stealth {
		return opsec.ShuffleAttrs(attrs)
	}
	return attrs
}
