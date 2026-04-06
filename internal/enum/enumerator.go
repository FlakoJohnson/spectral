// Package enum provides targeted AD object enumeration via ADWS.
package enum

import (
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
