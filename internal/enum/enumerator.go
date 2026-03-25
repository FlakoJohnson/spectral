// Package enum provides targeted AD object enumeration via ADWS.
package enum

import (
	"spectral/internal/adws"
	"spectral/internal/opsec"
)

// Enumerator holds shared state for all enumeration operations.
type Enumerator struct {
	client   *adws.Client
	pace     *opsec.Pacer
	batchMin int
	batchMax int
	baseDN   string
	verbose  bool
	stealth  bool // enables filter obfuscation, attr shuffling, batch randomization
}

// New creates an Enumerator.
func New(client *adws.Client, pace *opsec.Pacer, batchSize int, baseDN string, verbose bool) *Enumerator {
	return &Enumerator{
		client:   client,
		pace:     pace,
		batchMin: batchSize,
		batchMax: batchSize,
		baseDN:   baseDN,
		verbose:  verbose,
	}
}

// NewStealth creates an Enumerator with stealth features enabled.
func NewStealth(client *adws.Client, pace *opsec.Pacer, batchMin, batchMax int, baseDN string, verbose bool) *Enumerator {
	return &Enumerator{
		client:   client,
		pace:     pace,
		batchMin: batchMin,
		batchMax: batchMax,
		baseDN:   baseDN,
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
