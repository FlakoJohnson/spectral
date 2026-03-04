// Package enum provides targeted AD object enumeration via ADWS.
package enum

import (
	"spectral/internal/adws"
	"spectral/internal/opsec"
)

// Enumerator holds shared state for all enumeration operations.
type Enumerator struct {
	client    *adws.Client
	pace      *opsec.Pacer
	batchSize int
	baseDN    string
	verbose   bool
}

// New creates an Enumerator.
func New(client *adws.Client, pace *opsec.Pacer, batchSize int, baseDN string, verbose bool) *Enumerator {
	return &Enumerator{
		client:    client,
		pace:      pace,
		batchSize: batchSize,
		baseDN:    baseDN,
		verbose:   verbose,
	}
}
