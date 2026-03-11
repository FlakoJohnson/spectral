// Package enum provides targeted AD object enumeration via ADWS.
package enum

import (
	"log"
	"sync"

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

	// userSweepOnce ensures the full user sweep is only issued once per run.
	// kerberoastable, asreproast, and pwdnoexpire all need the same dataset.
	userSweepOnce sync.Once
	userSweepData []adws.ADObject
	userSweepErr  error
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

// allUsers returns all user objects, issuing the sweep at most once per run.
func (e *Enumerator) allUsers() ([]adws.ADObject, error) {
	e.userSweepOnce.Do(func() {
		if e.verbose {
			log.Printf("[*] User sweep (shared across targeted modes)")
		}
		e.userSweepData, e.userSweepErr = e.client.Query(
			e.baseDN, userFilter, userAttrs, adws.ScopeSubtree,
		)
		if e.verbose && e.userSweepErr == nil {
			log.Printf("[*] User sweep: %d objects", len(e.userSweepData))
		}
	})
	return e.userSweepData, e.userSweepErr
}
