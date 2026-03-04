// Package opsec provides request pacing to reduce enumeration noise.
package opsec

import (
	"math/rand"
	"time"
)

// Pacer controls timing between ADWS requests.
type Pacer struct {
	jitter    time.Duration // max random delay between individual requests
	typePause time.Duration // fixed delay between object type sweeps
}

// NewPacer creates a Pacer.
//
// jitter: max random sleep added between consecutive requests.
// typePause: sleep between enumeration of different object types.
func NewPacer(jitter, typePause time.Duration) *Pacer {
	return &Pacer{jitter: jitter, typePause: typePause}
}

// BetweenRequests sleeps for a random duration in [0, jitter].
// Call this between consecutive ADWS query pages.
func (p *Pacer) BetweenRequests() {
	if p.jitter <= 0 {
		return
	}
	sleep := time.Duration(rand.Int63n(int64(p.jitter)))
	time.Sleep(sleep)
}

// BetweenTypes sleeps for the configured inter-type pause.
// Call this between enumerating users, computers, groups, etc.
func (p *Pacer) BetweenTypes() {
	if p.typePause <= 0 {
		return
	}
	time.Sleep(p.typePause)
}
