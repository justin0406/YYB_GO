package protocol

import (
	"sync"
	"time"
)

// The code circuit breaker is traffic control, not a lifecycle verdict: an
// open circuit returns a local refusal and never changes account status,
// clears credentials or triggers recovery.
//
// Two layers, mirroring the observed failure shapes of script bursts:
//   - target layer: (account, appID) — repeated empty wx.login codes mean the
//     upstream keeps refusing this combination; cool the target down.
//   - account layer: several different AppIDs refused within a short window
//     mean the account itself is being rejected; cool every business request
//     for the account down.
//
// A single non-empty code clears all state for the account: whatever was
// wrong is demonstrably over.

const (
	circuitTargetStreakLimit   = 3 // consecutive empty codes
	circuitTargetCooldown      = 10 * time.Minute
	circuitStreakResetWindow   = 30 * time.Minute // failures farther apart do not count as consecutive
	circuitAccountCooldown     = 15 * time.Minute
	circuitAccountWindow       = 5 * time.Minute
	circuitAccountDistinctApps = 3
	maxCircuitAccounts         = 4096
)

type circuitTarget struct {
	streak    int
	lastEmpty time.Time
	coolUntil time.Time
}

type circuitEmpty struct {
	at    time.Time
	appID string
}

type circuit struct {
	now func() time.Time

	mu       sync.Mutex
	accounts map[int64]time.Time                 // account-level business cooldown
	targets  map[int64]map[string]*circuitTarget // account → appID → streak state
	empties  map[int64][]circuitEmpty            // account → recent empty-code events (account layer)
}

func newCircuit() *circuit {
	return &circuit{
		now:      time.Now,
		accounts: map[int64]time.Time{},
		targets:  map[int64]map[string]*circuitTarget{},
		empties:  map[int64][]circuitEmpty{},
	}
}

// allow reports whether a code request for (account, appID) may go upstream.
func (c *circuit) allow(accountID int64, appID string) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.accounts[accountID]; ok && until.After(now) {
		return false
	}
	if t := c.targets[accountID][appID]; t != nil && t.coolUntil.After(now) {
		return false
	}
	return true
}

func (c *circuit) recordEmpty(accountID int64, appID string) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	targets := c.targets[accountID]
	if targets == nil {
		targets = map[string]*circuitTarget{}
		c.targets[accountID] = targets
	}
	t := targets[appID]
	if t == nil {
		t = &circuitTarget{}
		targets[appID] = t
	}
	if !t.lastEmpty.IsZero() && now.Sub(t.lastEmpty) > circuitStreakResetWindow {
		t.streak = 0
	}
	t.streak++
	t.lastEmpty = now
	if t.streak >= circuitTargetStreakLimit {
		t.coolUntil = now.Add(circuitTargetCooldown)
	}

	// Account layer: enough distinct refused AppIDs in a short window means
	// the account itself is being rejected.
	kept := make([]circuitEmpty, 0, len(c.empties[accountID])+1)
	for _, e := range c.empties[accountID] {
		if now.Sub(e.at) <= circuitAccountWindow {
			kept = append(kept, e)
		}
	}
	kept = append(kept, circuitEmpty{at: now, appID: appID})
	distinct := map[string]bool{}
	for _, e := range kept {
		distinct[e.appID] = true
	}
	if len(distinct) >= circuitAccountDistinctApps {
		c.accounts[accountID] = now.Add(circuitAccountCooldown)
	}
	c.empties[accountID] = kept

	if len(c.targets) > maxCircuitAccounts {
		c.pruneLocked(now)
	}
}

func (c *circuit) recordSuccess(accountID int64, _ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.accounts, accountID)
	delete(c.targets, accountID)
	delete(c.empties, accountID)
}

func (c *circuit) forget(accountID int64) {
	c.recordSuccess(accountID, "")
}

// CircuitForget drops all breaker state for the account (re-scan, deletion,
// expiry — anything that invalidates what the streaks were measuring).
func (p *Pool) CircuitForget(accountID int64) {
	p.breaker.forget(accountID)
}

func (c *circuit) pruneLocked(now time.Time) {
	if len(c.targets) < maxCircuitAccounts {
		return
	}
	for id, targets := range c.targets {
		if until, ok := c.accounts[id]; ok && until.After(now) {
			continue
		}
		live := false
		for _, t := range targets {
			if t.coolUntil.After(now) {
				live = true
				break
			}
		}
		if !live {
			delete(c.targets, id)
			delete(c.empties, id)
		}
	}
}
