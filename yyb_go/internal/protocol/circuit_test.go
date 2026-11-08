package protocol

import (
	"testing"
	"time"
)

func TestPacingReserve(t *testing.T) {
	g := newPacingGate()
	now := time.Now()
	g.now = func() time.Time { return now }

	// First request starts immediately and moves the slot.
	wait, ok := g.reserve(1, DefaultPaceGap, DefaultPaceMaxWait)
	if !ok || wait != 0 {
		t.Fatalf("first reserve = (%v, %v), want (0, true)", wait, ok)
	}
	// The next request inside the gap must wait for its slot.
	now = now.Add(100 * time.Millisecond)
	wait, ok = g.reserve(1, DefaultPaceGap, DefaultPaceMaxWait)
	if !ok || wait != 2900*time.Millisecond {
		t.Fatalf("second reserve = (%v, %v), want (2.9s, true)", wait, ok)
	}
	// A refusal (queue longer than MaxWait) must not move the slot: after it,
	// the queue state is unchanged.
	for i := 0; ; i++ {
		now = now.Add(10 * time.Millisecond)
		wait, ok = g.reserve(1, DefaultPaceGap, DefaultPaceMaxWait)
		if !ok {
			break
		}
		if i > 100 {
			t.Fatalf("reserve never refused after 100 queued requests")
		}
	}
	before := g.next[1]
	now = now.Add(10 * time.Millisecond)
	if _, ok = g.reserve(1, DefaultPaceGap, DefaultPaceMaxWait); ok {
		t.Fatalf("reserve allowed while queue full")
	}
	if !g.next[1].Equal(before) {
		t.Fatalf("refusal moved the slot: %v → %v", before, g.next[1])
	}
	// A different account is independent.
	if _, ok := g.reserve(2, DefaultPaceGap, DefaultPaceMaxWait); !ok {
		t.Fatalf("account 2 refused, want allowed")
	}
}

func TestCircuitBreaker(t *testing.T) {
	c := newCircuit()
	now := time.Now()
	c.now = func() time.Time { return now }
	appA, appB, appC, appD := "wxaaa", "wxbbb", "wxccc", "wxddd"

	// Three consecutive empty codes cool the target down…
	for i := 0; i < circuitTargetStreakLimit; i++ {
		c.recordEmpty(1, appA)
	}
	if c.allow(1, appA) {
		t.Fatalf("target %s allowed after %d empty codes, want cooled", appA, circuitTargetStreakLimit)
	}
	// …but other targets of the same account are still allowed.
	if !c.allow(1, appB) {
		t.Fatalf("target %s refused, want allowed (account layer not open yet)", appB)
	}
	// Three distinct refused AppIDs inside the window open the account layer.
	c.recordEmpty(1, appB)
	c.recordEmpty(1, appC)
	if c.allow(1, appD) {
		t.Fatalf("account layer open after %d distinct refused appIDs, want all refused", circuitAccountDistinctApps)
	}
	if !c.accounts[1].After(now) {
		t.Fatalf("account cooldown not recorded")
	}

	// One real success clears everything for the account.
	c.recordSuccess(1, appA)
	if !c.allow(1, appA) || !c.allow(1, appD) {
		t.Fatalf("success must clear target and account state")
	}

	// Failures farther apart than the streak window are not "consecutive":
	// the old empty code is forgotten and a fresh streak of three is needed.
	c2 := newCircuit()
	t0 := time.Now()
	c2.now = func() time.Time { return t0 }
	c2.recordEmpty(2, appA)
	t0 = t0.Add(2 * circuitStreakResetWindow)
	for i := 0; i < circuitTargetStreakLimit; i++ {
		c2.recordEmpty(2, appA)
	}
	if c2.allow(2, appA) {
		t.Fatalf("target allowed, want cooled after fresh streak")
	}
	// Wait for the target cooldown to expire.
	t0 = t0.Add(circuitTargetCooldown + time.Minute)
	if !c2.allow(2, appA) {
		t.Fatalf("target still cooled after cooldown expired")
	}
}
