package protocol

import (
	"errors"
	"testing"
	"time"
)

func TestShortlinkHeaderRejection(t *testing.T) {
	// A header-only wpkg body: field 23 = -14 is an authenticated application
	// rejection, which must classify as such and must NOT be treated as a
	// stale session (that misclassification deleted healthy sessions).
	headerOnly := wpkgHead(map[int]uint64{1: 1, 23: negVarint(-14)}, nil)
	if err := shortlinkHeaderRejection(headerOnly); err == nil {
		t.Fatalf("header with field 23 = -14 must be a rejection")
	} else {
		if !IsApplicationRequestRejection(err) {
			t.Fatalf("field 23 rejection must be an application rejection, got %v", err)
		}
		var rej *ShortlinkRejectedError
		if !errors.As(err, &rej) || rej.Code != -14 || rej.Transport {
			t.Fatalf("rejection = %#v, want application code -14", rej)
		}
	}

	// Field 4 is the transport layer.
	transport := wpkgHead(map[int]uint64{1: 1, 4: negVarint(-6)}, nil)
	if err := shortlinkHeaderRejection(transport); err == nil || IsApplicationRequestRejection(err) {
		t.Fatalf("field 4 must be a transport rejection, got %v", err)
	}

	// A clean header with an encrypted body after it is not a rejection.
	clean := append(wpkgHead(map[int]uint64{1: 1}, nil), 0xde, 0xad, 0xbe, 0xef)
	if err := shortlinkHeaderRejection(clean); err != nil {
		t.Fatalf("header followed by payload must not be a rejection, got %v", err)
	}
	// A body without a decodable header is not a rejection either.
	if err := shortlinkHeaderRejection([]byte{0xff, 0xff}); err != nil {
		t.Fatalf("garbage must not be a rejection, got %v", err)
	}
}

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

// negVarint renders a negative int64 the way protobuf encodes it (10-byte
// two's complement varint), which is what the upstream puts in wpkg fields.
func negVarint(v int64) uint64 { return uint64(v) }
