package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestPbTagVarintEncoding(t *testing.T) {
	// Field numbers <= 15 must stay single-byte (wire compatible).
	if got := pbVar(1, 5); !bytes.Equal(got, []byte{0x08, 0x05}) {
		t.Fatalf("pbVar(1,5) = %x, want 0805", got)
	}
	if got := pbLen(3, []byte("ab")); !bytes.Equal(got, []byte{0x1a, 0x02, 'a', 'b'}) {
		t.Fatalf("pbLen(3,\"ab\") = %x, want 1a026162", got)
	}
	// Field numbers >= 16 must be encoded as multi-byte varint tags and
	// round-trip through pbParse (the previous single-byte encoding
	// truncated them).
	fields := pbParse(pbLen(16, []byte("xy")))
	if got := string(safeBytes(fields[16])); got != "xy" {
		t.Fatalf("pbParse(pbLen(16)) field 16 = %q, want \"xy\"", got)
	}
	fields = pbParse(pbVar(300, 7))
	if fields[300] != int64(7) {
		t.Fatalf("pbParse(pbVar(300,7)) field 300 = %v, want 7", fields[300])
	}
}

func TestLoginBudget(t *testing.T) {
	b := newLoginBudget(3, time.Minute)
	now := time.Now()
	b.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !b.take(1) {
			t.Fatalf("take #%d refused, want allowed", i+1)
		}
	}
	if b.take(1) {
		t.Fatalf("take #4 allowed, want refused (limit 3 per window)")
	}
	// Another account is independent.
	if !b.take(2) {
		t.Fatalf("take for account 2 refused, want allowed")
	}
	// The window slides: after it passes, the account may log in again.
	now = now.Add(2 * time.Minute)
	if !b.take(1) {
		t.Fatalf("take after window refused, want allowed")
	}
}
