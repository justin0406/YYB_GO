package protocol

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"yyb_go/internal/store"
)

func TestDeriveDeviceIdentityDeterministic(t *testing.T) {
	seed := []byte("0123456789abcdef0123456789abcdef")
	a := deriveDeviceIdentity(seed, "openid-1")
	b := deriveDeviceIdentity(seed, "openid-1")
	if len(a.AppDeviceID) != 32 {
		t.Fatalf("AppDeviceID length = %d, want 32", len(a.AppDeviceID))
	}
	if !bytes.Equal(a.AppDeviceID, b.AppDeviceID) || !bytes.Equal(a.SessDevice, b.SessDevice) {
		t.Fatalf("same seed+account must derive identical devices")
	}
	// A different account never shares a device.
	c := deriveDeviceIdentity(seed, "openid-2")
	if bytes.Equal(a.AppDeviceID, c.AppDeviceID) || bytes.Equal(a.SessDevice, c.SessDevice) {
		t.Fatalf("different accounts must derive different devices")
	}
	// A different installation seed never shares a device either.
	d := deriveDeviceIdentity([]byte("another-seed-another-seed-32by"), "openid-1")
	if bytes.Equal(a.AppDeviceID, d.AppDeviceID) {
		t.Fatalf("different seeds must derive different devices")
	}
	// Empty inputs keep the historical random behavior.
	if empty := deriveDeviceIdentity(seed, ""); !empty.empty() {
		t.Fatalf("empty account must yield an empty identity")
	}
	if empty := deriveDeviceIdentity(nil, "openid-1"); !empty.empty() {
		t.Fatalf("empty seed must yield an empty identity")
	}
}

func TestFormatSessDeviceShape(t *testing.T) {
	mac := formatSessDevice([]byte{0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	s := string(mac)
	if len(s) != 17 || strings.Count(s, "-") != 5 {
		t.Fatalf("sess device = %q, want XX-XX-XX-XX-XX-XX shape", s)
	}
	// Locally administered unicast: bit1 set, bit0 clear on the first byte.
	first := mac[0]
	if first&0x02 == 0 {
		t.Fatalf("sess device first byte %02X must have the local bit set", first)
	}
	if first&0x01 != 0 {
		t.Fatalf("sess device first byte %02X must be unicast", first)
	}
}

func TestDeviceSeedConverges(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	// Two pools on one database (e.g. during a rolling restart) must converge
	// on the first stored seed instead of each generating their own.
	s1, err := NewPool(DefaultConfig(), db).deviceSeed(ctx)
	if err != nil {
		t.Fatalf("first deviceSeed() error = %v", err)
	}
	s2, err := NewPool(DefaultConfig(), db).deviceSeed(ctx)
	if err != nil {
		t.Fatalf("second deviceSeed() error = %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatalf("seeds diverged: %x vs %x", s1, s2)
	}
	if len(s1) < 16 {
		t.Fatalf("seed too short: %d", len(s1))
	}
}
