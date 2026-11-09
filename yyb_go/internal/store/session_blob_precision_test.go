package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// A WeChat UIN exceeds 2^53, so it cannot survive a float64 round-trip. The
// session cache is read on every request after the first fresh login, and a
// rounded UIN makes the request carry a different identity than the handshake
// established (upstream answers "shortlink application -14").
const largeUIN int64 = 25985014796420881

func TestDecodeSessionBlobPreservesLargeUIN(t *testing.T) {
	raw := `{"session":{"uin":25985014796420881,"send_key":"AA=="},"psk_entry":{"psk_type":1}}`
	blob, err := decodeSessionBlob(raw)
	if err != nil {
		t.Fatalf("decodeSessionBlob() error = %v", err)
	}
	sm, ok := blob["session"].(map[string]any)
	if !ok {
		t.Fatalf("session = %#v", blob["session"])
	}
	num, ok := sm["uin"].(json.Number)
	if !ok {
		t.Fatalf("uin decoded as %T, want json.Number", sm["uin"])
	}
	if num.String() != "25985014796420881" {
		t.Fatalf("uin text = %q, want exact decimal", num.String())
	}
	got, err := num.Int64()
	if err != nil {
		t.Fatalf("uin Int64() error = %v", err)
	}
	if got != largeUIN {
		t.Fatalf("uin = %d, want %d", got, largeUIN)
	}
}

func TestDecodeSessionBlobRejectsTrailingData(t *testing.T) {
	for _, raw := range []string{
		`{"session":{}} {"session":{}}`,
		`{"session":{}} garbage`,
		`{"session":{}`,
	} {
		if _, err := decodeSessionBlob(raw); err == nil {
			t.Fatalf("decodeSessionBlob(%q) accepted malformed blob", raw)
		}
	}
}

func TestSessionRoundTripPreservesLargeUIN(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "yyb.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	acc, err := db.UpsertAccount(ctx, "openid-precision", "buffer", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	uin := largeUIN
	blob := map[string]any{
		"session":   map[string]any{"uin": uin, "send_key": []byte{1, 2, 3}},
		"psk_entry": map[string]any{"psk_type": 1},
	}
	if err = db.PutSession(ctx, acc.ID, &uin, blob, time.Now().Add(time.Hour).Unix(), ""); err != nil {
		t.Fatalf("PutSession() error = %v", err)
	}

	row, err := db.GetSession(ctx, acc.ID, "")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	sm, ok := row.SessionBlob["session"].(map[string]any)
	if !ok {
		t.Fatalf("session = %#v", row.SessionBlob["session"])
	}
	num, ok := sm["uin"].(json.Number)
	if !ok {
		t.Fatalf("cached uin decoded as %T, want json.Number", sm["uin"])
	}
	got, err := num.Int64()
	if err != nil {
		t.Fatalf("cached uin Int64() error = %v", err)
	}
	if got != largeUIN {
		t.Fatalf("cached uin = %d, want exact %d", got, largeUIN)
	}
	if row.UIN == nil || *row.UIN != largeUIN {
		t.Fatalf("session row uin = %v, want %d", row.UIN, largeUIN)
	}
}
