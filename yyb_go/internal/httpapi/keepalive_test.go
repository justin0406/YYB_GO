package httpapi

import (
	"testing"
	"time"

	"yyb_go/internal/protocol"
)

func TestCredentialsDue(t *testing.T) {
	now := time.Now()
	if credentialsDue(protocol.LoginBufferCredentials{}, now, time.Minute) {
		t.Fatalf("empty credentials must never be due")
	}
	creds := protocol.LoginBufferCredentials{AccessToken: "a", ExpiresAt: now.Add(2 * time.Minute).Unix()}
	if !credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("expiring within ahead must be due")
	}
	// Fresh token pair AND fresh login_buffer: not due.
	creds.ExpiresAt = now.Add(time.Hour).Unix()
	creds.RefreshedAt = now.Add(-time.Minute).Unix()
	if credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("credential with an hour left must not be due")
	}
	// The login_buffer ticket dies far sooner than the token pair: an old
	// refresh timestamp makes the record due even with hours of token left.
	creds.RefreshedAt = now.Add(-16 * time.Minute).Unix()
	if !credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("stale login_buffer must be due")
	}
	// Legacy records without a timestamp get refreshed once to stamp it.
	creds.RefreshedAt = 0
	if !credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("legacy record without refresh timestamp must be due")
	}
}
