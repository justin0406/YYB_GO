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
	// An hour of token left: not due, whatever the login_buffer age — the
	// buffer is renewed at login time, not on this schedule.
	creds.ExpiresAt = now.Add(time.Hour).Unix()
	creds.RefreshedAt = now.Add(-time.Minute).Unix()
	if credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("credential with an hour left must not be due")
	}
	creds.RefreshedAt = now.Add(-2 * time.Hour).Unix()
	if credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("stale login_buffer must not drive credential rotation")
	}
	// Legacy records without a timestamp still follow the token clock.
	creds.RefreshedAt = 0
	if credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("legacy record with an hour of token left must not be due")
	}
	creds.ExpiresAt = now.Add(time.Minute).Unix()
	if !credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("legacy record near expiry must be due")
	}
}
