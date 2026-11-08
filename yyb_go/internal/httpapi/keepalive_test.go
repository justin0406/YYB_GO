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
	creds.ExpiresAt = now.Add(time.Hour).Unix()
	if credentialsDue(creds, now, 4*time.Minute) {
		t.Fatalf("credential with an hour left must not be due")
	}
}
