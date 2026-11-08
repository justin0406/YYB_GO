package httpapi

import (
	"context"
	"log"
	"sync"
	"time"

	"yyb_go/internal/protocol"
)

// keepalive renews credentials ahead of expiry on a schedule instead of only
// when a request fails: scheduled, small renewals are the pattern that has
// been observed to keep authorizations alive, while error-triggered forced
// refreshes are the pattern that kills them.
//
// Failure handling is deliberately conservative: only a typed credential
// rejection (surfaced as status "expired") clears protocol state — transport
// failures just schedule a retry and leave the account untouched.

const (
	defaultKeepaliveInterval = 2 * time.Minute
	defaultKeepaliveAhead    = 4 * time.Minute
	keepaliveRetryBackoff    = 5 * time.Minute
	keepaliveMinTimeout      = 30 * time.Second
)

// credentialsDue reports whether the account's credentials should be renewed
// now: they are due once the remaining lifetime drops below ahead.
func credentialsDue(creds protocol.LoginBufferCredentials, now time.Time, ahead time.Duration) bool {
	if creds.AccessToken == "" || creds.ExpiresAt == 0 {
		return false
	}
	return now.Add(ahead).Unix() >= creds.ExpiresAt
}

func (a *App) keepaliveTick(ctx context.Context) {
	accounts, err := a.db.ListAccounts(ctx)
	if err != nil {
		log.Printf("keepalive: list accounts: %v", err)
		return
	}
	now := time.Now()
	for _, acc := range accounts {
		if ctx.Err() != nil {
			return
		}
		if !credentialsDue(protocol.CredentialsFromMap(acc.Credentials), now, a.cfg.KeepaliveAhead) {
			continue
		}
		a.keepaliveAccount(ctx, acc.ID)
	}
}

func (a *App) keepaliveAccount(ctx context.Context, id int64) {
	a.kaMu.Lock()
	if until, ok := a.kaRetry[id]; ok && until.After(time.Now()) {
		a.kaMu.Unlock()
		return
	}
	a.kaMu.Unlock()

	// Re-read: the account may have been re-scanned or deleted since listing.
	fresh, err := a.db.GetAccount(ctx, id)
	if err != nil {
		a.kaMu.Lock()
		a.kaRetry[id] = time.Now().Add(keepaliveRetryBackoff)
		a.kaMu.Unlock()
		return
	}
	if fresh.Status != nil && *fresh.Status == "expired" {
		// Wait for a re-scan; refreshing now would only provoke the upstream.
		a.kaMu.Lock()
		delete(a.kaRetry, id)
		a.kaMu.Unlock()
		return
	}
	if !credentialsDue(protocol.CredentialsFromMap(fresh.Credentials), time.Now(), a.cfg.KeepaliveAhead) {
		return
	}

	timeout := 4 * a.cfg.RequestTimeout
	if timeout < keepaliveMinTimeout {
		timeout = keepaliveMinTimeout
	}
	refreshCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	status := a.refreshLiveness(refreshCtx, fresh)

	a.kaMu.Lock()
	defer a.kaMu.Unlock()
	switch status {
	case "alive":
		delete(a.kaRetry, id)
	case "expired":
		// A definitive rejection: drop the protocol session and breaker state
		// so nothing keeps using the dead authorization.
		_ = a.db.InvalidateSession(ctx, id, a.cfg.TCPProxy)
		a.pool.CircuitForget(id)
		delete(a.kaRetry, id)
	default:
		// Transport or other non-verdict failure: retry after a backoff and
		// leave the account status alone.
		a.kaRetry[id] = time.Now().Add(keepaliveRetryBackoff)
	}
}

// refreshLockFor serializes credential refreshes per account, so a scheduled
// keepalive renewal and an error-triggered refresh cannot race on the same
// rotating refresh token.
func (a *App) refreshLockFor(id int64) *sync.Mutex {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if l := a.refreshLocks[id]; l != nil {
		return l
	}
	l := &sync.Mutex{}
	a.refreshLocks[id] = l
	return l
}
