package protocol

import (
	"sync"
	"time"
)

// A login budget caps how often business traffic may make the OAuth layer work
// for one account: a fresh ManualAuth login or a forced credential refresh.
//
// Replaying a Qinglong burst (dozens of codes for different AppIDs within
// minutes) against a healthy authorization kills it within about three
// minutes — either through repeated login tickets or through repeated forced
// refreshes, both ending on the same rejection chain. An authorization that
// nothing but scheduled renewal touched renews on schedule. What matters is
// the number of OAuth-layer calls per authorization, not the number of
// requests.
//
// The budget counts those calls per account in a sliding window and refuses
// the next one once the limit is reached, so the caller fails the request with
// the error it already has instead of provoking the upstream again. Manual
// refreshes via /accounts/refresh are not gated: they are deliberate and rare.

const (
	// DefaultLoginBudget and DefaultLoginWindow are the tested defaults
	// (mirroring YYB-Go-Enhanced): about one login every three minutes per
	// account is far below the rates that killed authorizations and above the
	// rates an authorization survived.
	DefaultLoginBudget = 3
	DefaultLoginWindow = 10 * time.Minute

	maxBudgetAccounts = 4096
)

type loginBudget struct {
	now func() time.Time

	mu       sync.Mutex
	limit    int
	window   time.Duration
	accounts map[int64][]time.Time // account → starts of the calls still inside the window, oldest first
}

func newLoginBudget(limit int, window time.Duration) *loginBudget {
	if limit <= 0 {
		limit = DefaultLoginBudget
	}
	if window <= 0 {
		window = DefaultLoginWindow
	}
	return &loginBudget{
		now:      time.Now,
		limit:    limit,
		window:   window,
		accounts: map[int64][]time.Time{},
	}
}

// take claims one OAuth-layer call for the account. It reports false when the
// account has already used its budget inside the window.
func (b *loginBudget) take(accountID int64) bool {
	if b == nil {
		return true
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := now.Add(-b.window)
	uses := b.accounts[accountID]
	drop := 0
	for drop < len(uses) && !uses[drop].After(cutoff) {
		drop++
	}
	uses = uses[drop:]
	if len(uses) >= b.limit {
		b.accounts[accountID] = uses
		return false
	}
	b.accounts[accountID] = append(uses, now)
	if len(b.accounts) > maxBudgetAccounts {
		b.pruneLocked(now)
	}
	return true
}

// pruneLocked forgets accounts whose window has emptied, so the table stays
// small even when a script walks many account IDs.
func (b *loginBudget) pruneLocked(now time.Time) {
	if len(b.accounts) < maxBudgetAccounts {
		return
	}
	cutoff := now.Add(-b.window)
	for id, uses := range b.accounts {
		if len(uses) == 0 || !uses[len(uses)-1].After(cutoff) {
			delete(b.accounts, id)
		}
	}
}

// AllowLogin reports whether traffic may make the OAuth layer work for the
// account (a fresh ManualAuth login or a forced credential refresh). A false
// answer means the caller should fail the request with the error it already
// has and must not touch the upstream again this window.
func (p *Pool) AllowLogin(accountID int64) bool {
	return p.budget.take(accountID)
}
