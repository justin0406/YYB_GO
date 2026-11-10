package protocol

import (
	"context"
	"testing"

	"yyb_go/internal/store"
)

func TestFreshLoginBufferFallsBackWhenUnavailable(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer db.Close()
	pool := NewPool(DefaultConfig(), db)
	ctx := context.Background()

	const stored = "stored-ticket"
	// No account / no credentials: the stored ticket is used as-is.
	if got := pool.freshLoginBuffer(ctx, nil, stored); got != stored {
		t.Fatalf("nil account = %q, want stored", got)
	}
	acc := &store.WechatAccount{ID: 1, OpenID: "o1"}
	if got := pool.freshLoginBuffer(ctx, acc, stored); got != stored {
		t.Fatalf("account without credentials = %q, want stored", got)
	}
	// Credentials without an access token cannot mint either.
	acc.Credentials = map[string]any{"openid": "o1"}
	if got := pool.freshLoginBuffer(ctx, acc, stored); got != stored {
		t.Fatalf("credentials without access token = %q, want stored", got)
	}
	// A token that the upstream cannot use (no network here) must not turn a
	// recoverable login into a hard failure: fall back to the stored ticket.
	acc.Credentials = map[string]any{"openid": "o1", "accesstoken": "invalid", "refreshtoken": "r"}
	if got := pool.freshLoginBuffer(ctx, acc, stored); got != stored {
		t.Fatalf("failed mint = %q, want stored fallback", got)
	}
}
