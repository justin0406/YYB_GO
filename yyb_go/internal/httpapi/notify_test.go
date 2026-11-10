package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"yyb_go/internal/store"
)

func TestNotifierDedupesPerAuthorization(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := newNotifier(notifyChannelWeCom, srv.URL, "")
	acc := &store.WechatAccount{
		ID:          7,
		OpenID:      "openid-7",
		Credentials: map[string]any{"accesstoken": "a", "refresh_refreshed_at": float64(1000)},
	}
	n.notifyAccountExpired(acc, "42007")
	n.notifyAccountExpired(acc, "42007") // same authorization: deduped
	n.wait()
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("deliveries = %d, want 1 (dedupe per authorization)", got)
	}

	// A re-scan produces a new authorization timestamp and may notify again.
	acc.Credentials["refresh_refreshed_at"] = float64(2000)
	n.notifyAccountExpired(acc, "42007")
	n.wait()
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("deliveries after re-scan = %d, want 2", got)
	}
}

func TestNotifierDisabledWithoutChannel(t *testing.T) {
	n := newNotifier("", "token", "")
	if n.enabled() {
		t.Fatalf("notifier without a channel must be disabled")
	}
	if n.claim(1, 1) {
		t.Fatalf("disabled notifier must never claim a notification")
	}
	n2 := newNotifier(notifyChannelPushPlus, "", "")
	if n2.enabled() {
		t.Fatalf("notifier without a token must be disabled")
	}
}

func TestNotifierDeliveryFailureIsNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	n := newNotifier(notifyChannelPushPlus, srv.URL, "")
	acc := &store.WechatAccount{ID: 1, OpenID: "o"}
	n.notifyAccountExpired(acc, "x")
	n.wait() // must return without panicking or blocking
}

func TestNotifierRedactsTokenOnTransportError(t *testing.T) {
	n := newNotifier(notifyChannelWeCom, "http://127.0.0.1:1/secret-key-should-not-appear", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := n.deliver(ctx, "t", "b")
	if err == nil {
		t.Fatalf("deliver() to a closed port must fail")
	}
	if got := err.Error(); contains(got, "secret-key") {
		t.Fatalf("error leaks the token: %s", got)
	}
}

func TestNotifyAccountExpiredBodyIsJSONSafe(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := newNotifier(notifyChannelWeCom, srv.URL, "")
	acc := &store.WechatAccount{ID: 3, OpenID: "openid-3", Nickname: strPtr("泽腾")}
	n.notifyAccountExpired(acc, "42007")
	n.wait()
	if got["msgtype"] != "text" {
		t.Fatalf("wecom payload msgtype = %v, want text", got["msgtype"])
	}
}

func strPtr(s string) *string { return &s }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
