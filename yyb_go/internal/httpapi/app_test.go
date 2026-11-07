package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func TestHandlerServesGinRoutesAndSwaggerDocs(t *testing.T) {
	t.Setenv("GIN_MODE", "test")

	app, err := NewApp(Config{
		ResourceRoot:   t.TempDir(),
		RequestTimeout: time.Second,
		AvatarTimeout:  time.Second,
		SessionTTL:     time.Minute,
		QRSessionTTL:   time.Minute,
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	handler := app.Handler()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d", health.Code)
	}
	var healthBody struct {
		Code int            `json:"code"`
		Msg  string         `json:"msg"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("decode health JSON: %v", err)
	}
	if healthBody.Code != 0 || healthBody.Msg != "success" || healthBody.Data["ok"] != true {
		t.Fatalf("GET /health body = %#v", healthBody)
	}

	openapi := httptest.NewRecorder()
	handler.ServeHTTP(openapi, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if openapi.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json status = %d", openapi.Code)
	}
	var spec map[string]any
	if err := json.Unmarshal(openapi.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode OpenAPI JSON: %v", err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Fatalf("openapi version = %v", spec["openapi"])
	}
	if _, ok := spec["code"]; ok {
		t.Fatalf("OpenAPI JSON should not be wrapped in API envelope")
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI paths missing or invalid")
	}
	for _, path := range []string{"/wxapp/getCode", "/wxapp/getPhoneNumber", "/wxapp/operateWxData", "/accounts/avatar"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("OpenAPI path %s missing", path)
		}
	}
	for _, path := range []string{"/wxapp/getCode", "/wxapp/getPhoneNumber", "/wxapp/operateWxData"} {
		pathItem := paths[path].(map[string]any)
		post := pathItem["post"].(map[string]any)
		tags := post["tags"].([]any)
		if len(tags) != 1 || tags[0] != "wxapp" {
			t.Fatalf("OpenAPI path %s tags = %#v, want [wxapp]", path, tags)
		}
	}
	for _, path := range []string{"/accounts/{ref}", "/accounts/{ref}/getCode", "/accounts/{ref}/getPhoneNumber", "/accounts/{ref}/operateWxData", "/accounts/getCode", "/accounts/getPhoneNumber", "/accounts/operateWxData"} {
		if _, ok := paths[path]; ok {
			t.Fatalf("OpenAPI still exposes old account feature route %s", path)
		}
	}
	if _, ok := paths["/features"]; ok {
		t.Fatalf("OpenAPI still exposes /features")
	}

	docs := httptest.NewRecorder()
	handler.ServeHTTP(docs, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if docs.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /docs status = %d", docs.Code)
	}
	if got := docs.Header().Get("Location"); got != "/docs/index.html" {
		t.Fatalf("GET /docs Location = %q", got)
	}

	features := httptest.NewRecorder()
	handler.ServeHTTP(features, httptest.NewRequest(http.MethodGet, "/features", nil))
	if features.Code != http.StatusNotFound {
		t.Fatalf("GET /features status = %d", features.Code)
	}
	var notFoundBody struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data any    `json:"data"`
	}
	if err := json.Unmarshal(features.Body.Bytes(), &notFoundBody); err != nil {
		t.Fatalf("decode /features error JSON: %v", err)
	}
	if notFoundBody.Code == 0 || notFoundBody.Msg == "" || notFoundBody.Data != nil {
		t.Fatalf("GET /features body = %#v", notFoundBody)
	}

	oldPath := httptest.NewRecorder()
	handler.ServeHTTP(oldPath, httptest.NewRequest(http.MethodPost, "/accounts/getCode", nil))
	if oldPath.Code != http.StatusNotFound {
		t.Fatalf("POST old account feature route status = %d", oldPath.Code)
	}
}

func newTestApp(t *testing.T, cfg Config) *App {
	t.Helper()
	t.Setenv("GIN_MODE", "test")
	if cfg.ResourceRoot == "" {
		cfg.ResourceRoot = t.TempDir()
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = time.Second
	}
	if cfg.AvatarTimeout == 0 {
		cfg.AvatarTimeout = time.Second
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = time.Minute
	}
	if cfg.QRSessionTTL == 0 {
		cfg.QRSessionTTL = time.Minute
	}
	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app
}

func TestHandlerRequiresAuthToken(t *testing.T) {
	app := newTestApp(t, Config{AuthToken: "s3cret"})
	handler := app.Handler()

	open := func(method, target string, header map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := open(http.MethodGet, "/health", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /health with auth enabled status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/scan", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /scan with auth enabled status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /accounts without token status = %d, want 401", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts?token=wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /accounts with wrong token status = %d, want 401", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts?token=s3cret", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /accounts with token query param status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts", map[string]string{"Authorization": "Bearer s3cret"}); rec.Code != http.StatusOK {
		t.Fatalf("GET /accounts with Bearer header status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts", map[string]string{"X-YYB-Token": "s3cret"}); rec.Code != http.StatusOK {
		t.Fatalf("GET /accounts with X-YYB-Token header status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodPost, "/qr", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /qr without token status = %d, want 401", rec.Code)
	}
	if rec := open(http.MethodGet, "/openapi.json", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json with auth enabled status = %d, want 200", rec.Code)
	}
}

func TestInvokeWXAppErrorClassification(t *testing.T) {
	app := newTestApp(t, Config{})
	ctx := context.Background()
	acc, err := app.db.UpsertAccount(ctx, "openid-classify", "buffer", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}

	// Stale session: exactly one retry, then success; no credential refresh.
	calls := 0
	want := map[string]any{"ok": true}
	result, err := app.invokeWXApp(ctx, acc, "wxapp", nil, func(context.Context, *store.WechatAccount, string, map[string]any) (map[string]any, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("send failed: %w", protocol.ErrStaleSession)
		}
		return want, nil
	})
	if err != nil {
		t.Fatalf("invokeWXApp() error = %v, want nil", err)
	}
	if calls != 2 {
		t.Fatalf("stale session retry calls = %d, want 2", calls)
	}
	if result["ok"] != true {
		t.Fatalf("invokeWXApp() result = %#v", result)
	}

	// Transport error: surfaced as-is, no retry, no status downgrade.
	calls = 0
	_, err = app.invokeWXApp(ctx, acc, "wxapp", nil, func(context.Context, *store.WechatAccount, string, map[string]any) (map[string]any, error) {
		calls++
		return nil, fmt.Errorf("dial tcp: i/o timeout")
	})
	if err == nil || errors.Is(err, accountExpiredError{}) {
		t.Fatalf("invokeWXApp() transport error = %v, want original error", err)
	}
	if calls != 1 {
		t.Fatalf("transport error calls = %d, want 1 (no retry)", calls)
	}
	reloaded, reloadErr := app.db.GetAccount(ctx, acc.ID)
	if reloadErr != nil {
		t.Fatalf("GetAccount() error = %v", reloadErr)
	}
	if reloaded.Status != nil && *reloaded.Status == "expired" {
		t.Fatalf("transport error must not mark account expired, status = %q", *reloaded.Status)
	}
}
