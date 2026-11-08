package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestHandlerRequiresLogin(t *testing.T) {
	app := newTestApp(t, Config{AuthUser: "admin", AuthPassword: "s3cret"})
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
	login := func(user, pass string) *httptest.ResponseRecorder {
		form := url.Values{"username": {user}, "password": {pass}, "next": {"/accounts"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Open routes stay open with auth enabled.
	if rec := open(http.MethodGet, "/health", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /health with auth enabled status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/login", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /login status = %d, want 200", rec.Code)
	}

	// API clients get a 401 JSON envelope; browsers get redirected to /login.
	if rec := open(http.MethodGet, "/accounts", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /accounts without session status = %d, want 401", rec.Code)
	}
	browser := open(http.MethodGet, "/accounts", map[string]string{"Accept": "text/html,application/xhtml+xml"})
	if browser.Code != http.StatusFound {
		t.Fatalf("browser GET /accounts status = %d, want 302", browser.Code)
	}
	if loc := browser.Header().Get("Location"); !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("browser redirect Location = %q, want /login?next=...", loc)
	}

	// Wrong credentials do not reach the protected target.
	if rec := login("admin", "wrong"); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /login wrong password status = %d, want 303", rec.Code)
	} else if strings.Contains(rec.Header().Get("Location"), "/accounts") {
		t.Fatalf("wrong password redirected to %q, want back to /login", rec.Header().Get("Location"))
	}

	// Correct credentials redirect to next and set the session cookie.
	rec := login("admin", "s3cret")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /login status = %d, want 303", rec.Code)
	}
	var session *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			session = ck
		}
	}
	if session == nil || session.Value == "" {
		t.Fatalf("POST /login did not set %s cookie", sessionCookieName)
	}

	// Session cookie authorizes protected routes.
	if rec := open(http.MethodGet, "/accounts", map[string]string{"Cookie": session.Name + "=" + session.Value}); rec.Code != http.StatusOK {
		t.Fatalf("GET /accounts with session cookie status = %d, want 200", rec.Code)
	}
	// Bearer password authorizes API clients without a session.
	if rec := open(http.MethodGet, "/accounts", map[string]string{"Authorization": "Bearer s3cret"}); rec.Code != http.StatusOK {
		t.Fatalf("GET /accounts with Bearer password status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts", map[string]string{"X-YYB-Token": "s3cret"}); rec.Code != http.StatusOK {
		t.Fatalf("GET /accounts with X-YYB-Token status = %d, want 200", rec.Code)
	}
	if rec := open(http.MethodGet, "/accounts", map[string]string{"Authorization": "Bearer wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /accounts with wrong Bearer status = %d, want 401", rec.Code)
	}

	// Logout drops the session.
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(session)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout status = %d, want 303", logoutRec.Code)
	}
	if rec := open(http.MethodGet, "/accounts", map[string]string{"Cookie": session.Name + "=" + session.Value}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /accounts after logout status = %d, want 401", rec.Code)
	}
}

func TestWXAppAppIDPolicy(t *testing.T) {
	t.Setenv("YYB_CODE_DENY_APPIDS", "wxdeadbeefcafe")
	app := newTestApp(t, Config{})

	post := func(a *App, appid string) *httptest.ResponseRecorder {
		body := `{"ref":"1","app_id":"` + appid + `"}`
		req := httptest.NewRequest(http.MethodPost, "/wxapp/getCode", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Built-in website-app AppIDs are refused before anything is sent
	// upstream, with a reason the caller can act on.
	rec := post(app, "wx5cd60c5d4817a188")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked builtin appid status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "网站应用") {
		t.Fatalf("blocked builtin appid body = %s, want reason", rec.Body.String())
	}
	// The env-configured deny list is honored too.
	if rec := post(app, "wxdeadbeefcafe"); rec.Code != http.StatusForbidden {
		t.Fatalf("blocked env appid status = %d, want 403", rec.Code)
	}
	// Unknown mini-program AppIDs pass the policy layer (they then fail on
	// account resolution).
	if rec := post(app, "wx1234567890abcdef"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown appid status = %d, want 404 (policy must not block it)", rec.Code)
	}

	// An explicit allow lifts even the built-in refusal.
	t.Setenv("YYB_CODE_ALLOW_APPIDS", "wx5cd60c5d4817a188")
	allowed := newTestApp(t, Config{})
	if rec := post(allowed, "wx5cd60c5d4817a188"); rec.Code != http.StatusNotFound {
		t.Fatalf("allowed appid status = %d, want 404 (policy must not block it)", rec.Code)
	}
}

func TestInvokeWXAppExpiredShortCircuit(t *testing.T) {
	app := newTestApp(t, Config{})
	ctx := context.Background()
	acc, err := app.db.UpsertAccount(ctx, "openid-expired", "buffer", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	if err := app.db.SetAccountStatus(ctx, acc.ID, "expired"); err != nil {
		t.Fatalf("SetAccountStatus() error = %v", err)
	}
	// Reload like the HTTP handler does: the status lives in the DB row.
	acc, err = app.db.GetAccount(ctx, acc.ID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	calls := 0
	_, err = app.invokeWXApp(ctx, acc, "wxapp", nil, func(context.Context, *store.WechatAccount, string, map[string]any) (map[string]any, error) {
		calls++
		return nil, nil
	})
	var expiredErr accountExpiredError
	if !errors.As(err, &expiredErr) {
		t.Fatalf("invokeWXApp() error = %v, want accountExpiredError", err)
	}
	if calls != 0 {
		t.Fatalf("expired account must not be touched upstream, calls = %d", calls)
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
