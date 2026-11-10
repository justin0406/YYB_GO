package protocol

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"yyb_go/internal/store"
)

type Config struct {
	ShortlinkTimeout        time.Duration
	LoginTimeout            time.Duration
	SessionTTL              time.Duration
	DNSCacheTTL             time.Duration
	MaxShortlinkConcurrency int
	MaxLoginConcurrency     int
	TCPProxy                string
	TCPProxyFallbackDirect  bool
}

func DefaultConfig() Config {
	return Config{
		ShortlinkTimeout:        8 * time.Second,
		LoginTimeout:            30 * time.Second,
		SessionTTL:              30 * time.Minute,
		DNSCacheTTL:             30 * time.Minute,
		MaxShortlinkConcurrency: 1000,
		MaxLoginConcurrency:     32,
		TCPProxyFallbackDirect:  true,
	}
}

type WmpfSession struct {
	Session          AppSession
	PSK              pskEntry
	ShortlinkTargets []Target
	CreatedAt        time.Time
	TCPProxy         string
	// SessDevice is the stable per-account session device this session was
	// established with; JSAPI requests must keep presenting it. Empty means
	// the session predates stable identities and callers fall back random.
	SessDevice []byte
}

type Pool struct {
	cfg Config
	db  *store.DB

	mu    sync.Mutex
	locks map[string]*sync.Mutex

	loginSem     chan struct{}
	shortlinkSem chan struct{}
	budget       *loginBudget
	pace         *pacingGate
	breaker      *circuit

	loginBuffers *LoginBufferClient

	deviceSeedMu    sync.Mutex
	deviceSeedValue []byte
}

func NewPool(cfg Config, db *store.DB) *Pool {
	def := DefaultConfig()
	if cfg.ShortlinkTimeout == 0 {
		cfg.ShortlinkTimeout = def.ShortlinkTimeout
	}
	if cfg.LoginTimeout == 0 {
		cfg.LoginTimeout = def.LoginTimeout
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = def.SessionTTL
	}
	if cfg.DNSCacheTTL == 0 {
		cfg.DNSCacheTTL = def.DNSCacheTTL
	}
	if cfg.MaxShortlinkConcurrency == 0 {
		cfg.MaxShortlinkConcurrency = def.MaxShortlinkConcurrency
	}
	if cfg.MaxLoginConcurrency == 0 {
		cfg.MaxLoginConcurrency = def.MaxLoginConcurrency
	}
	return &Pool{
		cfg:          cfg,
		db:           db,
		locks:        map[string]*sync.Mutex{},
		loginSem:     make(chan struct{}, cfg.MaxLoginConcurrency),
		shortlinkSem: make(chan struct{}, cfg.MaxShortlinkConcurrency),
		budget:       newLoginBudget(DefaultLoginBudget, DefaultLoginWindow),
		pace:         newPacingGate(),
		breaker:      newCircuit(),
		loginBuffers: NewLoginBufferClient(cfg.ShortlinkTimeout),
	}
}

// freshLoginBuffer mints a new login_buffer ticket from the account's current
// access token, falling back to the stored buffer when that is impossible
// (no credentials, expired token, transport error). The mint is a read-only
// call: it does not rotate the OAuth credential pair and is not counted
// against the login budget.
func (p *Pool) freshLoginBuffer(ctx context.Context, acc *store.WechatAccount, stored string) string {
	if acc == nil || acc.Credentials == nil || p.loginBuffers == nil {
		return stored
	}
	creds := CredentialsFromMap(acc.Credentials)
	if creds.AccessToken == "" {
		return stored
	}
	lb, err := p.loginBuffers.FetchLoginBuffer(ctx, creds)
	if err != nil {
		log.Printf("pool: mint fresh login_buffer for account %d failed, using stored: %v", acc.ID, err)
		return stored
	}
	return lb
}

// sessDevice returns the stable session device of the session, falling back
// to a fresh random one for sessions created before stable identities.
func (st WmpfSession) sessDevice() []byte {
	if len(st.SessDevice) != 0 {
		return st.SessDevice
	}
	return randomSessDevice()
}

func (p *Pool) GetCode(ctx context.Context, loginBuffer, appID string, accountID int64, tcpProxy string) (map[string]any, error) {
	// The breaker is checked before anything is sent: an open circuit returns
	// a local refusal instead of hammering a combination that keeps failing.
	if !p.breaker.allow(accountID, appID) {
		return nil, fmt.Errorf("%w for account %d app %s: repeated empty codes; cooling down, retry later", ErrCircuitOpen, accountID, appID)
	}
	res, err := p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		hostAppID := st.Session.HostAppID
		if len(hostAppID) == 0 {
			hostAppID = hostAppIDDefault
		}
		plain := buildJSAPIPlaintext(st.Session.UIN, appID, jsLoginURL, jsLoginCmdID, nil, hostAppID, st.sessDevice())
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		code, _, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		return map[string]any{"code": string(code), "errMsg": "login:ok"}, nil
	})
	if err != nil {
		// An application -14 is a business refusal, not a session signal —
		// but it IS a breaker signal, like an empty code: repeated ones mean
		// this (account, appID) combination keeps being refused upstream.
		if IsApplicationRequestRejection(err) {
			p.breaker.recordEmpty(accountID, appID)
		}
		// Transport-level failures are not breaker signals (the session
		// healing path owns them).
		return nil, err
	}
	if code, _ := res["code"].(string); code == "" {
		p.breaker.recordEmpty(accountID, appID)
	} else {
		p.breaker.recordSuccess(accountID, appID)
	}
	return res, nil
}

func (p *Pool) GetPhoneNumber(ctx context.Context, loginBuffer, appID string, accountID int64, tcpProxy string) (map[string]any, error) {
	return p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain := buildPhoneRequest(st.Session.UIN, appID, st.sessDevice())
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		code, resp, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		return parseRawResponse(code, resp), nil
	})
}

func (p *Pool) OperateWXData(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, tcpProxy string) (map[string]any, error) {
	return p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain, err := buildOperateRequest(st.Session.UIN, appID, payload, st.sessDevice())
		if err != nil {
			return nil, err
		}
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		code, resp, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		return parseRawResponse(code, resp), nil
	})
}

func (p *Pool) Invalidate(ctx context.Context, accountID int64, tcpProxy string) error {
	return p.db.InvalidateSession(ctx, accountID, effectiveProxy(tcpProxy, p.cfg.TCPProxy))
}

func (p *Pool) run(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string, op func(context.Context, WmpfSession) (map[string]any, error)) (map[string]any, error) {
	effective := effectiveProxy(tcpProxy, p.cfg.TCPProxy)
	st, err := p.state(ctx, loginBuffer, accountID, effective)
	if err == nil {
		res, err := op(ctx, st)
		if err == nil || effective == "" || !p.cfg.TCPProxyFallbackDirect || errors.Is(err, ErrStaleSession) {
			return res, err
		}
		_ = p.Invalidate(ctx, accountID, effective)
	}
	if effective != "" && p.cfg.TCPProxyFallbackDirect {
		st, err = p.state(ctx, loginBuffer, accountID, "")
		if err != nil {
			return nil, err
		}
		return op(ctx, st)
	}
	return nil, err
}

func (p *Pool) state(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string) (WmpfSession, error) {
	if row, err := p.db.GetSession(ctx, accountID, tcpProxy); err == nil {
		return sessionFromBlob(row.SessionBlob)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return WmpfSession{}, err
	}
	lock := p.lockFor(fmt.Sprintf("%d\x00%s", accountID, tcpProxy))
	lock.Lock()
	defer lock.Unlock()
	if row, err := p.db.GetSession(ctx, accountID, tcpProxy); err == nil {
		return sessionFromBlob(row.SessionBlob)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return WmpfSession{}, err
	}
	acc, err := p.db.GetAccount(ctx, accountID)
	if err != nil {
		return WmpfSession{}, err
	}
	dev := p.deviceFor(ctx, acc.OpenID, acc.ID)
	// A fresh ManualAuth is an OAuth-layer call; once the account has used up
	// its sliding-window budget, refuse locally instead of provoking the
	// upstream again.
	if !p.AllowLogin(accountID) {
		return WmpfSession{}, fmt.Errorf("%w for account %d: too many OAuth logins in %v; retry later",
			ErrLoginBudgetExhausted, accountID, DefaultLoginWindow)
	}
	if err = acquire(ctx, p.loginSem); err != nil {
		return WmpfSession{}, err
	}
	defer release(p.loginSem)
	loginCtx, cancel := context.WithTimeout(ctx, p.cfg.LoginTimeout)
	defer cancel()
	// The stored login_buffer ticket lives far shorter (~10-12 min) than the
	// token pair, so a ManualAuth with the stored one is routinely refused
	// ("ManualAuthResponse missing session block"). Mint a fresh ticket from
	// the current access token first: that call only reads, it neither
	// rotates credentials nor counts as an OAuth login.
	freshBuffer := p.freshLoginBuffer(loginCtx, acc, loginBuffer)
	st, err := p.loginAndSession(loginCtx, freshBuffer, dev, tcpProxy)
	if err != nil {
		log.Printf("pool: fresh login for account %d failed: %v", accountID, err)
		return WmpfSession{}, err
	}
	uin := st.Session.UIN
	_ = p.db.SetAccountUIN(ctx, acc.ID, uin)
	expiresAt := sessionExpiresAt(st, p.cfg.SessionTTL)
	log.Printf("pool: fresh login for account %d ok (uin %d), session ttl %v, psk expires at %s",
		accountID, uin, time.Duration(expiresAt-time.Now().Unix())*time.Second,
		time.Unix(st.PSK.ExpiredAt, 0).Format("15:04:05"))
	blob := st.toBlob()
	if err = p.db.PutSession(ctx, accountID, &uin, blob, expiresAt, tcpProxy); err != nil {
		log.Printf("pool: put session for account %d failed: %v", accountID, err)
		return WmpfSession{}, err
	}
	return st, nil
}

// lockFor returns the per-(account, proxy) login lock. Entries are never
// removed, but the map is bounded by accounts × proxy variants (two entries
// per account at most), so unbounded growth is not a concern.
func (p *Pool) lockFor(key string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.locks[key]; l != nil {
		return l
	}
	l := &sync.Mutex{}
	p.locks[key] = l
	return l
}

func (p *Pool) loginAndSession(ctx context.Context, loginBuffer string, dev DeviceIdentity, tcpProxy string) (WmpfSession, error) {
	if loginBuffer == "" {
		return WmpfSession{}, fmt.Errorf("login_buffer is empty")
	}
	meta, err := parseLoginBuffer(loginBuffer)
	if err != nil {
		return WmpfSession{}, err
	}
	targets, err := getLonglinkTargets(ctx, p.cfg.LoginTimeout, p.cfg.DNSCacheTTL)
	if err != nil {
		return WmpfSession{}, fmt.Errorf("HTTPDNS LongLink failed: %w", err)
	}
	targets = orderLonglinkTargets(targets, 6)
	var last error
	for _, t := range targets {
		st, err := p.loginViaTarget(ctx, t, loginBuffer, meta, dev, tcpProxy)
		if err == nil {
			return st, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("no LongLink candidates")
	}
	return WmpfSession{}, fmt.Errorf("all LongLink candidates failed: %w", last)
}

func (p *Pool) loginViaTarget(ctx context.Context, t Target, loginBuffer string, meta loginMeta, dev DeviceIdentity, tcpProxy string) (WmpfSession, error) {
	mc, err := connectMmtls(ctx, t, p.cfg.LoginTimeout, tcpProxy, p.cfg.TCPProxyFallbackDirect)
	if err != nil {
		return WmpfSession{}, err
	}
	defer mc.close()

	// A stable per-account device identity reads as the same machine
	// re-authorizing; fall back to the historical random behavior when the
	// identity is unavailable.
	appDeviceID := dev.AppDeviceID
	if len(appDeviceID) == 0 {
		appDeviceID, err = randomAppDeviceID()
		if err != nil {
			return WmpfSession{}, err
		}
	}
	temp := &manualAuthTemp{}
	body, err := buildLoginBody(loginBuffer, meta.DeviceID, appDeviceID, temp)
	if err != nil {
		return WmpfSession{}, err
	}
	if err = mc.sendApp(cmdManualAuth, body); err != nil {
		return WmpfSession{}, err
	}
	resp, err := mc.recvApp()
	if err != nil {
		return WmpfSession{}, err
	}
	if resp.Cmd != cmdManualAuth {
		return WmpfSession{}, fmt.Errorf("%w: manualauth rejected: cmd=%d", ErrAuthRejected, resp.Cmd)
	}
	mar, err := parseLoginResponse(resp.Body, temp)
	if err != nil {
		return WmpfSession{}, fmt.Errorf("%w: manualauth response: %v", ErrAuthRejected, err)
	}
	appSess, err := extractSession(mar)
	if err != nil {
		return WmpfSession{}, fmt.Errorf("%w: manualauth session: %v", ErrAuthRejected, err)
	}
	appSess.DeviceID = meta.DeviceID
	appSess.HostAppID = meta.HostAppID
	psks, err := mc.extractPSKs()
	if err != nil {
		return WmpfSession{}, err
	}
	psk, ok := pickAccessPSK(psks)
	if !ok {
		return WmpfSession{}, fmt.Errorf("login finished but no access PSK was issued")
	}
	shortTargets := getShortlinkTargets(ctx, p.cfg.ShortlinkTimeout, p.cfg.DNSCacheTTL)
	return WmpfSession{
		Session:          appSess,
		PSK:              psk,
		ShortlinkTargets: shortTargets,
		CreatedAt:        time.Now(),
		TCPProxy:         tcpProxy,
		SessDevice:       dev.SessDevice,
	}, nil
}

func (p *Pool) sendEnvelope(ctx context.Context, st WmpfSession, envelope []byte) ([]byte, []byte, error) {
	if err := acquire(ctx, p.shortlinkSem); err != nil {
		return nil, nil, err
	}
	defer release(p.shortlinkSem)
	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.ShortlinkTimeout)
	defer cancel()
	fallback := p.cfg.TCPProxyFallbackDirect
	if st.TCPProxy != "" {
		fallback = false
	}
	return send0RTT(reqCtx, st.ShortlinkTargets, st.PSK, st.Session.RecvKey, envelope, p.cfg.ShortlinkTimeout, st.TCPProxy, fallback)
}

func acquire(ctx context.Context, sem chan struct{}) error {
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release(sem chan struct{}) {
	select {
	case <-sem:
	default:
	}
}

func effectiveProxy(req, def string) string {
	if req != "" {
		return req
	}
	return def
}

func sessionExpiresAt(st WmpfSession, ttl time.Duration) int64 {
	now := time.Now().Unix()
	exp := st.PSK.ExpiredAt
	ttlExp := now + int64(ttl.Seconds())
	if exp == 0 || exp > ttlExp {
		exp = ttlExp
	}
	return exp
}

func (st WmpfSession) toBlob() map[string]any {
	return map[string]any{
		"session": map[string]any{
			"send_key":    encBytes(st.Session.SendKey),
			"recv_key":    encBytes(st.Session.RecvKey),
			"f9":          encBytes(st.Session.F9),
			"uin":         st.Session.UIN,
			"ticket":      encBytes(st.Session.Ticket),
			"device_id":   encBytes(st.Session.DeviceID),
			"host_appid":  encBytes(st.Session.HostAppID),
			"sess_device": encBytes(st.SessDevice),
		},
		"psk_entry":         st.PSK,
		"shortlink_targets": targetsToAny(st.ShortlinkTargets),
		"tcp_proxy":         st.TCPProxy,
	}
}

func sessionFromBlob(blob map[string]any) (WmpfSession, error) {
	sm, ok := blob["session"].(map[string]any)
	if !ok {
		return WmpfSession{}, fmt.Errorf("session_blob missing session")
	}
	pm, ok := blob["psk_entry"].(map[string]any)
	if !ok {
		return WmpfSession{}, fmt.Errorf("session_blob missing psk_entry")
	}
	st := WmpfSession{
		Session: AppSession{
			SendKey:   decBytes(sm["send_key"]),
			RecvKey:   decBytes(sm["recv_key"]),
			F9:        decBytes(sm["f9"]),
			UIN:       int64FromAny(sm["uin"]),
			Ticket:    decBytes(sm["ticket"]),
			DeviceID:  decBytes(sm["device_id"]),
			HostAppID: decBytes(sm["host_appid"]),
		},
		// Sessions created before stable identities carry no sess_device;
		// st.sessDevice() falls back to the historical random behavior.
		SessDevice: decBytes(sm["sess_device"]),
		PSK: pskEntry{
			PSKType:      int(int64FromAny(pm["psk_type"])),
			PreSharedKey: stringAny(pm["pre_shared_key"]),
			TicketEntry:  stringAny(pm["ticket_entry"]),
			Lifetime:     int64FromAny(pm["lifetime"]),
			ExpiredAt:    int64FromAny(pm["expired_at"]),
		},
		ShortlinkTargets: targetsFromAny(blob["shortlink_targets"]),
		TCPProxy:         stringAny(blob["tcp_proxy"]),
		CreatedAt:        time.Now(),
	}
	if len(st.ShortlinkTargets) == 0 {
		st.ShortlinkTargets = []Target{{IP: "120.241.131.173", Port: 80}}
	}
	if len(st.Session.SendKey) == 0 || len(st.Session.RecvKey) == 0 || st.Session.UIN == 0 {
		return WmpfSession{}, fmt.Errorf("session_blob incomplete")
	}
	return st, nil
}

func encBytes(b []byte) map[string]any {
	if b == nil {
		b = []byte{}
	}
	return map[string]any{"__bytes__": hex.EncodeToString(b)}
}

func decBytes(v any) []byte {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["__bytes__"].(string); ok {
			b, _ := hex.DecodeString(s)
			return b
		}
	}
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	return nil
}

func targetsToAny(ts []Target) [][]any {
	out := make([][]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, []any{t.IP, t.Port})
	}
	return out
}

func targetsFromAny(v any) []Target {
	var out []Target
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	for _, it := range arr {
		pair, ok := it.([]any)
		if !ok || len(pair) < 2 {
			continue
		}
		out = append(out, Target{IP: stringAny(pair[0]), Port: int(int64FromAny(pair[1]))})
	}
	return out
}

func stringAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func int64FromAny(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	default:
		return 0
	}
}
