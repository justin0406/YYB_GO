package protocol

import "errors"

// ErrStaleSession indicates a request reached the WeChat protocol layer but
// session-level cryptography failed (or the PSK was rejected), so the cached
// session keys can no longer be used. Re-login (ManualAuth) may recover; for
// rejected 0-RTT the server discarded the request, so a retry is safe.
var ErrStaleSession = errors.New("stale session keys")

// ErrAuthRejected indicates the server explicitly rejected the credentials:
// ManualAuth refused the login_buffer, or the YYB access API returned a
// non-zero business code. Refreshing the token / login_buffer may recover.
var ErrAuthRejected = errors.New("credentials rejected")

// ErrLoginBudgetExhausted indicates the account already used its sliding-window
// budget of OAuth-layer calls (fresh logins / forced credential refreshes), so
// the request was refused locally instead of provoking the upstream again.
var ErrLoginBudgetExhausted = errors.New("login budget exhausted")

// ErrCircuitOpen indicates the code circuit breaker refused the request
// locally: the (account, appID) combination or the whole account is cooling
// down after repeated empty codes.
var ErrCircuitOpen = errors.New("code circuit open")
