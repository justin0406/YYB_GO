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
