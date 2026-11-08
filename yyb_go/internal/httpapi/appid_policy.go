package httpapi

import (
	"fmt"
	"os"
	"strings"
)

// builtinDeniedAppIDs are AppIDs of website applications (the open-platform
// kind behind qrconnect logins), not mini programs. A wx.login code request
// for one of them reaches the upstream, comes back without a code, and the
// account's OAuth layer is refused within seconds (documented by
// YYB-Go-Enhanced: docs/website-appid-getcode-20261103.md — two healthy
// accounts lost authorization right after one such request).
//
// YYB_CODE_ALLOW_APPIDS lifts a refusal for operators who know better;
// YYB_CODE_DENY_APPIDS adds more.
var builtinDeniedAppIDs = map[string]string{
	"wx5cd60c5d4817a188": "腾讯电脑管家网站应用",
	"wx2f5d8f9715c59d10": "京东网页登录护照",
}

// appIDPolicy decides which AppIDs a wxapp call may carry before anything is
// sent upstream. It is traffic policy only: a refusal never changes account
// status, clears credentials or touches the database.
type appIDPolicy struct {
	denied map[string]string // lower-case AppID → reason shown to the caller
}

func newAppIDPolicy() *appIDPolicy {
	p := &appIDPolicy{denied: map[string]string{}}
	for id, label := range builtinDeniedAppIDs {
		p.denied[id] = fmt.Sprintf("%s 是网站应用而不是小程序，用它取码会让账号授权在数秒内失效；确需使用请在服务端设置 YYB_CODE_ALLOW_APPIDS 放行", label)
	}
	for _, id := range envAppIDList("YYB_CODE_DENY_APPIDS") {
		if _, builtin := p.denied[id]; !builtin {
			p.denied[id] = "已在服务端 YYB_CODE_DENY_APPIDS 中禁用"
		}
	}
	for _, id := range envAppIDList("YYB_CODE_ALLOW_APPIDS") {
		delete(p.denied, id)
	}
	return p
}

// check returns the refusal reason for the AppID, or "" when it may pass.
func (p *appIDPolicy) check(appID string) string {
	if p == nil {
		return ""
	}
	return p.denied[strings.ToLower(strings.TrimSpace(appID))]
}

func envAppIDList(name string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(os.Getenv(name), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if id := strings.ToLower(strings.TrimSpace(part)); id != "" {
			out = append(out, id)
		}
	}
	return out
}
