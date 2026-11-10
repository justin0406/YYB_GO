package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

// Offline notification: when an account's authorization is definitively
// rejected (42007 and friends, i.e. the refresh chain says "re-scan"), push
// once per authorization instead of letting the operator discover it hours
// later. De-duplication keys on (account, authorization timestamp): a re-scan
// produces a new timestamp and may notify again.
//
// Delivery is asynchronous with its own timeout and never blocks or fails the
// caller; errors are only logged, with credential material redacted.

const (
	notifyChannelServerChan = "serverchan"
	notifyChannelPushPlus   = "pushplus"
	notifyChannelWeCom      = "wecom"
	notifyTimeout           = 20 * time.Second
)

type notifier struct {
	channel string
	token   string
	topic   string

	mu   sync.Mutex
	sent map[string]time.Time // dedupe key → when it was sent
	wg   sync.WaitGroup
}

func newNotifier(channel, token, topic string) *notifier {
	channel = strings.ToLower(strings.TrimSpace(channel))
	if token == "" {
		channel = ""
	}
	return &notifier{channel: channel, token: token, topic: topic, sent: map[string]time.Time{}}
}

func (n *notifier) enabled() bool { return n != nil && n.channel != "" }

// claim reports whether this (account, authorization) pair still needs a
// notification, recording it as sent when so.
func (n *notifier) claim(accountID int64, authorizationAt int64) bool {
	if !n.enabled() {
		return false
	}
	key := fmt.Sprintf("%d:%d", accountID, authorizationAt)
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.sent[key]; ok {
		return false
	}
	n.sent[key] = time.Now()
	return true
}

// notifyAccountExpired pushes one notification about a dead authorization.
func (n *notifier) notifyAccountExpired(acc *store.WechatAccount, detail string) {
	if !n.enabled() || acc == nil {
		return
	}
	authorizationAt := int64(0)
	if acc.Credentials != nil {
		authorizationAt = protocol.CredentialsFromMap(acc.Credentials).RefreshedAt
	}
	if !n.claim(acc.ID, authorizationAt) {
		return
	}
	name := deref(acc.Nickname)
	if name == "" {
		name = acc.OpenID
	}
	title := "YYB 账号需要重新扫码"
	body := fmt.Sprintf("账号 %s（openid %s）的授权已被微信拒绝，需要重新扫码。\n%s",
		name, acc.OpenID, detail)
	n.send(title, body)
}

func (n *notifier) send(title, body string) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancel()
		if err := n.deliver(ctx, title, body); err != nil {
			log.Printf("notify: %s delivery failed: %v", n.channel, err)
		} else {
			log.Printf("notify: %s delivered", n.channel)
		}
	}()
}

// wait blocks until in-flight notifications finish (bounded by Close).
func (n *notifier) wait() {
	if n == nil {
		return
	}
	n.wg.Wait()
}

func (n *notifier) deliver(ctx context.Context, title, body string) error {
	var req *http.Request
	var err error
	switch n.channel {
	case notifyChannelServerChan:
		// Supports both the classic sctapi.ftqq.com/<key>.send endpoint and
		// the newer sctp<key>.push.ft07.com/send form; the token may also be
		// the full URL for self-hosted forks.
		endpoint := n.token
		if !strings.HasPrefix(endpoint, "http") {
			if strings.HasPrefix(endpoint, "sctp") {
				endpoint = "https://" + endpoint + ".push.ft07.com/send"
			} else {
				endpoint = "https://sctapi.ftqq.com/" + endpoint + ".send"
			}
		}
		form := url.Values{"title": {title}, "desp": {body}}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case notifyChannelPushPlus:
		payload, _ := json.Marshal(map[string]string{
			"token": n.token, "title": title, "content": body, "template": "txt",
		})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost,
			"https://www.pushplus.plus/send", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	case notifyChannelWeCom:
		payload, _ := json.Marshal(map[string]any{
			"msgtype": "text", "text": map[string]string{"content": title + "\n" + body},
		})
		endpoint := n.token
		if !strings.HasPrefix(endpoint, "http") {
			endpoint = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + endpoint
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	default:
		return fmt.Errorf("unsupported notification channel %q", n.channel)
	}
	resp, err := (&http.Client{Timeout: notifyTimeout}).Do(req)
	if err != nil {
		// url.Error embeds the request URL, which may carry the token.
		if ue, ok := err.(*url.Error); ok && ue.Err != nil {
			return ue.Err
		}
		return fmt.Errorf("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
