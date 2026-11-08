package protocol

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrPacingRefused indicates the account's request queue is full: the caller
// should retry after the hinted delay instead of queueing behind it.
var ErrPacingRefused = errors.New("account request pacing")

const (
	// DefaultPaceGap spaces upstream requests per account apart; it is roughly
	// one fifth of the burst rate observed to trip upstream risk control.
	// DefaultPaceMaxWait bounds how long a request may queue for its slot;
	// beyond it the request is refused instead of queued, so a caller's own
	// timeout is never eaten by the queue.
	DefaultPaceGap     = 3 * time.Second
	DefaultPaceMaxWait = 20 * time.Second
)

type pacingGate struct {
	now func() time.Time

	mu   sync.Mutex
	next map[int64]time.Time
}

func newPacingGate() *pacingGate {
	return &pacingGate{now: time.Now, next: map[int64]time.Time{}}
}

// reserve claims the account's next slot. It returns how long to wait before
// starting; ok=false means the wait already exceeds maxWait and the request is
// refused without moving the slot (refusals must not push the queue back).
func (g *pacingGate) reserve(accountID int64, minGap, maxWait time.Duration) (wait time.Duration, ok bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	slot := g.next[accountID]
	if slot.Before(now) {
		slot = now
	}
	wait = slot.Sub(now)
	if wait > maxWait {
		return wait, false
	}
	g.next[accountID] = slot.Add(minGap)
	return wait, true
}

// Pace waits for the account's slot before an upstream request, or refuses the
// request when the queue is full. It is traffic shaping only: a refusal never
// changes account state or credentials.
func (p *Pool) Pace(ctx context.Context, accountID int64) error {
	wait, ok := p.pace.reserve(accountID, DefaultPaceGap, DefaultPaceMaxWait)
	if !ok {
		return fmt.Errorf("%w: account %d 已有排队的请求，稍后重试（同账号请求间隔 %v）", ErrPacingRefused, accountID, DefaultPaceGap)
	}
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
