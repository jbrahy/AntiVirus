// internal/web/ratelimit/ratelimit.go
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter is a per-key sliding-window rate limiter: at most Max calls to
// Allow for a given key succeed within any Window-length trailing interval.
// It's in-memory and single-process, which matches this service's current
// single-instance deployment (see docs/carrier-compliance.md's deployment
// notes) — if this ever runs behind more than one instance, this needs to
// move to a shared store instead.
type Limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	attempts map[string][]time.Time
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{
		max:      max,
		window:   window,
		attempts: make(map[string][]time.Time),
	}
}

// Allow records an attempt for key and reports whether it's within the
// limit. Timestamps older than the window are pruned on every call, so
// memory use is bounded by the number of distinct keys seen inside the
// trailing window, not the total request count over the service's lifetime.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	kept := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}

	if len(kept) >= l.max {
		l.attempts[key] = kept
		return false
	}

	kept = append(kept, now)
	l.attempts[key] = kept
	return true
}

// Middleware returns a chi-compatible middleware that rejects requests over
// the limit with 429 Too Many Requests, keyed by ClientIP.
func Middleware(l *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(ClientIP(r)) {
				http.Error(w, "too many requests, try again later", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP returns the caller's address, preferring the leftmost
// X-Forwarded-For entry since this service sits behind an Apache reverse
// proxy (mirrors handlers.clientIP's logic — kept separate rather than
// exported cross-package since rate limiting is a generic HTTP concern, not
// specific to the consent audit trail that function was written for).
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
