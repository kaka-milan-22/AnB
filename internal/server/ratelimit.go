package server

import (
	"sync"
	"time"
)

// rateLimiter is a per-identity token bucket. Capacity per identity is
// resolved by the limit() callback (policy-driven); refill rate is
// capacity / 60 tokens-per-second. Each decrypt-class op consumes one
// token.
//
// Lazy refill: no background goroutine. We compute elapsed time on
// every allow() call and credit tokens accordingly. Bucket entries
// live in memory until bob restarts — fine for a small operator set,
// and intentionally non-persistent (rate limits reset across reboots,
// matching how DOS-defense usually wants things to settle).
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   func(identity string) int
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

func newRateLimiter(limit func(identity string) int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
	}
}

// allow tries to consume one token for identity. Returns true if the
// caller may proceed, false if rate-limited.
func (r *rateLimiter) allow(identity string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cap := float64(r.limit(identity))
	refillPerSec := cap / 60.0
	now := time.Now()

	b, ok := r.buckets[identity]
	if !ok {
		// First request: start with a full bucket (capacity - 1, since this
		// call consumes one). Burst tolerance equals the configured cap.
		r.buckets[identity] = &bucket{tokens: cap - 1, lastRefill: now}
		return true
	}

	// Lazy refill: credit tokens for elapsed time, then clamp.
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * refillPerSec
	if b.tokens > cap {
		b.tokens = cap
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
