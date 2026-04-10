package bayed

import (
	"sync"
	"time"
)

// rateLimiter implements a simple token-bucket rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	tokens   int
	max      int
	interval time.Duration
	last     time.Time
}

func newRateLimiter(perSecond int) *rateLimiter {
	return &rateLimiter{
		tokens:   perSecond,
		max:      perSecond,
		interval: time.Second,
		last:     time.Now(),
	}
}

func (r *rateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.last)
	if elapsed >= r.interval {
		// Refill tokens for elapsed full seconds (cap at max).
		refill := int(elapsed / r.interval) * r.max
		r.tokens += refill
		if r.tokens > r.max {
			r.tokens = r.max
		}
		r.last = r.last.Add(time.Duration(int(elapsed/r.interval)) * r.interval)
	}

	if r.tokens > 0 {
		r.tokens--
		return true
	}
	return false
}
