package protection

import (
	"sync"
	"time"
)

type BandwidthLimiter struct {
	mu     sync.Mutex
	window time.Duration
	bytes  map[string]uint64
	start  time.Time
	limit  uint64
}

func NewBandwidthLimiter(kbps int, window time.Duration) *BandwidthLimiter {
	if window <= 0 {
		window = time.Second
	}
	limit := uint64(kbps) * 1024
	return &BandwidthLimiter{window: window, start: time.Now(), limit: limit, bytes: make(map[string]uint64)}
}

func (b *BandwidthLimiter) Allow(ip string, n uint64) bool {
	if b == nil || b.limit == 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if now.Sub(b.start) >= b.window {
		b.start = now
		b.bytes = make(map[string]uint64)
	}
	used := b.bytes[ip]
	if used+n > b.limit {
		return false
	}
	b.bytes[ip] = used + n
	return true
}

type ConnectionLimiter struct {
	mu     sync.Mutex
	window time.Duration
	start  time.Time
	counts map[string]int
	limit  int
}

func NewConnectionLimiter(limit int, window time.Duration) *ConnectionLimiter {
	if window <= 0 {
		window = time.Second
	}
	return &ConnectionLimiter{window: window, start: time.Now(), limit: limit, counts: make(map[string]int)}
}

func (c *ConnectionLimiter) Allow(ip string) bool {
	if c == nil || c.limit <= 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Sub(c.start) >= c.window {
		c.start = now
		c.counts = make(map[string]int)
	}
	c.counts[ip]++
	return c.counts[ip] <= c.limit
}
