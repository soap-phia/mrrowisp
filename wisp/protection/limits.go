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

type PacketRateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	limit    int
	count    int
	resetAt  time.Time
}

func NewPacketRateLimiter(packetsPerSec int) *PacketRateLimiter {
	if packetsPerSec <= 0 {
		packetsPerSec = 500
	}
	return &PacketRateLimiter{
		interval: time.Second,
		limit:    packetsPerSec,
		resetAt:  time.Now().Add(time.Second),
	}
}

func (p *PacketRateLimiter) Allow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if now.After(p.resetAt) {
		p.count = 0
		p.resetAt = now.Add(p.interval)
	}
	p.count++
	return p.count <= p.limit
}

type ConnectionCounter struct {
	mu       sync.Mutex
	perIP    map[string]int
	global   int
}

func NewConnectionCounter() *ConnectionCounter {
	return &ConnectionCounter{perIP: make(map[string]int)}
}

func (c *ConnectionCounter) TryAdd(ip string, maxPerIP int, maxGlobal int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if maxGlobal > 0 && c.global >= maxGlobal {
		return false
	}
	if maxPerIP > 0 && c.perIP[ip] >= maxPerIP {
		return false
	}
	c.perIP[ip]++
	c.global++
	return true
}

func (c *ConnectionCounter) Remove(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.perIP[ip] > 0 {
		c.perIP[ip]--
		if c.perIP[ip] <= 0 {
			delete(c.perIP, ip)
		}
	}
	if c.global > 0 {
		c.global--
	}
}

type InboundRateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	limit    int
	count    int
	resetAt  time.Time
}

func NewInboundRateLimiter(bytesPerSec int) *InboundRateLimiter {
	if bytesPerSec <= 0 {
		bytesPerSec = 0
	}
	return &InboundRateLimiter{
		interval: time.Second,
		limit:    bytesPerSec,
		resetAt:  time.Now().Add(time.Second),
	}
}

func (r *InboundRateLimiter) Allow(n int) bool {
	if r == nil || r.limit <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.After(r.resetAt) {
		r.count = 0
		r.resetAt = now.Add(r.interval)
	}
	if r.count+n > r.limit {
		return false
	}
	r.count += n
	return true
}
