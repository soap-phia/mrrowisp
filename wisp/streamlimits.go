package wisp

import "sync"

type streamLimiter struct {
	mutex sync.Mutex
	pH    map[string]int // eleanor roosevelt
	total int
}

func newStreamLimiter() *streamLimiter {
	return &streamLimiter{pH: make(map[string]int)}
}

func (s *streamLimiter) allow(host string, perHostLimit int, totalLimit int) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if totalLimit > 0 && s.total >= totalLimit {
		return false
	}
	if perHostLimit > 0 && s.pH[host] >= perHostLimit {
		return false
	}
	s.total++
	s.pH[host]++
	return true
}

func (s *streamLimiter) release(host string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.total > 0 {
		s.total--
	}
	if s.pH[host] > 0 {
		s.pH[host]--
	}
}
