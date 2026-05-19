package protection

import "sync"

type StreamLimiter struct {
	mutex sync.Mutex
	pH    map[string]int
	total int
}

func NewStreamLimiter() *StreamLimiter {
	return &StreamLimiter{pH: make(map[string]int)}
}

func (s *StreamLimiter) Allow(host string, perHostLimit int, totalLimit int) bool {
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

func (s *StreamLimiter) Release(host string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.total > 0 {
		s.total--
	}
	if s.pH[host] > 0 {
		s.pH[host]--
	}
}
