package protection

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type BanList struct {
	mutex                sync.RWMutex
	bans                 map[string]time.Time
	banDur               time.Duration
	strikes              map[string]int
	maxStrikes           int
	escalationMultiplier int
}

func NewBanList(banDuration time.Duration, maxStrikes int) *BanList {
	return NewBanListEscalated(banDuration, maxStrikes, 0)
}

func NewBanListEscalated(banDuration time.Duration, maxStrikes int, escalation int) *BanList {
	if banDuration <= 0 {
		banDuration = time.Hour
	}
	if maxStrikes <= 0 {
		maxStrikes = 10
	}
	b := &BanList{
		bans:                 make(map[string]time.Time),
		strikes:              make(map[string]int),
		mutex:                sync.RWMutex{},
		banDur:               banDuration,
		maxStrikes:           maxStrikes,
		escalationMultiplier: escalation,
	}
	go b.cleanup()
	return b
}

func (b *BanList) Strike(ip string) (banned bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.strikes[ip]++
	if b.strikes[ip] >= b.maxStrikes {
		dur := b.banDur
		if b.escalationMultiplier > 0 {
			for i := 1; i < b.strikes[ip]/b.maxStrikes; i++ {
				dur *= time.Duration(b.escalationMultiplier)
			}
		}
		b.bans[ip] = time.Now().Add(dur)
		delete(b.strikes, ip)
		return true
	}
	return false
}

func (b *BanList) IsBanned(ip string) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	unbanAt, exists := b.bans[ip]
	if !exists {
		return false
	}
	return time.Now().Before(unbanAt)
}

func (b *BanList) cleanup() {
	for range time.Tick(5 * time.Minute) {
		b.mutex.Lock()
		now := time.Now()
		for ip, unbanAt := range b.bans {
			if now.After(unbanAt) {
				delete(b.bans, ip)
			}
		}
		b.mutex.Unlock()
	}
}

func (b *BanList) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if b.IsBanned(ip) {
			http.Error(w, "banned", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
