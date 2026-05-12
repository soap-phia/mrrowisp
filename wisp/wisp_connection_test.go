package wisp

import "testing"

func TestConnectRateLimiterDefaultsToPacketLimit(t *testing.T) {
	limiter := newConnectRateLimiter(0)

	for i := 0; i < maxConnectsPerSecond; i++ {
		if !limiter.allow() {
			t.Fatalf("connect %d should be allowed", i+1)
		}
	}
	if limiter.allow() {
		t.Fatalf("connect %d should be throttled", maxConnectsPerSecond+1)
	}
}

func TestConnectRateLimiterUsesConfiguredLimit(t *testing.T) {
	limiter := newConnectRateLimiter(2)

	if !limiter.allow() || !limiter.allow() {
		t.Fatal("first two connects should be allowed")
	}
	if limiter.allow() {
		t.Fatal("third connect should be throttled")
	}
}
