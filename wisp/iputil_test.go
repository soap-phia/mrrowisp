package wisp

import (
	"net"
	"testing"
)

func TestFirstAllowedIPBlocksRestrictedRanges(t *testing.T) {
	cfg := DefaultConfig()
	ips := []net.IPAddr{
		{IP: net.ParseIP("127.0.0.1")},
		{IP: net.ParseIP("169.254.169.254")},
		{IP: net.ParseIP("10.0.0.5")},
		{IP: net.ParseIP("fc00::1")},
		{IP: net.ParseIP("fd00::1")},
		{IP: net.ParseIP("203.0.113.10")},
	}

	got, ok := firstAllowedIP(ips, cfg)
	if !ok {
		t.Fatal("expected a public IP to be selected")
	}
	if got != "203.0.113.10" {
		t.Fatalf("expected public IP, got %q", got)
	}
}

func TestFirstAllowedIPRejectsOnlyRestrictedRanges(t *testing.T) {
	cfg := DefaultConfig()
	ips := []net.IPAddr{
		{IP: net.ParseIP("::1")},
		{IP: net.ParseIP("fe80::1")},
		{IP: net.ParseIP("224.0.0.1")},
		{IP: net.ParseIP("fc00::1")},
		{IP: net.ParseIP("fd00::1")},
	}

	if got, ok := firstAllowedIP(ips, cfg); ok {
		t.Fatalf("expected all IPs to be blocked, selected %q", got)
	}
}

func TestNormalizeTargetHostname(t *testing.T) {
	got := normalizeTargetHostname(" Example.COM. ")
	if got != "example.com" {
		t.Fatalf("normalizeTargetHostname returned %q", got)
	}
}
