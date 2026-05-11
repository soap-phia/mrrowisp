package wisp

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type dnsEntry struct {
	ips       []net.IPAddr
	expiresAt time.Time
	err       error
}

type DNSCacheConfig struct {
	Servers     []string
	TTLSeconds  int
	Method      string
	ResultOrder string
}

type DNSCache struct {
	servers     []string
	resolver    *net.Resolver
	ttl         time.Duration
	resultOrder string

	mu    sync.RWMutex
	cache map[string]dnsEntry
}

func NewDNSCache(cfg DNSCacheConfig) *DNSCache {
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	cache := &DNSCache{
		servers:     cfg.Servers,
		ttl:         ttl,
		resultOrder: cfg.ResultOrder,
		cache:       make(map[string]dnsEntry),
	}
	cache.initResolver(cfg.Method)
	return cache
}

func (d *DNSCache) initResolver(method string) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "resolve" && len(d.servers) > 0 {
		d.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: 5 * time.Second,
				}
				return dialer.DialContext(ctx, "udp", d.servers[0])
			},
		}
		return
	}
	d.resolver = net.DefaultResolver
}

func (d *DNSCache) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	now := time.Now()

	d.mu.RLock()
	entry, ok := d.cache[host]
	d.mu.RUnlock()

	if ok && now.Before(entry.expiresAt) {
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.ips, nil
	}

	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err == nil {
		ips = reorderIPs(ips, d.resultOrder)
	}

	d.mu.Lock()
	d.cache[host] = dnsEntry{
		ips:       ips,
		expiresAt: now.Add(d.ttl),
		err:       err,
	}
	d.mu.Unlock()

	if err != nil {
		return nil, err
	}

	return ips, nil
}

func reorderIPs(ips []net.IPAddr, order string) []net.IPAddr {
	if len(ips) <= 1 {
		return ips
	}
	order = strings.ToLower(strings.TrimSpace(order))
	if order == "verbatim" || order == "" {
		return ips
	}

	var v4 []net.IPAddr
	var v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	if order == "ipv4first" {
		return append(v4, v6...)
	}
	if order == "ipv6first" {
		return append(v6, v4...)
	}

	return ips
}
