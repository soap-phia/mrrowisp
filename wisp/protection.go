package wisp

import (
	"net"
	"net/http"
	"strings"

	prot "mrrowisp/wisp/protection"
)

type guard struct {
	config *Config
}

type connectAction uint8

const (
	connectBlocked connectAction = iota
	connectStream
	connectTwisp
)

func newProtection(config *Config) *guard {
	return &guard{config: config}
}

func (p *guard) allowHTTP(r *http.Request, remoteIP string, useV2 bool) (int, string, bool) {
	cfg := p.config

	if cfg.BanList != nil && cfg.BanList.IsBanned(remoteIP) {
		cfg.Logger.Warn("banned ip rejected", "ip", remoteIP)
		return http.StatusForbidden, "", false
	}

	if cfg.ConnectionLimiter != nil {
		if !cfg.ConnectionLimiter.Allow(remoteIP) {
			if cfg.BanList != nil {
				if banned := cfg.BanList.Strike(remoteIP); banned {
					cfg.Logger.Warn("ip banned", "ip", remoteIP)
				}
			}
			return http.StatusTooManyRequests, cfg.NonWSResponse, false
		}
	}

	if !isWebsocketUpgrade(r) {
		if cfg.NonWSResponse != "" {
			return http.StatusOK, cfg.NonWSResponse, false
		}
		return http.StatusBadRequest, "", false
	}

	if !useV2 && cfg.requiresV2() {
		cfg.Logger.Warn("websocket v1 downgrade blocked", "ip", remoteIP)
		return http.StatusUnauthorized, cfg.NonWSResponse, false
	}

	return 0, "", true
}

func isWebsocketUpgrade(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

func (p *guard) allowConnect(c *wispConnection, streamType uint8, hostname string, port string) (connectAction, string, uint8) {
	cfg := p.config

	if len(hostname) > 2048 || strings.IndexByte(hostname, 0) >= 0 {
		return connectBlocked, "", closeReasonInvalidInfo
	}

	if !c.connectLimiter.allow() {
		cfg.Logger.Warn("connect rate limit exceeded", "ip", c.remoteIP)
		if cfg.BanList != nil {
			if banned := cfg.BanList.Strike(c.remoteIP); banned {
				cfg.Logger.Warn("ip banned", "ip", c.remoteIP)
				c.terminateNetwork()
			}
		}
		return connectBlocked, "", closeReasonThrottled
	}

	if streamType == streamTypeTerm {
		if !cfg.EnableTwisp || !c.twispAuthorized() {
			cfg.Logger.Warn("terminal stream blocked", "ip", c.remoteIP)
			return connectBlocked, "", closeReasonBlocked
		}
		return connectTwisp, "", 0
	}

	if streamType == streamTypeTCP && !cfg.AllowTCP {
		cfg.Logger.Warn("TCP streams blocked", "ip", c.remoteIP, "hostname", hostname)
		return connectBlocked, "", closeReasonBlocked
	}
	if streamType == streamTypeUDP && !cfg.AllowUDP {
		cfg.Logger.Warn("UDP streams blocked", "ip", c.remoteIP, "hostname", hostname)
		return connectBlocked, "", closeReasonBlocked
	}

	normalizedHostname := normalizeTargetHostname(hostname)
	if normalizedHostname == "" {
		return connectBlocked, "", closeReasonInvalidInfo
	}

	if isOwnIP(normalizedHostname) {
		cfg.Logger.Warn("self-targeting stream blocked", "ip", c.remoteIP, "hostname", hostname)
		return connectBlocked, "", closeReasonBlocked
	}

	if cfg.StreamLimiter != nil {
		if !cfg.StreamLimiter.Allow(normalizedHostname, cfg.StreamLimitPerHost, cfg.StreamLimitTotal) {
			cfg.Logger.Warn("stream limit reached", "ip", c.remoteIP, "hostname", hostname)
			return connectBlocked, "", closeReasonThrottled
		}
	}

	return connectStream, normalizedHostname, 0
}

func (p *guard) allowHostPort(hostname string, port string) (uint8, bool) {
	cfg := p.config

	if len(cfg.Whitelist.Hostnames) > 0 {
		if _, ok := cfg.Whitelist.Hostnames[hostname]; !ok {
			return closeReasonBlocked, false
		}
	} else if len(cfg.Blacklist.Hostnames) > 0 {
		if _, ok := cfg.Blacklist.Hostnames[hostname]; ok {
			return closeReasonBlocked, false
		}
	}

	if len(cfg.Whitelist.Ports) > 0 {
		if _, ok := cfg.Whitelist.Ports[port]; !ok {
			return closeReasonBlocked, false
		}
	} else if len(cfg.Blacklist.Ports) > 0 {
		if _, ok := cfg.Blacklist.Ports[port]; ok {
			return closeReasonBlocked, false
		}
	}

	return 0, true
}

func (p *guard) allowDirectIP(ip net.IP, remoteIP string, hostname string) (uint8, bool) {
	cfg := p.config

	if !cfg.AllowDirectIP {
		return closeReasonBlocked, false
	}
	if !prot.IsAllowedTargetIP(ip, prot.IPConfig{
		AllowDirectIP:    cfg.AllowDirectIP,
		AllowPrivateIPs:  cfg.AllowPrivateIPs,
		AllowLoopbackIPs: cfg.AllowLoopbackIPs,
	}) {
		return closeReasonBlocked, false
	}
	if isOwnIP(ip.String()) {
		cfg.Logger.Warn("self-targeting stream blocked", "ip", remoteIP, "hostname", hostname)
		return closeReasonBlocked, false
	}

	return 0, true
}

func (p *guard) selectAllowedIP(ips []net.IPAddr, remoteIP string, hostname string) (string, uint8, bool) {
	cfg := p.config

	selected, ok := prot.FirstAllowedIP(ips, prot.IPConfig{
		AllowDirectIP:    cfg.AllowDirectIP,
		AllowPrivateIPs:  cfg.AllowPrivateIPs,
		AllowLoopbackIPs: cfg.AllowLoopbackIPs,
	})
	if !ok {
		cfg.Logger.Warn("DNS returned only blocked IPs", "ip", remoteIP, "hostname", hostname)
		return "", closeReasonBlocked, false
	}
	if isOwnIP(selected) {
		cfg.Logger.Warn("self-targeting stream blocked", "ip", remoteIP, "hostname", hostname)
		return "", closeReasonBlocked, false
	}

	return selected, 0, true
}

func (p *guard) allowBandwidth(remoteIP string, size int) bool {
	if p.config.BandwidthLimiter == nil {
		return true
	}
	return p.config.BandwidthLimiter.Allow(remoteIP, uint64(size))
}

func (p *guard) allowMessageSize(size int) bool {
	max := p.config.MaxMessageSize
	return max <= 0 || size <= max
}
