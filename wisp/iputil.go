package wisp

import (
	"net"
	"net/http"
	"strings"
)

func remoteIPFromRequest(r *http.Request, cfg *Config) string {
	if r == nil {
		return ""
	}
	if cfg != nil && cfg.ParseRealIP {
		if ip := parseForwardedIP(r, cfg.ParseRealIPFrom); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func parseForwardedIP(r *http.Request, allowed map[string]struct{}) string {
	if r == nil {
		return ""
	}
	if len(allowed) == 0 {
		return ""
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	if _, ok := allowed[host]; !ok {
		return ""
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	xrip := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if xrip != "" && net.ParseIP(xrip) != nil {
		return xrip
	}

	return ""
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

func normalizeTargetHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func isAllowedTargetIP(ip net.IP, cfg *Config) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if cfg != nil {
		if !cfg.AllowLoopbackIPs && ip.IsLoopback() {
			return false
		}
		if !cfg.AllowPrivateIPs && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return false
		}
	}
	return true
}

func firstAllowedIP(ips []net.IPAddr, cfg *Config) (string, bool) {
	for _, addr := range ips {
		if isAllowedTargetIP(addr.IP, cfg) {
			return addr.IP.String(), true
		}
	}
	return "", false
}

func isOwnIP(resolvedIP string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		ifaceAddrs, _ := iface.Addrs()
		for _, ifaceAddr := range ifaceAddrs {
			ip, _, _ := net.ParseCIDR(ifaceAddr.String())
			if ip != nil && ip.String() == resolvedIP {
				return true
			}
		}
	}
	return false
}
