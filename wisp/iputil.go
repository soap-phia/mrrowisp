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
