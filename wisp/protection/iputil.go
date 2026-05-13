package protection

import (
	"net"
	"net/http"
	"strings"
)

type IPConfig struct {
	AllowDirectIP    bool
	AllowPrivateIPs  bool
	AllowLoopbackIPs bool
	ParseRealIP      bool
	ParseRealIPFrom  map[string]struct{}
}

func RemoteIPFromRequest(r *http.Request, cfg IPConfig) string {
	if r == nil {
		return ""
	}
	if cfg.ParseRealIP {
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
	if !isIPAllowed(host, allowed) {
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

func isIPAllowed(ip string, allowed map[string]struct{}) bool {
	if _, ok := allowed[ip]; ok {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for entry := range allowed {
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil && cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func IsAllowedTargetIP(ip net.IP, cfg IPConfig) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if isCarrierGradeNAT(ip) || isBenchmarkingIP(ip) {
		return false
	}
	if !cfg.AllowLoopbackIPs && ip.IsLoopback() {
		return false
	}
	if !cfg.AllowPrivateIPs && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return false
	}
	return true
}

func FirstAllowedIP(ips []net.IPAddr, cfg IPConfig) (string, bool) {
	for _, addr := range ips {
		if IsAllowedTargetIP(addr.IP, cfg) {
			return addr.IP.String(), true
		}
	}
	return "", false
}

func isCarrierGradeNAT(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return ipv4[0] == 100 && ipv4[1]&0xC0 == 0x40
}

func isBenchmarkingIP(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return ipv4[0] == 198 && (ipv4[1] == 18 || ipv4[1] == 19)
}

func NormalizeTargetHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func IsOwnIP(resolvedIP string) bool {
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
