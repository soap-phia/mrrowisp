package wisp

import (
	"net"
	"strings"
)

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
