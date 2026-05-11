package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"mrrowisp/wisp"
)

type Config struct {
	Port                  int    `json:"port"`
	AllowTCP              bool   `json:"allowTCP"`
	AllowUDP              bool   `json:"allowUDP"`
	AllowDirectIP         bool   `json:"allowDirectIP"`
	AllowPrivateIPs       bool   `json:"allowPrivateIPs"`
	AllowLoopbackIPs      bool   `json:"allowLoopbackIPs"`
	TcpBufferSize         int    `json:"tcpBufferSize"`
	BufferRemainingLength uint32 `json:"bufferRemainingLength"`
	TcpNoDelay            bool   `json:"tcpNoDelay"`
	WebsocketTcpNoDelay   bool   `json:"websocketTcpNoDelay"`
	StreamLimitPerHost    int    `json:"streamLimitPerHost"`
	StreamLimitTotal      int    `json:"streamLimitTotal"`

	Blacklist struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"blacklist"`
	Whitelist struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"whitelist"`

	Proxy                      string   `json:"proxy"`
	WebsocketPermessageDeflate bool     `json:"websocketPermessageDeflate"`
	DnsServers                 []string `json:"dnsServers"`
	DnsTTLSeconds              int      `json:"dnsTTLSeconds"`
	DnsMethod                  string   `json:"dnsMethod"`
	DnsResultOrder             string   `json:"dnsResultOrder"`

	EnableTwisp bool `json:"enableTwisp"`

	EnableV2             bool              `json:"enableV2"`
	Motd                 string            `json:"motd"`
	PasswordAuth         bool              `json:"passwordAuth"`
	PasswordAuthRequired bool              `json:"passwordAuthRequired"`
	PasswordUsers        map[string]string `json:"passwordUsers"`
	CertAuth             bool              `json:"certAuth"`
	CertAuthRequired     bool              `json:"certAuthRequired"`
	CertAuthPublicKeys   []string          `json:"certAuthPublicKeys"`
	EnableStreamConfirm  bool              `json:"enableStreamConfirm"`
	MaxConnectsPerSecond int               `json:"maxConnectsPerSecond"`

	BandwidthLimitKbps      int      `json:"bandwidthLimitKbps"`
	ConnectionsLimitPerIP   int      `json:"connectionsLimitPerIP"`
	ConnectionWindowSeconds int      `json:"connectionWindowSeconds"`
	ParseRealIP             bool     `json:"parseRealIP"`
	ParseRealIPFrom         []string `json:"parseRealIPFrom"`
	MaxMessageSize          int      `json:"maxMessageSize"`
	StaticDir               string   `json:"staticDir"`
	NonWSResponse           string   `json:"nonWSResponse"`
	LogLevel                string   `json:"logLevel"`
}

func defaultConfig() Config {
	return Config{
		Port:                       6001,
		AllowTCP:                   true,
		AllowUDP:                   true,
		AllowDirectIP:              true,
		AllowPrivateIPs:            false,
		AllowLoopbackIPs:           false,
		TcpBufferSize:              32768,
		BufferRemainingLength:      65536,
		TcpNoDelay:                 true,
		WebsocketTcpNoDelay:        true,
		WebsocketPermessageDeflate: false,
		EnableTwisp:                false,
		EnableV2:                   false,
		PasswordAuth:               false,
		PasswordAuthRequired:       false,
		PasswordUsers:              make(map[string]string),
		CertAuth:                   false,
		CertAuthRequired:           false,
		EnableStreamConfirm:        false,
		DnsTTLSeconds:              120,
		DnsMethod:                  "lookup",
		DnsResultOrder:             "verbatim",
		ConnectionWindowSeconds:    1,
		ParseRealIP:                true,
		ParseRealIPFrom:            []string{"127.0.0.1"},
		LogLevel:                   "info",
	}
}

func loadConfig(config string) (Config, error) {
	cfg := defaultConfig()

	trimConfig := strings.TrimSpace(config)
	if strings.HasPrefix(trimConfig, "{") {
		if err := json.Unmarshal([]byte(trimConfig), &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	file, err := os.Open(config)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func createWispConfig(cfg Config) *wisp.Config {
	blacklistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Blacklist.Hostnames {
		blacklistedHostnames[host] = struct{}{}
	}
	blacklistedPorts := make(map[string]struct{})
	for _, port := range cfg.Blacklist.Ports {
		blacklistedPorts[fmt.Sprintf("%d", port)] = struct{}{}
	}

	whitelistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Whitelist.Hostnames {
		whitelistedHostnames[host] = struct{}{}
	}
	whitelistedPorts := make(map[string]struct{})
	for _, port := range cfg.Whitelist.Ports {
		whitelistedPorts[fmt.Sprintf("%d", port)] = struct{}{}
	}

	var pubKeys []ed25519.PublicKey
	for _, hexKey := range cfg.CertAuthPublicKeys {
		hexKeyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			fmt.Printf("warning: invalid public key hex %q: %v\n", hexKey, err)
			continue
		}
		if len(hexKeyBytes) != ed25519.PublicKeySize {
			fmt.Printf("warning: public key %q has invalid length %d (expected %d)\n", hexKey, len(hexKeyBytes), ed25519.PublicKeySize)
			continue
		}
		pubKeys = append(pubKeys, ed25519.PublicKey(hexKeyBytes))
	}

	parseReal := make(map[string]struct{})
	for _, ip := range cfg.ParseRealIPFrom {
		parseReal[ip] = struct{}{}
	}

	wispCfg := &wisp.Config{
		AllowTCP:              cfg.AllowTCP,
		AllowUDP:              cfg.AllowUDP,
		AllowDirectIP:         cfg.AllowDirectIP,
		AllowPrivateIPs:       cfg.AllowPrivateIPs,
		AllowLoopbackIPs:      cfg.AllowLoopbackIPs,
		TcpBufferSize:         cfg.TcpBufferSize,
		BufferRemainingLength: cfg.BufferRemainingLength,
		TcpNoDelay:            cfg.TcpNoDelay,
		WebsocketTcpNoDelay:   cfg.WebsocketTcpNoDelay,
		StreamLimitPerHost:    cfg.StreamLimitPerHost,
		StreamLimitTotal:      cfg.StreamLimitTotal,
		Blacklist: struct {
			Hostnames map[string]struct{}
			Ports     map[string]struct{}
		}{
			Hostnames: blacklistedHostnames,
			Ports:     blacklistedPorts,
		},
		Whitelist: struct {
			Hostnames map[string]struct{}
			Ports     map[string]struct{}
		}{
			Hostnames: whitelistedHostnames,
			Ports:     whitelistedPorts,
		},
		Proxy:                      cfg.Proxy,
		WebsocketPermessageDeflate: cfg.WebsocketPermessageDeflate,
		DnsServers:                 cfg.DnsServers,
		DnsTTLSeconds:              cfg.DnsTTLSeconds,
		DnsMethod:                  cfg.DnsMethod,
		DnsResultOrder:             cfg.DnsResultOrder,
		EnableTwisp:                cfg.EnableTwisp,
		EnableV2:                   cfg.EnableV2,
		Motd:                       cfg.Motd,
		PasswordAuth:               cfg.PasswordAuth,
		PasswordAuthRequired:       cfg.PasswordAuthRequired,
		PasswordUsers:              cfg.PasswordUsers,
		CertAuth:                   cfg.CertAuth,
		CertAuthRequired:           cfg.CertAuthRequired,
		CertAuthPublicKeys:         pubKeys,
		EnableStreamConfirm:        cfg.EnableStreamConfirm,
		MaxConnectsPerSecond:       cfg.MaxConnectsPerSecond,
		BandwidthLimitKbps:         cfg.BandwidthLimitKbps,
		ConnectionsLimitPerIP:      cfg.ConnectionsLimitPerIP,
		ConnectionWindowSeconds:    cfg.ConnectionWindowSeconds,
		ParseRealIP:                cfg.ParseRealIP,
		ParseRealIPFrom:            parseReal,
		MaxMessageSize:             cfg.MaxMessageSize,
		NonWSResponse:              cfg.NonWSResponse,
		LogLevel:                   cfg.LogLevel,
	}

	if wispCfg.PasswordUsers == nil {
		wispCfg.PasswordUsers = make(map[string]string)
	}
	if wispCfg.StreamLimitPerHost < 0 {
		wispCfg.StreamLimitPerHost = 0
	}
	if wispCfg.StreamLimitTotal < 0 {
		wispCfg.StreamLimitTotal = 0
	}

	return wispCfg
}

func main() {
	fConfig := flag.String("config", "", "config to load (file or json string)")
	fPort := flag.Int("port", 0, "port to run on")
	fLogLevel := flag.String("log-level", "", "log level (debug, info, warn, error)")
	fAllowTCP := flag.Bool("allow-tcp", true, "allow TCP streams")
	fAllowUDP := flag.Bool("allow-udp", true, "allow UDP streams")
	fAllowDirectIP := flag.Bool("allow-direct-ip", true, "allow direct IP targets")
	fAllowPrivateIPs := flag.Bool("allow-private", false, "allow private IP targets")
	fAllowLoopbackIPs := flag.Bool("allow-loopback", false, "allow loopback IP targets")
	fStreamLimitPerHost := flag.Int("stream-limit-per-host", 0, "max streams per host (0 = unlimited)")
	fStreamLimitTotal := flag.Int("stream-limit-total", 0, "max total streams (0 = unlimited)")
	fBandwidthLimit := flag.Int("bandwidth", 0, "bandwidth limit per IP in KB/s")
	fConnectionsLimit := flag.Int("connections", 0, "connections per IP per window")
	fWindow := flag.Int("window", 1, "rate limit window in seconds")
	fDnsServers := flag.String("dns", "", "comma-separated DNS servers")
	fDnsMethod := flag.String("dns-method", "", "DNS method (lookup|resolve)")
	fDnsOrder := flag.String("dns-order", "", "DNS result order (ipv4first|ipv6first|verbatim)")
	fDnsTTL := flag.Int("dns-ttl", 0, "DNS cache TTL seconds")
	fStatic := flag.String("static", "", "static directory to serve")
	fNonWS := flag.String("non-ws-response", "", "response body for non-websocket requests")
	fParseRealIP := flag.Bool("parse-real-ip", true, "parse client IP from forwarded headers")
	fParseRealIPFrom := flag.String("parse-real-ip-from", "", "comma-separated list of IPs allowed to set real IP")
	fMaxMessageSize := flag.Int("max-message-size", 0, "max websocket message size in bytes")
	flag.Parse()

	var cfg Config
	var err error

	if *fConfig != "" {
		cfg, err = loadConfig(*fConfig)
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			return
		}
	} else {
		cfg = defaultConfig()
	}

	if *fPort != 0 {
		cfg.Port = *fPort
	}
	if *fLogLevel != "" {
		cfg.LogLevel = *fLogLevel
	}
	if *fAllowTCP != true {
		cfg.AllowTCP = *fAllowTCP
	}
	if *fAllowUDP != true {
		cfg.AllowUDP = *fAllowUDP
	}
	if *fAllowDirectIP != true {
		cfg.AllowDirectIP = *fAllowDirectIP
	}
	if *fAllowPrivateIPs != false {
		cfg.AllowPrivateIPs = *fAllowPrivateIPs
	}
	if *fAllowLoopbackIPs != false {
		cfg.AllowLoopbackIPs = *fAllowLoopbackIPs
	}
	if *fStreamLimitPerHost != 0 {
		cfg.StreamLimitPerHost = *fStreamLimitPerHost
	}
	if *fStreamLimitTotal != 0 {
		cfg.StreamLimitTotal = *fStreamLimitTotal
	}
	if *fBandwidthLimit != 0 {
		cfg.BandwidthLimitKbps = *fBandwidthLimit
	}
	if *fConnectionsLimit != 0 {
		cfg.ConnectionsLimitPerIP = *fConnectionsLimit
	}
	if *fWindow != 0 {
		cfg.ConnectionWindowSeconds = *fWindow
	}
	if *fDnsServers != "" {
		cfg.DnsServers = strings.Split(*fDnsServers, ",")
	}
	if *fDnsMethod != "" {
		cfg.DnsMethod = *fDnsMethod
	}
	if *fDnsOrder != "" {
		cfg.DnsResultOrder = *fDnsOrder
	}
	if *fDnsTTL != 0 {
		cfg.DnsTTLSeconds = *fDnsTTL
	}
	if *fStatic != "" {
		cfg.StaticDir = *fStatic
	}
	if *fNonWS != "" {
		cfg.NonWSResponse = *fNonWS
	}
	if *fParseRealIP != true {
		cfg.ParseRealIP = *fParseRealIP
	}
	if *fParseRealIPFrom != "" {
		cfg.ParseRealIPFrom = strings.Split(*fParseRealIPFrom, ",")
	}
	if *fMaxMessageSize != 0 {
		cfg.MaxMessageSize = *fMaxMessageSize
	}

	wispConfig := createWispConfig(cfg)

	wispHandler := wisp.CreateWispHandler(wispConfig)

	if cfg.StaticDir != "" {
		http.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
		http.HandleFunc("/wisp", wispHandler)
	} else {
		http.HandleFunc("/", wispHandler)
	}
	fmt.Printf("Starting Mrrowisp on port %d. . .", cfg.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil)
	if err != nil {
		fmt.Printf("Failed to start Mrrowisp: %v", err)
	}
}
