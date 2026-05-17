package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mrrowisp/wisp"
)

type PortEntry struct {
	Min int
	Max int
}

func (p *PortEntry) UnmarshalJSON(data []byte) error {
	var single int
	if err := json.Unmarshal(data, &single); err == nil {
		if single <= 0 || single > 65535 {
			return fmt.Errorf("invalid port %d", single)
		}
		p.Min = single
		p.Max = single
		return nil
	}
	var pair [2]int
	if err := json.Unmarshal(data, &pair); err != nil {
		return fmt.Errorf("port entry must be an integer or [min, max] pair: %w", err)
	}
	if pair[0] <= 0 || pair[1] > 65535 || pair[0] > pair[1] {
		return fmt.Errorf("invalid port range [%d, %d]", pair[0], pair[1])
	}
	p.Min = pair[0]
	p.Max = pair[1]
	return nil
}

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
		Hostnames []string    `json:"hostnames"`
		Ports     []PortEntry `json:"ports"`
	} `json:"blacklist"`
	Whitelist struct {
		Hostnames []string    `json:"hostnames"`
		Ports     []PortEntry `json:"ports"`
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
	AllowedOrigins          []string `json:"allowedOrigins"`
	WriteTimeoutSeconds     int      `json:"writeTimeoutSeconds"`
	FrameReadTimeoutSeconds int      `json:"frameReadTimeoutSeconds"`
	LogLevel                string   `json:"logLevel"`

	BanEnabled              bool `json:"banEnabled"`
	BanDurationSeconds      int  `json:"banDurationSeconds"`
	BanMaxStrikes           int  `json:"banMaxStrikes"`
	BanEscalationMultiplier int  `json:"banEscalationMultiplier"`
	MaxHandshakeFailures    int  `json:"maxHandshakeFailures"`

	MaxPacketRate            int `json:"maxPacketRate"`
	MaxConnectionLifetimeSec int `json:"maxConnectionLifetimeSeconds"`
	MaxStreamsPerConnection   int `json:"maxStreamsPerConnection"`
	MaxConnectionsPerIP       int `json:"maxConnectionsPerIP"`
	GlobalMaxConnections      int `json:"globalMaxConnections"`
	WriteQueueSize            int `json:"writeQueueSize"`
	MaxInboundBytesPerSecond  int `json:"maxInboundBytesPerSecond"`
}

const (
	defaultStreamLimitPerHost    = 512
	defaultStreamLimitTotal      = 16384
	defaultMaxConnectsPerSecond  = 20
	defaultConnectionsLimitPerIP = 120
	defaultHandshakeFailures     = 10
)

func defaultConfig() Config {
	return Config{
		Port:                       6001,
		AllowTCP:                   true,
		AllowUDP:                   true,
		AllowDirectIP:              false,
		AllowPrivateIPs:            false,
		AllowLoopbackIPs:           false,
		TcpBufferSize:              32768,
		BufferRemainingLength:      65536,
		TcpNoDelay:                 true,
		WebsocketTcpNoDelay:        true,
		StreamLimitPerHost:         defaultStreamLimitPerHost,
		StreamLimitTotal:           defaultStreamLimitTotal,
		WebsocketPermessageDeflate: false,
		EnableTwisp:                false,
		EnableV2:                   false,
		PasswordAuth:               false,
		PasswordAuthRequired:       false,
		PasswordUsers:              make(map[string]string),
		CertAuth:                   false,
		CertAuthRequired:           false,
		EnableStreamConfirm:        false,
		MaxConnectsPerSecond:       defaultMaxConnectsPerSecond,
		DnsTTLSeconds:              120,
		DnsMethod:                  "lookup",
		DnsResultOrder:             "verbatim",
		ConnectionWindowSeconds:    1,
		ConnectionsLimitPerIP:      defaultConnectionsLimitPerIP,
		ParseRealIP:                true,
		ParseRealIPFrom:            []string{"127.0.0.1"},
		WriteTimeoutSeconds:        15,
		FrameReadTimeoutSeconds:    30,
		LogLevel:                   "debug",
		NonWSResponse:              "not found",
		BanEnabled:                 true,
		BanDurationSeconds:         3600,
		BanMaxStrikes:              10,
		BanEscalationMultiplier:    0,
		MaxHandshakeFailures:       defaultHandshakeFailures,
		MaxPacketRate:              500,
		MaxConnectionLifetimeSec:   0,
		MaxStreamsPerConnection:    0,
		MaxConnectionsPerIP:        0,
		GlobalMaxConnections:       0,
		WriteQueueSize:             4096,
		MaxInboundBytesPerSecond:   0,
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

func portEntriesToRanges(entries []PortEntry) []wisp.PortRange {
	out := make([]wisp.PortRange, 0, len(entries))
	for _, e := range entries {
		out = append(out, wisp.PortRange{Min: e.Min, Max: e.Max})
	}
	return out
}

func createWispConfig(cfg Config) *wisp.Config {
	normalizeHostname := func(host string) string {
		host = strings.TrimSpace(strings.ToLower(host))
		host = strings.TrimSuffix(host, ".")
		return host
	}

	if cfg.TcpBufferSize <= 0 {
		cfg.TcpBufferSize = 32768
	}
	if cfg.BufferRemainingLength == 0 {
		cfg.BufferRemainingLength = 65536
	}
	if cfg.ConnectionWindowSeconds <= 0 {
		cfg.ConnectionWindowSeconds = 1
	}
	if cfg.BandwidthLimitKbps < 0 {
		cfg.BandwidthLimitKbps = 0
	}
	if cfg.ConnectionsLimitPerIP < 0 {
		cfg.ConnectionsLimitPerIP = 0
	}
	if cfg.MaxConnectsPerSecond < 0 {
		cfg.MaxConnectsPerSecond = 0
	}
	if cfg.MaxMessageSize < 0 {
		cfg.MaxMessageSize = 0
	}
	if cfg.WriteTimeoutSeconds < 0 {
		cfg.WriteTimeoutSeconds = 0
	}
	if cfg.FrameReadTimeoutSeconds < 0 {
		cfg.FrameReadTimeoutSeconds = 0
	}
	if cfg.MaxHandshakeFailures <= 0 {
		cfg.MaxHandshakeFailures = defaultHandshakeFailures
	}
	if cfg.MaxPacketRate <= 0 {
		cfg.MaxPacketRate = 500
	}
	if cfg.WriteQueueSize <= 0 {
		cfg.WriteQueueSize = 4096
	}
	if cfg.MaxConnectionLifetimeSec < 0 {
		cfg.MaxConnectionLifetimeSec = 0
	}
	if cfg.MaxStreamsPerConnection < 0 {
		cfg.MaxStreamsPerConnection = 0
	}
	if cfg.MaxConnectionsPerIP < 0 {
		cfg.MaxConnectionsPerIP = 0
	}
	if cfg.GlobalMaxConnections < 0 {
		cfg.GlobalMaxConnections = 0
	}
	if cfg.MaxInboundBytesPerSecond < 0 {
		cfg.MaxInboundBytesPerSecond = 0
	}
	if len(cfg.AllowedOrigins) > 0 {
		filtered := make([]string, 0, len(cfg.AllowedOrigins))
		for _, origin := range cfg.AllowedOrigins {
			origin = strings.TrimSpace(origin)
			if origin == "" {
				continue
			}
			filtered = append(filtered, origin)
		}
		cfg.AllowedOrigins = filtered
	}

	blacklistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Blacklist.Hostnames {
		normalized := normalizeHostname(host)
		if normalized == "" {
			continue
		}
		blacklistedHostnames[normalized] = struct{}{}
	}

	whitelistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Whitelist.Hostnames {
		normalized := normalizeHostname(host)
		if normalized == "" {
			continue
		}
		whitelistedHostnames[normalized] = struct{}{}
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
		normalized := strings.TrimSpace(ip)
		if normalized == "" {
			continue
		}
		if net.ParseIP(normalized) == nil {
			fmt.Printf("warning: invalid parse-real-ip-from value %q\n", ip)
			continue
		}
		parseReal[normalized] = struct{}{}
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
			Ports     []wisp.PortRange
		}{
			Hostnames: blacklistedHostnames,
			Ports:     portEntriesToRanges(cfg.Blacklist.Ports),
		},
		Whitelist: struct {
			Hostnames map[string]struct{}
			Ports     []wisp.PortRange
		}{
			Hostnames: whitelistedHostnames,
			Ports:     portEntriesToRanges(cfg.Whitelist.Ports),
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
		AllowedOrigins:             cfg.AllowedOrigins,
		WriteTimeout:               time.Duration(cfg.WriteTimeoutSeconds) * time.Second,
		FrameReadTimeout:           time.Duration(cfg.FrameReadTimeoutSeconds) * time.Second,
		LogLevel:                   cfg.LogLevel,
		BanEnabled:                 cfg.BanEnabled,
		BanDuration:                time.Duration(cfg.BanDurationSeconds) * time.Second,
		BanMaxStrikes:              cfg.BanMaxStrikes,
		BanEscalationMultiplier:    cfg.BanEscalationMultiplier,
		MaxHandshakeFailures:       cfg.MaxHandshakeFailures,
		MaxPacketRate:              cfg.MaxPacketRate,
		MaxConnectionLifetime:      time.Duration(cfg.MaxConnectionLifetimeSec) * time.Second,
		MaxStreamsPerConnection:    cfg.MaxStreamsPerConnection,
		MaxConnectionsPerIP:        cfg.MaxConnectionsPerIP,
		GlobalMaxConnections:       cfg.GlobalMaxConnections,
		WriteQueueSize:             cfg.WriteQueueSize,
		MaxInboundBytesPerSecond:   cfg.MaxInboundBytesPerSecond,
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
	if wispCfg.AllowedOrigins == nil {
		wispCfg.AllowedOrigins = []string{}
	}

	return wispCfg
}

func main() {
	fConfig := flag.String("config", "", "config to load (file or json string)")
	fPort := flag.Int("port", 0, "port to run on")
	fLogLevel := flag.String("log-level", "", "log level (debug, info, warn, error)")
	fAllowTCP := flag.Bool("allow-tcp", true, "allow TCP streams")
	fAllowUDP := flag.Bool("allow-udp", true, "allow UDP streams")
	fAllowDirectIP := flag.Bool("allow-direct-ip", false, "allow direct IP targets")
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
	fWriteTimeout := flag.Int("write-timeout", 0, "write timeout in seconds (0 = disabled)")
	fAllowedOrigins := flag.String("allowed-origins", "", "comma-separated list of allowed origins")
	fMaxPacketRate := flag.Int("max-packet-rate", 0, "max wisp packets/sec per connection (0=default)")
	fMaxConnLifetime := flag.Int("max-conn-lifetime", 0, "max connection lifetime in seconds (0=unlimited)")
	fMaxStreamsPerConn := flag.Int("max-streams-per-conn", 0, "max concurrent streams per connection (0=unlimited)")
	fMaxConnPerIP := flag.Int("max-conn-per-ip", 0, "hard connection cap per IP (0=unlimited)")
	fGlobalMaxConn := flag.Int("global-max-conn", 0, "global connection cap (0=unlimited)")
	fInboundBPS := flag.Int("inbound-bps", 0, "max inbound bytes/sec per connection (0=unlimited)")
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
	if *fAllowDirectIP != false {
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
	if *fWriteTimeout != 0 {
		cfg.WriteTimeoutSeconds = *fWriteTimeout
	}
	if *fMaxPacketRate != 0 {
		cfg.MaxPacketRate = *fMaxPacketRate
	}
	if *fMaxConnLifetime != 0 {
		cfg.MaxConnectionLifetimeSec = *fMaxConnLifetime
	}
	if *fMaxStreamsPerConn != 0 {
		cfg.MaxStreamsPerConnection = *fMaxStreamsPerConn
	}
	if *fMaxConnPerIP != 0 {
		cfg.MaxConnectionsPerIP = *fMaxConnPerIP
	}
	if *fGlobalMaxConn != 0 {
		cfg.GlobalMaxConnections = *fGlobalMaxConn
	}
	if *fInboundBPS != 0 {
		cfg.MaxInboundBytesPerSecond = *fInboundBPS
	}
	if *fAllowedOrigins != "" {
		cfg.AllowedOrigins = strings.Split(*fAllowedOrigins, ",")
	}

	wispConfig := createWispConfig(cfg)

	wispHandler := wisp.CreateWispHandler(wispConfig)

	if cfg.StaticDir != "" {
		http.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
		http.HandleFunc("/wisp", wispHandler)
	} else {
		http.HandleFunc("/", wispHandler)
	}
	fmt.Printf("Starting Mrrowisp on port %d. . .\n", cfg.Port)
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigch
		fmt.Printf("Shutting down (signal: %s)\n", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
			fmt.Printf("Shutdown error: %v\n", shutdownErr)
		}
	}()

	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("Failed to start Mrrowisp: %v", err)
	}
}
