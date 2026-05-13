package wisp

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mrrowisp/wisp/protection"

	"github.com/lxzan/gws"
)

type Config struct {
	AllowTCP         bool
	AllowUDP         bool
	AllowDirectIP    bool
	AllowPrivateIPs  bool
	AllowLoopbackIPs bool

	TcpBufferSize         int
	BufferRemainingLength uint32
	TcpNoDelay            bool
	WebsocketTcpNoDelay   bool

	StreamLimitPerHost int
	StreamLimitTotal   int

	Blacklist struct {
		Hostnames map[string]struct{}
		Ports     map[string]struct{}
	}
	Whitelist struct {
		Hostnames map[string]struct{}
		Ports     map[string]struct{}
	}

	Proxy                      string
	WebsocketPermessageDeflate bool

	DnsServers     []string
	DnsTTLSeconds  int
	DnsMethod      string
	DnsResultOrder string

	EnableTwisp bool

	EnableV2             bool
	Motd                 string
	PasswordAuth         bool
	PasswordAuthRequired bool
	PasswordUsers        map[string]string
	CertAuth             bool
	CertAuthRequired     bool
	CertAuthPublicKeys   []ed25519.PublicKey
	EnableStreamConfirm  bool
	MaxConnectsPerSecond int

	BandwidthLimitKbps      int
	ConnectionsLimitPerIP   int
	ConnectionWindowSeconds int
	ParseRealIP             bool
	ParseRealIPFrom         map[string]struct{}

	MaxMessageSize int
	AllowedOrigins []string
	WriteTimeout   time.Duration

	NonWSResponse string
	LogLevel      string

	Logger            Logger
	BandwidthLimiter  *protection.BandwidthLimiter
	ConnectionLimiter *protection.ConnectionLimiter
	ConnectionCounter *protection.ConnectionCounter
	StreamLimiter     *protection.StreamLimiter
	FramePool         *sync.Pool

	DNSCache    *DNSCache
	ReadBufPool sync.Pool
	Dialer      net.Dialer

	BanEnabled             bool
	BanDuration            time.Duration
	BanMaxStrikes          int
	BanEscalationMultiplier int
	BanList                *protection.BanList
	MaxHandshakeFailures   int

	MaxPacketRate           int
	MaxConnectionLifetime   time.Duration
	MaxStreamsPerConnection int
	MaxConnectionsPerIP     int
	GlobalMaxConnections    int
	WriteQueueSize          int
	MaxInboundBytesPerSecond int
}

const (
	defaultStreamLimitPerHost    = 512
	defaultStreamLimitTotal      = 16384
	defaultConnectionsLimitPerIP = 120
)

func DefaultConfig() *Config {
	return &Config{
		AllowTCP:                true,
		AllowUDP:                true,
		AllowDirectIP:           false,
		AllowPrivateIPs:         false,
		AllowLoopbackIPs:        false,
		TcpBufferSize:           32768,
		BufferRemainingLength:   65536,
		TcpNoDelay:              true,
		WebsocketTcpNoDelay:     true,
		StreamLimitPerHost:      defaultStreamLimitPerHost,
		StreamLimitTotal:        defaultStreamLimitTotal,
		MaxConnectsPerSecond:    maxConnectsPerSecond,
		PasswordUsers:           make(map[string]string),
		DnsTTLSeconds:           120,
		DnsMethod:               "lookup",
		DnsResultOrder:          "verbatim",
		ConnectionWindowSeconds: 1,
		ConnectionsLimitPerIP:   defaultConnectionsLimitPerIP,
		MaxHandshakeFailures:    10,
		BanEnabled:              true,
		BanDuration:             time.Hour,
		BanMaxStrikes:           10,
		BanEscalationMultiplier: 0,
		WriteTimeout:            15 * time.Second,
		MaxPacketRate:           500,
		MaxConnectionLifetime:   0,
		MaxStreamsPerConnection: 0,
		MaxConnectionsPerIP:     0,
		GlobalMaxConnections:    0,
		WriteQueueSize:          4096,
		MaxInboundBytesPerSecond: 0,
	}
}

func (c *Config) InitResolver() {
	c.DNSCache = NewDNSCache(
		DNSCacheConfig{
			Servers:     c.DnsServers,
			TTLSeconds:  c.DnsTTLSeconds,
			Method:      c.DnsMethod,
			ResultOrder: c.DnsResultOrder,
		})
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Logger == nil {
		c.Logger = newLogger(c.LogLevel)
	}
	if c.BandwidthLimitKbps > 0 {
		c.BandwidthLimiter = protection.NewBandwidthLimiter(c.BandwidthLimitKbps, time.Duration(c.ConnectionWindowSeconds)*time.Second)
	}
	if c.ConnectionsLimitPerIP > 0 {
		c.ConnectionLimiter = protection.NewConnectionLimiter(c.ConnectionsLimitPerIP, time.Duration(c.ConnectionWindowSeconds)*time.Second)
	}
	if c.StreamLimiter == nil {
		c.StreamLimiter = protection.NewStreamLimiter()
	}
	if c.ParseRealIPFrom == nil {
		c.ParseRealIPFrom = make(map[string]struct{})
	}
	if c.MaxConnectionsPerIP > 0 || c.GlobalMaxConnections > 0 {
		c.ConnectionCounter = protection.NewConnectionCounter()
	}
	if c.BanEnabled {
		c.BanList = protection.NewBanListEscalated(c.BanDuration, c.BanMaxStrikes, c.BanEscalationMultiplier)
	}
	if c.FramePool == nil {
		readBufSize := 15 + c.TcpBufferSize
		c.FramePool = &sync.Pool{
			New: func() any {
				buf := make([]byte, readBufSize)
				return buf
			},
		}
	}
	if c.WriteTimeout < 0 {
		c.WriteTimeout = 0
	}
}

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, readBufSize)
			return &buf
		},
	}
	if config.FramePool == nil {
		config.FramePool = &sync.Pool{
			New: func() any {
				buf := make([]byte, readBufSize)
				return buf
			},
		}
	}

	config.Dialer = net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: false,
		},
	})
	if config.WebsocketPermessageDeflate {
		config.Logger.Warn("websocket permessage-deflate disabled because raw frame handling does not support compressed payloads")
	}

	guard := newProtection(config)

	return func(w http.ResponseWriter, r *http.Request) {
		useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""
		remoteIP := protection.RemoteIPFromRequest(r, protection.IPConfig{
			AllowDirectIP:    config.AllowDirectIP,
			AllowPrivateIPs:  config.AllowPrivateIPs,
			AllowLoopbackIPs: config.AllowLoopbackIPs,
			ParseRealIP:      config.ParseRealIP,
			ParseRealIPFrom:  config.ParseRealIPFrom,
		})
		config.Logger.Info("incoming connection", "ip", remoteIP, "path", r.URL.Path, "origin", r.Header.Get("Origin"))
		if config.requiresV2() && !useV2 {
			config.Logger.Warn("v2 required but not negotiated", "ip", remoteIP)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if status, response, ok := guard.allowHTTP(r, remoteIP, useV2); !ok {
			w.WriteHeader(status)
			if response != "" {
				_, _ = w.Write([]byte(response))
			}
			return
		}
		if !originAllowed(r, config.AllowedOrigins) {
			config.Logger.Warn("origin blocked", "ip", remoteIP, "origin", r.Header.Get("Origin"))
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if config.ConnectionCounter != nil {
			if !config.ConnectionCounter.TryAdd(remoteIP, config.MaxConnectionsPerIP, config.GlobalMaxConnections) {
				config.Logger.Warn("connection cap reached", "ip", remoteIP)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
			if config.ConnectionCounter != nil {
				config.ConnectionCounter.Remove(remoteIP)
			}
			if config.NonWSResponse != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(config.NonWSResponse))
			}
			config.Logger.Debug("websocket upgrade failed", "error", err)
			return
		}

		netConn := wsConn.NetConn()

		if tc, ok := netConn.(*net.TCPConn); ok {
			if config.WebsocketTcpNoDelay {
				tc.SetNoDelay(true)
			}
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}

		writeQSize := config.WriteQueueSize
		if writeQSize <= 0 {
			writeQSize = 4096
		}

		wc := &wispConnection{
			netConn:        netConn,
			writeCh:        make(chan writeReq, writeQSize),
			config:         config,
			twispStreams:   newTwisp(),
			isV2:           useV2,
			connectLimiter: newConnectRateLimiter(config.MaxConnectsPerSecond),
			remoteIP:       remoteIP,
			dialSem:        make(chan struct{}, maxConcurrentDials),
			closeCh:        make(chan struct{}),
			createdAt:      time.Now(),
		}

		if config.MaxPacketRate > 0 {
			wc.packetLimiter = protection.NewPacketRateLimiter(config.MaxPacketRate)
		}
		if config.MaxInboundBytesPerSecond > 0 {
			wc.inboundLimiter = protection.NewInboundRateLimiter(config.MaxInboundBytesPerSecond)
		}

		config.Logger.Info("connection established", "ip", remoteIP, "v2", useV2)
		go wc.writeLoop()

		if config.MaxConnectionLifetime > 0 {
			go wc.lifetimeWatchdog()
		}

		if useV2 {
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}

func (c *Config) requiresV2() bool {
	if c == nil {
		return false
	}
	return c.PasswordAuthRequired || c.CertAuthRequired || c.EnableTwisp
}

func originAllowed(r *http.Request, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	for _, allowed := range allowedOrigins {
		if origin == strings.TrimSpace(allowed) {
			return true
		}
	}
	return false
}
