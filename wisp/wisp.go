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

	NonWSResponse string
	LogLevel      string

	Logger            Logger
	BandwidthLimiter  *protection.BandwidthLimiter
	ConnectionLimiter *protection.ConnectionLimiter
	StreamLimiter     *protection.StreamLimiter
	FramePool         *sync.Pool

	DNSCache    *DNSCache
	ReadBufPool sync.Pool
	Dialer      net.Dialer

	BanEnabled    bool
	BanDuration   time.Duration
	BanMaxStrikes int
	BanList       *protection.BanList
	MaxHandshakeFailures int
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
	if c.BanEnabled {
		c.BanList = protection.NewBanList(c.BanDuration, c.BanMaxStrikes)
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

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
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

		wc := &wispConnection{
			netConn:        netConn,
			writeCh:        make(chan writeReq, 4096), // funny number
			config:         config,
			twispStreams:   newTwisp(),
			isV2:           useV2,
			connectLimiter: newConnectRateLimiter(config.MaxConnectsPerSecond),
			remoteIP:       remoteIP,
			dialSem:        make(chan struct{}, maxConcurrentDials),
			closeCh:        make(chan struct{}),
		}

		config.Logger.Info("connection established", "ip", remoteIP, "v2", useV2)
		go wc.writeLoop()

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
