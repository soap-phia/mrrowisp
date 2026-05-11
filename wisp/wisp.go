package wisp

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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

	NonWSResponse string
	LogLevel      string

	Logger            Logger
	BandwidthLimiter  *BandwidthLimiter
	ConnectionLimiter *ConnectionLimiter
	StreamLimiter     *streamLimiter

	DNSCache    *DNSCache
	ReadBufPool sync.Pool
	Dialer      net.Dialer
}

func DefaultConfig() *Config {
	return &Config{
		AllowTCP:                true,
		AllowUDP:                true,
		AllowDirectIP:           true,
		AllowPrivateIPs:         false,
		AllowLoopbackIPs:        false,
		TcpBufferSize:           32768,
		BufferRemainingLength:   65536,
		TcpNoDelay:              true,
		WebsocketTcpNoDelay:     true,
		PasswordUsers:           make(map[string]string),
		DnsTTLSeconds:           120,
		DnsMethod:               "lookup",
		DnsResultOrder:          "verbatim",
		ConnectionWindowSeconds: 1,
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
		c.BandwidthLimiter = newBandwidthLimiter(c.BandwidthLimitKbps, time.Duration(c.ConnectionWindowSeconds)*time.Second)
	}
	if c.ConnectionsLimitPerIP > 0 {
		c.ConnectionLimiter = newConnectionLimiter(c.ConnectionsLimitPerIP, time.Duration(c.ConnectionWindowSeconds)*time.Second)
	}
	if c.StreamLimiter == nil {
		c.StreamLimiter = newStreamLimiter()
	}
	if c.ParseRealIPFrom == nil {
		c.ParseRealIPFrom = make(map[string]struct{})
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

	config.Dialer = net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: config.WebsocketPermessageDeflate,
		},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""
		remoteIP := remoteIPFromRequest(r, config)
		config.Logger.Info("incoming connection", "ip", remoteIP, "path", r.URL.Path, "origin", r.Header.Get("Origin"))
		if config.ConnectionLimiter != nil {
			if !config.ConnectionLimiter.Allow(remoteIP) {
				w.WriteHeader(http.StatusTooManyRequests)
				if config.NonWSResponse != "" {
					_, _ = w.Write([]byte(config.NonWSResponse))
				}
				return
			}
		}

		if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
			if config.NonWSResponse != "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(config.NonWSResponse))
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
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
