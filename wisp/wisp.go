package wisp

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/lxzan/gws"
)

type Config struct {
	DisableUDP bool

	TcpBufferSize         int
	BufferRemainingLength uint32
	TcpNoDelay            bool
	WebsocketTcpNoDelay   bool

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

	DnsServers []string

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

	DNSCache    *DNSCache
	ReadBufPool sync.Pool
	Dialer      net.Dialer
}

func DefaultConfig() *Config {
	return &Config{
		DisableUDP:            false,
		TcpBufferSize:         32768,
		BufferRemainingLength: 65536,
		TcpNoDelay:            true,
		WebsocketTcpNoDelay:   true,
		PasswordUsers:         make(map[string]string),
	}
}

func (c *Config) InitResolver() {
	c.DNSCache = NewDNSCache(c.DnsServers)
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

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
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
		}

		go wc.writeLoop()

		if useV2 {
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}
