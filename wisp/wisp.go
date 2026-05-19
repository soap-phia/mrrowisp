package wisp

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mrrowisp/wisp/protection"

	"github.com/lxzan/gws"
)

const (
	defaultStreamLimitPerHost    = 512
	defaultStreamLimitTotal      = 16384
	defaultMaxConnectsPerSecond  = 20
	defaultConnectionsLimitPerIP = 120
	defaultHandshakeFailures     = 10
)

func (cfg *Config) InitResolver() {
	cfg.DNSCache = NewDNSCache(
		DNSCacheConfig{
			Servers:     cfg.DnsServers,
			Method:      cfg.DnsMethod,
			ResultOrder: cfg.DnsResultOrder,
		})
	cfg.Logger = newLogger(cfg.LogLevel)
}

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = &sync.Pool{
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

func (cfg *Config) requiresV2() bool {
	if cfg == nil {
		return false
	}
	return cfg.PasswordAuthRequired || cfg.EnableTwisp
}
