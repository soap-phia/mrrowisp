package wisp

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	prot "mrrowisp/wisp/protection"

	"golang.org/x/net/proxy"
)

type wispStream struct {
	wispConn *wispConnection

	streamId        uint32
	streamType      uint8
	conn            net.Conn
	bufferRemaining uint32
	hostname        string

	connReady     chan struct{}
	connReadyDone atomic.Bool

	isOpen atomic.Bool

	pendingMutex sync.Mutex
	pendingData  [][]byte
	pendingBytes int
}

const dnsLookupTimeout = 10 * time.Second

func (s *wispStream) handleConnect(streamType uint8, port string, hostname string) {
	defer s.signalConnReady()

	cfg := s.wispConn.config
	s.hostname = prot.NormalizeTargetHostname(hostname)
	if s.hostname == "" {
		s.close(closeReasonInvalidInfo)
		return
	}

	guard := newProtection(cfg)

	// Check hostname/port rules against the original (pre-DNS) hostname.
	if reason, ok := guard.allowHostPort(s.hostname, port); !ok {
		s.close(reason)
		return
	}

	resolvedHostname := s.hostname

	if ip := net.ParseIP(resolvedHostname); ip != nil {
		if reason, ok := guard.allowDirectIP(ip, s.wispConn.remoteIP, s.hostname); !ok {
			s.close(reason)
			return
		}
		resolvedHostname = ip.String()
	} else if cfg.Proxy != "" {
		resolvedHostname = s.hostname
	} else if cfg.DNSCache != nil {
		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		ips, err := cfg.DNSCache.LookupIPAddr(ctx, resolvedHostname)
		cancel()
		if err != nil {
			cfg.Logger.Warn("DNS lookup failed", "ip", s.wispConn.remoteIP, "hostname", resolvedHostname, "error", err)
			s.close(closeReasonUnreachable)
			return
		}
		if len(ips) == 0 {
			cfg.Logger.Warn("DNS returned no results", "ip", s.wispConn.remoteIP, "hostname", resolvedHostname)
			s.close(closeReasonUnreachable)
			return
		}
		selected, reason, ok := guard.selectAllowedIP(ips, s.wispConn.remoteIP, resolvedHostname)
		if !ok {
			s.close(reason)
			return
		}
		resolvedHostname = selected
	}

	s.streamType = streamType
	s.bufferRemaining = cfg.BufferRemainingLength

	destination := net.JoinHostPort(resolvedHostname, port)

	var err error
	switch streamType {
	case streamTypeTCP:
		select {
		case s.wispConn.dialSem <- struct{}{}:
		case <-s.wispConn.closeCh:
			return
		}
		if cfg.Proxy != "" {
			proxyURL := cfg.Proxy
			proxyURL = strings.Replace(proxyURL, "socks5h://", "socks5://", 1)
			proxyURL = strings.Replace(proxyURL, "socks4a://", "socks4://", 1)
			dialer, proxyErr := proxy.SOCKS5("tcp", stripScheme(proxyURL), nil, proxy.Direct)
			if proxyErr != nil {
				<-s.wispConn.dialSem
				cfg.Logger.Warn("proxy dialer creation failed", "ip", s.wispConn.remoteIP, "error", proxyErr)
				s.close(closeReasonNetworkError)
				return
			}
			s.conn, err = dialer.Dial("tcp", net.JoinHostPort(s.hostname, port))
		} else {
			s.conn, err = cfg.Dialer.Dial("tcp", destination)
		}
		<-s.wispConn.dialSem
	case streamTypeUDP:
		if cfg.Proxy != "" || !cfg.AllowUDP {
			s.close(closeReasonBlocked)
			return
		}
		s.conn, err = net.Dial("udp", destination)
	default:
		s.close(closeReasonInvalidInfo)
		return
	}

	if err != nil {
		cfg.Logger.Warn("stream connection failed", "ip", s.wispConn.remoteIP, "hostname", hostname, "port", port, "error", err)
		s.close(mapDialError(err))
		return
	}

	if streamType == streamTypeTCP {
		if tc, ok := s.conn.(*net.TCPConn); ok {
			tc.SetNoDelay(cfg.TcpNoDelay)
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}
	}

	if s.wispConn.streamConfirm && streamType == streamTypeTCP {
		s.wispConn.sendPacket(s.streamId, s.bufferRemaining)
	}

	s.pendingMutex.Lock()
	pending := s.pendingData
	s.pendingData = nil
	s.pendingBytes = 0
	s.pendingMutex.Unlock()

	for _, data := range pending {
		if !s.isOpen.Load() {
			return
		}
		if _, err := s.conn.Write(data); err != nil {
			s.close(closeReasonNetworkError)
			return
		}
	}

	// Signal ready only after all pending data has been written in order.
	s.signalConnReady()

	s.readFromConnection()
}

func stripScheme(url string) string {
	if idx := strings.Index(url, "://"); idx >= 0 {
		return url[idx+3:]
	}
	return url
}

func (s *wispStream) signalConnReady() {
	if s.connReadyDone.CompareAndSwap(false, true) {
		close(s.connReady)
	}
}

func (s *wispStream) readFromConnection() {
	const maxHeaderLen = 15
	bufp := s.wispConn.config.ReadBufPool.Get().(*[]byte)
	buf := *bufp
	defer s.wispConn.config.ReadBufPool.Put(bufp)
	guard := newProtection(s.wispConn.config)

	streamId := s.streamId

	for {
		n, err := s.conn.Read(buf[maxHeaderLen:])
		if n > 0 {
			if !guard.allowBandwidth(s.wispConn.remoteIP, n) {
				s.close(closeReasonThrottled)
				return
			}
			totalPayload := 5 + n
			var frameStart int

			if totalPayload <= 125 {
				frameStart = maxHeaderLen - 7
				buf[frameStart] = 0x82
				buf[frameStart+1] = byte(totalPayload)
			} else if totalPayload <= 65535 {
				frameStart = maxHeaderLen - 9
				buf[frameStart] = 0x82
				buf[frameStart+1] = 126
				buf[frameStart+2] = byte(totalPayload >> 8)
				buf[frameStart+3] = byte(totalPayload)
			} else {
				frameStart = 0
				buf[0] = 0x82
				buf[1] = 127
				buf[2] = byte(totalPayload >> 56)
				buf[3] = byte(totalPayload >> 48)
				buf[4] = byte(totalPayload >> 40)
				buf[5] = byte(totalPayload >> 32)
				buf[6] = byte(totalPayload >> 24)
				buf[7] = byte(totalPayload >> 16)
				buf[8] = byte(totalPayload >> 8)
				buf[9] = byte(totalPayload)
			}

			wispStart := maxHeaderLen - 5
			buf[wispStart] = packetTypeData
			buf[wispStart+1] = byte(streamId)
			buf[wispStart+2] = byte(streamId >> 8)
			buf[wispStart+3] = byte(streamId >> 16)
			buf[wispStart+4] = byte(streamId >> 24)

			frameBuf := s.wispConn.config.FramePool.Get().([]byte)
			frame := frameBuf[:maxHeaderLen+n-frameStart]
			copy(frame, buf[frameStart:maxHeaderLen+n])
			s.wispConn.queueWritePooled(frame)
		}
		if err != nil {
			if err == io.EOF {
				s.close(closeReasonVoluntary)
			} else {
				s.wispConn.config.Logger.Warn("stream read error", "ip", s.wispConn.remoteIP, "hostname", s.hostname, "error", err)
				s.close(closeReasonNetworkError)
			}
			return
		}
	}
}

func (s *wispStream) close(reason uint8) {
	if !s.isOpen.CompareAndSwap(true, false) {
		return
	}

	s.signalConnReady()

	s.wispConn.deleteWispStream(s.streamId)

	if s.conn != nil {
		s.conn.Close()
	}

	if s.wispConn.config.StreamLimiter != nil {
		s.wispConn.config.StreamLimiter.Release(s.hostname)
	}

	s.wispConn.sendClosePacket(s.streamId, reason)
}

func mapDialError(err error) uint8 {
	if err == nil {
		return closeReasonUnspecified
	}

	errStr := err.Error()

	if strings.Contains(errStr, "connection refused") {
		return closeReasonConnectionRefused
	}
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "no address") {
		return closeReasonUnreachable
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return closeReasonTimeout
	}
	if strings.Contains(errStr, "network is unreachable") || strings.Contains(errStr, "host is unreachable") {
		return closeReasonUnreachable
	}

	return closeReasonNetworkError
}
