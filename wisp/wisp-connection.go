package wisp

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	maxConnectsPerSecond = 20
	connectRateWindow    = time.Second
)

type connectRateLimiter struct {
	mutex       sync.Mutex
	windowStart time.Time
	count       int
	limit       int
}

func newConnectRateLimiter(limit int) *connectRateLimiter {
	if limit <= 0 {
		limit = maxConnectsPerSecond
	}
	return &connectRateLimiter{windowStart: time.Now(), limit: limit}
}

func (r *connectRateLimiter) allow() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	now := time.Now()
	if now.Sub(r.windowStart) >= connectRateWindow {
		r.windowStart = now
		r.count = 0
	}
	r.count++
	return r.count <= r.limit
}

type writeReq struct {
	data []byte
	pool bool
}

const maxConcurrentDials = 50
const maxPendingStreamBytes = 16 * 1024 * 1024

type wispConnection struct {
	netConn        net.Conn
	writeCh        chan writeReq
	streams        sync.Map
	cachedStreamId uint32
	cachedStream   unsafe.Pointer
	isClosed       atomic.Bool
	shutdownOnce   sync.Once
	config         *Config
	twispStreams   *twispRegistry
	connectLimiter *connectRateLimiter
	remoteIP       string

	isV2          bool
	handshakeDone chan struct{}
	streamConfirm bool
	v2Challenge   []byte
	authenticated atomic.Bool

	dialSem chan struct{}
	closeCh chan struct{}
}

// terminateNetwork closes the client socket and signals closeCh once so dial
// goroutines and other waiters unblock. Safe to call from any goroutine.
func (c *wispConnection) terminateNetwork() {
	c.shutdownOnce.Do(func() {
		c.isClosed.Store(true)
		close(c.closeCh)
		c.netConn.Close()
	})
}

func (c *wispConnection) close() {
	c.terminateNetwork()
}

func (c *wispConnection) writeLoop() {
	for req := range c.writeCh {
		bufs := net.Buffers{req.data}
		n := len(c.writeCh)
		for i := 0; i < n; i++ {
			r := <-c.writeCh
			bufs = append(bufs, r.data)
		}
		if _, err := bufs.WriteTo(c.netConn); err != nil {
			c.terminateNetwork()
			return
		}
	}
}

func (c *wispConnection) queueWrite(data []byte) {
	if c.isClosed.Load() {
		return
	}
	defer func() {
		recover()
	}()
	c.writeCh <- writeReq{data: data}
}

func (c *wispConnection) handlePacket(packetType uint8, streamId uint32, payload []byte) {
	switch packetType {
	case packetTypeInfo:
		if c.isV2 {
			c.handleInfo(streamId, payload)
		}
	case packetTypeConnect:
		c.handleConnectPacket(streamId, payload)
	case packetTypeClose:
		c.handleClosePacket(streamId, payload)
	case twispExtensionID:
		if c.config.EnableTwisp && c.twispStreams != nil && len(payload) >= 4 {
			rows := binary.LittleEndian.Uint16(payload[0:2])
			cols := binary.LittleEndian.Uint16(payload[2:4])
			ts := c.twispStreams.get(streamId)
			if ts != nil {
				ts.resize(rows, cols)
			}
		}
	}
}

func (c *wispConnection) handleConnectPacket(streamId uint32, payload []byte) {
	if len(payload) < 3 {
		return
	}
	guard := newProtection(c.config)
	streamType := payload[0]
	port := strconv.FormatUint(uint64(binary.LittleEndian.Uint16(payload[1:3])), 10)
	hostname := string(payload[3:])

	c.config.Logger.Debug("creating stream", "ip", c.remoteIP, "streamId", streamId, "hostname", hostname, "port", port, "type", streamType)
	action, normalizedHostname, reason := guard.allowConnect(c, streamType, hostname, port)
	if action == connectBlocked {
		c.sendClosePacket(streamId, reason)
		return
	}
	if action == connectTwisp {
		go handleTwisp(c, streamId, hostname)
		return
	}

	stream := &wispStream{
		wispConn:  c,
		streamId:  streamId,
		connReady: make(chan struct{}),
		hostname:  normalizedHostname,
	}
	stream.isOpen.Store(true)

	if _, loaded := c.streams.LoadOrStore(streamId, stream); loaded {
		if c.config.StreamLimiter != nil {
			c.config.StreamLimiter.Release(stream.hostname)
		}
		close(stream.connReady)
		return
	}

	go stream.handleConnect(streamType, port, normalizedHostname)
}

func (c *wispConnection) handleDataPacket(streamId uint32, payload []byte) {
	guard := newProtection(c.config)
	if !guard.allowBandwidth(c.remoteIP, len(payload)) {
		c.sendClosePacket(streamId, closeReasonThrottled)
		return
	}
	if !guard.allowMessageSize(len(payload)) {
		c.sendClosePacket(streamId, closeReasonInvalidInfo)
		return
	}
	var stream *wispStream
	if c.cachedStreamId == streamId {
		stream = (*wispStream)(atomic.LoadPointer(&c.cachedStream))
	}
	if stream == nil {
		v, ok := c.streams.Load(streamId)
		if !ok {
			if c.twispStreams != nil {
				ts := c.twispStreams.get(streamId)
				if ts != nil && ts.isOpen.Load() {
					if err := ts.writePty(payload); err != nil {
						ts.close(closeReasonNetworkError)
					}
					return
				}
			}
			c.sendClosePacket(streamId, closeReasonInvalidInfo)
			return
		}
		stream = v.(*wispStream)
		atomic.StorePointer(&c.cachedStream, unsafe.Pointer(stream))
		c.cachedStreamId = streamId
	}

	if !stream.isOpen.Load() {
		return
	}

	stream.pendingMutex.Lock()
	if !stream.connReadyDone.Load() {
		if stream.pendingBytes+len(payload) > maxPendingStreamBytes {
			stream.pendingMutex.Unlock()
			stream.close(closeReasonThrottled)
			return
		}
		dataCopy := make([]byte, len(payload))
		copy(dataCopy, payload)
		stream.pendingData = append(stream.pendingData, dataCopy)
		stream.pendingBytes += len(dataCopy)
		stream.pendingMutex.Unlock()
		return
	}
	stream.pendingMutex.Unlock()

	_, err := stream.conn.Write(payload)
	if err != nil {
		stream.close(closeReasonNetworkError)
		return
	}

	if stream.streamType == streamTypeTCP {
		stream.bufferRemaining--
		if stream.bufferRemaining == 0 {
			stream.bufferRemaining = c.config.BufferRemainingLength
			c.sendPacket(streamId, stream.bufferRemaining)
		}
	}
}

func (c *wispConnection) twispAuthorized() bool {
	return c.isV2 && c.authenticated.Load()
}

func (c *wispConnection) handleClosePacket(streamId uint32, payload []byte) {
	if len(payload) < 1 {
		return
	}

	v, ok := c.streams.Load(streamId)
	if !ok {
		if c.twispStreams != nil {
			ts := c.twispStreams.get(streamId)
			if ts != nil {
				go ts.close(closeReasonVoluntary)
			}
		}
		return
	}
	stream := v.(*wispStream)
	go stream.close(closeReasonVoluntary)
}

func (c *wispConnection) sendPacket(streamId uint32, bufferRemaining uint32) {
	if c.isClosed.Load() {
		return
	}
	buf := make([]byte, 11)
	buf[0] = 0x82
	buf[1] = 9
	buf[2] = packetTypeContinue
	buf[3] = byte(streamId)
	buf[4] = byte(streamId >> 8)
	buf[5] = byte(streamId >> 16)
	buf[6] = byte(streamId >> 24)
	binary.LittleEndian.PutUint32(buf[7:11], bufferRemaining)
	c.queueWrite(buf)
}

func (c *wispConnection) sendClosePacket(streamId uint32, reason uint8) {
	if c.isClosed.Load() {
		return
	}
	buf := make([]byte, 8)
	buf[0] = 0x82
	buf[1] = 6
	buf[2] = packetTypeClose
	buf[3] = byte(streamId)
	buf[4] = byte(streamId >> 8)
	buf[5] = byte(streamId >> 16)
	buf[6] = byte(streamId >> 24)
	buf[7] = reason
	c.queueWrite(buf)
}

func (c *wispConnection) writeRawPong(payload []byte) error {
	if c.isClosed.Load() {
		return nil
	}
	totalLen := len(payload)
	buf := make([]byte, 2+totalLen)
	buf[0] = 0x8A
	buf[1] = byte(totalLen)
	copy(buf[2:], payload)
	c.queueWrite(buf)
	return nil
}

func (c *wispConnection) deleteWispStream(streamId uint32) {
	c.streams.Delete(streamId)
	if c.cachedStreamId == streamId {
		atomic.StorePointer(&c.cachedStream, nil)
	}
}

func (c *wispConnection) deleteAllWispStreams() {
	c.terminateNetwork()
	c.config.Logger.Info("connection closed", "ip", c.remoteIP)
	c.streams.Range(func(key, value any) bool {
		stream := value.(*wispStream)
		stream.close(closeReasonUnspecified)
		return true
	})
	if c.twispStreams != nil {
		c.twispStreams.mu.Lock()
		streams := make([]*twispStream, 0, len(c.twispStreams.streams))
		for _, ts := range c.twispStreams.streams {
			streams = append(streams, ts)
		}
		c.twispStreams.mu.Unlock()
		for _, ts := range streams {
			ts.close(closeReasonUnspecified)
		}
	}
	defer func() { recover() }()
	close(c.writeCh)
}
