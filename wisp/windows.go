//go:build windows

package wisp

import (
	"sync"
	"sync/atomic"
)

type twispStream struct {
	wispConn *wispConnection
	streamId uint32
	isOpen   atomic.Bool
}

type twispRegistry struct {
	mu      sync.RWMutex
	streams map[uint32]*twispStream
}

func newTwisp() *twispRegistry {
	return &twispRegistry{
		streams: make(map[uint32]*twispStream),
	}
}

func (r *twispRegistry) add(id uint32, s *twispStream) {
	r.mu.Lock()
	r.streams[id] = s
	r.mu.Unlock()
}

func (r *twispRegistry) remove(id uint32) {
	r.mu.Lock()
	delete(r.streams, id)
	r.mu.Unlock()
}

func (r *twispRegistry) get(id uint32) *twispStream {
	r.mu.RLock()
	s := r.streams[id]
	r.mu.RUnlock()
	return s
}

func handleTwisp(wc *wispConnection, streamId uint32, command string) {
	wc.sendClosePacket(streamId, closeReasonBlocked)
}

func (ts *twispStream) writePty(data []byte) error {
	return nil
}

func (ts *twispStream) resize(rows, cols uint16) {}

func (ts *twispStream) close(reason uint8) {
	if !ts.isOpen.CompareAndSwap(true, false) {
		return
	}
	ts.wispConn.twispStreams.remove(ts.streamId)
	ts.wispConn.sendClosePacket(ts.streamId, reason)
}
