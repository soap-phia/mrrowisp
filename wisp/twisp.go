//go:build !windows
// +build !windows

// requires unix features
package wisp

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
)

type twispStream struct {
	wispConn *wispConnection

	streamId uint32
	ptmx     *os.File
	cmd      *exec.Cmd
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
	args, err := splitShell(command)
	if err != nil || len(args) == 0 {
		wc.sendClosePacket(streamId, closeReasonInvalidInfo)
		return
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		wc.sendClosePacket(streamId, closeReasonNetworkError)
		return
	}

	ts := &twispStream{
		wispConn: wc,
		streamId: streamId,
		ptmx:     ptmx,
		cmd:      cmd,
	}
	ts.isOpen.Store(true)

	wc.twispStreams.add(streamId, ts)

	go ts.readPty()

	go func() {
		_ = cmd.Wait()
		ts.close(closeReasonVoluntary)
	}()
}

func (ts *twispStream) readPty() {
	const maxHeaderLen = 15
	bufPool := ts.wispConn.config.ReadBufPool.Get().(*[]byte)
	buf := *bufPool
	defer ts.wispConn.config.ReadBufPool.Put(bufPool)

	streamId := ts.streamId

	for {
		n, err := ts.ptmx.Read(buf[maxHeaderLen:])
		if n > 0 {
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

			frame := make([]byte, maxHeaderLen+n-frameStart)
			copy(frame, buf[frameStart:maxHeaderLen+n])
			ts.wispConn.queueWrite(frame)
		}
		if err != nil {
			if err != io.EOF {
				ts.close(closeReasonNetworkError)
			} else {
				ts.close(closeReasonVoluntary)
			}
			return
		}
	}
}

func (ts *twispStream) writePty(data []byte) error {
	_, err := ts.ptmx.Write(data)
	return err
}

func (ts *twispStream) resize(rows, cols uint16) {
	ws := struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}{Row: rows, Col: cols}

	syscall.Syscall(
		syscall.SYS_IOCTL,
		ts.ptmx.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
}

func (ts *twispStream) close(reason uint8) {
	if !ts.isOpen.CompareAndSwap(true, false) {
		return
	}

	ts.wispConn.twispStreams.remove(ts.streamId)

	ts.ptmx.Close()

	if ts.cmd.Process != nil {
		_ = ts.cmd.Process.Kill()
	}

	ts.wispConn.sendClosePacket(ts.streamId, reason)
}

func splitShell(s string) ([]string, error) {
	var args []string
	var current []byte
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			current = append(current, c)
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if c == ' ' && !inSingle && !inDouble {
			if len(current) > 0 {
				args = append(args, string(current))
				current = current[:0]
			}
			continue
		}
		current = append(current, c)
	}
	if len(current) > 0 {
		args = append(args, string(current))
	}
	if inSingle || inDouble {
		return nil, io.ErrUnexpectedEOF
	}
	return args, nil
}
