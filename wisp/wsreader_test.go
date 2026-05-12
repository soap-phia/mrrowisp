package wisp

import (
	"net"
	"testing"
	"time"
)

func TestReadLoopRejectsUnmaskedClientFrame(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	conn := &wispConnection{
		netConn: server,
		writeCh: make(chan writeReq, 1),
		config:  DefaultConfig(),
		closeCh: make(chan struct{}),
	}
	conn.config.InitResolver()

	done := make(chan struct{})
	go func() {
		conn.readLoop()
		close(done)
	}()

	if _, err := client.Write([]byte{0x82, 0x00}); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	select {
	case req := <-conn.writeCh:
		if len(req.data) != 4 || req.data[0] != 0x88 || req.data[3] != 1002%256 {
			t.Fatalf("expected protocol close frame, got %v", req.data)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for close frame")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readLoop did not exit")
	}
}

func TestMaxPayloadSizeDefaultsTo128KiB(t *testing.T) {
	conn := &wispConnection{config: DefaultConfig()}
	if got := conn.maxPayloadSize(); got != 128*1024 {
		t.Fatalf("maxPayloadSize returned %d", got)
	}
}

func TestMaxPayloadSizeUsesConfiguredLimit(t *testing.T) {
	conn := &wispConnection{config: DefaultConfig()}
	conn.config.MaxMessageSize = 64 * 1024
	if got := conn.maxPayloadSize(); got != 64*1024 {
		t.Fatalf("maxPayloadSize returned %d", got)
	}
}
