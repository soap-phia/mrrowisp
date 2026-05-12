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

func TestReadLoopRejectsOversizedPayloadBeforeReadingBody(t *testing.T) {
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

	header := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 2, 0, 1, 1, 2, 3, 4}
	if _, err := client.Write(header); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	select {
	case req := <-conn.writeCh:
		if len(req.data) != 4 || req.data[0] != 0x88 || req.data[2] != 1009/256 || req.data[3] != 1009%256 {
			t.Fatalf("expected message-too-big close frame, got %v", req.data)
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
