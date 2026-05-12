package wisp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateWispHandlerBlocksV1WhenAuthRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableV2 = true
	cfg.PasswordAuth = true
	cfg.PasswordAuthRequired = true

	handler := CreateWispHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/wisp", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestCreateWispHandlerBlocksV1WhenTwispEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableV2 = true
	cfg.EnableTwisp = true

	handler := CreateWispHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/wisp", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}
