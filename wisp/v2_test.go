package wisp

import "testing"

func TestParseClientInfoRejectsTrailingGarbage(t *testing.T) {
	payload := []byte{wispMajorVersion, wispMinorVersion, extensionUDP}
	if _, err := parseClientInfo(payload); err == nil {
		t.Fatal("expected trailing extension bytes to be rejected")
	}
}

func TestParseClientInfoAcceptsPasswordAuth(t *testing.T) {
	payload := []byte{
		wispMajorVersion, wispMinorVersion,
		extensionPasswordAuth, 8, 0, 0, 0,
		4, 'u', 's', 'e', 'r', 'p', 'a', 's',
	}

	exts, err := parseClientInfo(payload)
	if err != nil {
		t.Fatalf("parseClientInfo returned error: %v", err)
	}
	if exts.passwordUsername != "user" || exts.passwordPassword != "pas" {
		t.Fatalf("unexpected credentials: %#v", exts)
	}
}
