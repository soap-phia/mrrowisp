package wisp

import "testing"

func TestNormalizeDNSServerAddsDefaultPort(t *testing.T) {
	tests := map[string]string{
		"1.1.1.1":              "1.1.1.1:53",
		"1.1.1.1:5353":         "1.1.1.1:5353",
		"2001:4860:4860::8888": "[2001:4860:4860::8888]:53",
		"dns.example.test":     "dns.example.test:53",
	}

	for input, want := range tests {
		if got := normalizeDNSServer(input); got != want {
			t.Fatalf("normalizeDNSServer(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFirstDNSServerSkipsBlankEntries(t *testing.T) {
	got := firstDNSServer([]string{" ", "8.8.8.8"})
	if got != "8.8.8.8:53" {
		t.Fatalf("firstDNSServer returned %q", got)
	}
}
