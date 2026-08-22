package handlers

import (
	"net/http/httptest"
	"testing"
)

func TestLoginClientIPUsesAddressAppendedByLocalProxy(t *testing.T) {
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "127.0.0.1:45678"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.8")
	if got := loginClientIP(req); got != "203.0.113.8" {
		t.Fatalf("loginClientIP() = %q, want %q", got, "203.0.113.8")
	}
}

func TestLoginClientIPIgnoresForwardingHeaderFromUntrustedPeer(t *testing.T) {
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "198.51.100.20:45678"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	if got := loginClientIP(req); got != "198.51.100.20" {
		t.Fatalf("loginClientIP() = %q, want direct peer", got)
	}
}
