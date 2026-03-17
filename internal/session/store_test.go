package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetFallsBackToFreshSessionOnInvalidCookie(t *testing.T) {
	t.Setenv("GORESOLVER_SESSION_SECRET", "test-session-secret")
	t.Setenv("GORESOLVER_SESSION_SECURE", "0")

	if err := Init(); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie("session", "invalid-cookie-value"))

	sess, err := Get(req, "session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if sess == nil {
		t.Fatal("Get() returned nil session")
	}
	if got, ok := sess.Values["authenticated"]; ok || got != nil {
		t.Fatalf("Get() should return a fresh session, got values=%v", sess.Values)
	}
}

func cookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}
