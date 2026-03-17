package services

import (
	"GoResolver/internal/models"
	"strings"
	"testing"
)

func TestNormalizeSystemNginxConfig(t *testing.T) {
	got := normalizeSystemNginxConfig(" server { listen 80; }\n")
	want := "server { listen 80; }\n"
	if got != want {
		t.Fatalf("normalizeSystemNginxConfig() = %q, want %q", got, want)
	}
}

func TestRenderSystemNginxConfigWithChallenge(t *testing.T) {
	content, err := renderSystemNginxConfig([]models.SystemNginxSite{
		{
			ID:           "site-a",
			ServerName:   "test.example.org",
			ListenPort:   443,
			SSL:          true,
			HTTP2:        true,
			Mode:         "proxy",
			EnableDDoS:   true,
			CertPath:     "/etc/ssl/test.crt",
			KeyPath:      "/etc/ssl/test.key",
			ProxyPassURL: "http://127.0.0.1:8888",
		},
	}, "", models.DDoSPolicy{
		Enabled:        true,
		Mode:           "challenge",
		RateLimit:      10,
		Burst:          20,
		ConnLimit:      50,
		ChallengeDelay: 5,
		CookieTTL:      3600,
	})
	if err != nil {
		t.Fatalf("renderSystemNginxConfig() error = %v", err)
	}
	wantSnippets := []string{
		"server_name test.example.org;",
		"proxy_pass http://127.0.0.1:8888;",
		"location = /__gr_challenge_",
		"Set-Cookie \"gr_challenge_",
		"limit_req zone=gr_",
	}
	for _, snippet := range wantSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("rendered content missing %q:\n%s", snippet, content)
		}
	}
}
