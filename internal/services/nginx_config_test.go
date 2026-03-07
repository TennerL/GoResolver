package services

import (
	"GoResolver/internal/models"
	"strings"
	"testing"
)

func TestRenderMainServerBlockAddsIPv6HTTPListener(t *testing.T) {
	site := models.ServerConfiguration{
		ID:                    7,
		Server_Name:           "example.com",
		Server_Port:           80,
		SSL_Enabled:           0,
		Proxy_Pass_Port:       8080,
		Proxy_Connect_Timeout: 5,
		Proxy_Read_Timeout:    300,
		Proxy_Send_Timeout:    300,
		IP:                    "127.0.0.1",
	}

	block := renderMainServerBlock(site, []string{"example.com"}, defaultLetsEncryptConfigFile, models.DDoSPolicy{}, nil, false)

	if !strings.Contains(block, " listen 80;\n") {
		t.Fatalf("expected IPv4 HTTP listen directive, got:\n%s", block)
	}
	if !strings.Contains(block, " listen [::]:80;\n") {
		t.Fatalf("expected IPv6 HTTP listen directive, got:\n%s", block)
	}
}

func TestRenderRedirectServerBlockPreservesACMEChallengeHandling(t *testing.T) {
	site := models.ServerConfiguration{
		ID:           11,
		Server_Name:  "example.com",
		SSL_Enabled:  1,
		SSL_Redirect: 1,
	}

	block := renderRedirectServerBlock(site, []string{"example.com"}, defaultLetsEncryptConfigFile)

	if !strings.Contains(block, " include "+defaultLetsEncryptConfigFile+";\n") {
		t.Fatalf("expected letsencrypt include in redirect block, got:\n%s", block)
	}
	if !strings.Contains(block, " location / {\n  return 301 https://$host$request_uri;\n }\n") {
		t.Fatalf("expected redirect to be scoped to location / so ACME can override it, got:\n%s", block)
	}
}

func TestRenderDefaultDenyConfigAllowsACMEIncludeBefore403(t *testing.T) {
	site := renderDefaultDenyConfig("/tmp/default.crt", "/tmp/default.key", defaultLetsEncryptConfigFile)

	if !strings.Contains(site, "    include "+defaultLetsEncryptConfigFile+";\n") {
		t.Fatalf("expected letsencrypt include in default deny config, got:\n%s", site)
	}
	if !strings.Contains(site, "    location / {\n        default_type text/html;\n        return 403 ") {
		t.Fatalf("expected HTTP deny response inside location block, got:\n%s", site)
	}
}

func TestParseNginxErrorCodesSupportsGroupedValues(t *testing.T) {
	codes, err := parseNginxErrorCodes("504, 503 503")
	if err != nil {
		t.Fatalf("parseNginxErrorCodes() error = %v", err)
	}

	got := strings.Join(codes, " ")
	if got != "503 504" {
		t.Fatalf("parseNginxErrorCodes() = %q, want %q", got, "503 504")
	}
}

func TestResolveErrorPagesForSiteOverridesGroupedCodesPerStatus(t *testing.T) {
	site := models.ServerConfiguration{
		ID:       10,
		ServerID: "srv-1",
	}

	pages := []models.ServerErrorPages{
		{
			ID:           "default",
			Server_ID:    "srv-1",
			Site_ID:      "*",
			ErrorPage_ID: "file-default",
			Enabled:      true,
		},
		{
			ID:           "site",
			Server_ID:    "srv-1",
			Site_ID:      "10",
			ErrorPage_ID: "file-site",
			Enabled:      true,
		},
	}

	files := map[string]models.ServerErrorFiles{
		"file-default": {
			ID:           "file-default",
			Error_Code:   "503 504",
			ResponseType: "html",
			Filename:     "default.html",
			Path:         "/srv/errors",
		},
		"file-site": {
			ID:           "file-site",
			Error_Code:   "503",
			ResponseType: "html",
			Filename:     "site.html",
			Path:         "/srv/errors",
		},
	}

	resolved := resolveErrorPagesForSite(site, pages, files)
	if len(resolved) != 2 {
		t.Fatalf("resolveErrorPagesForSite() len = %d, want 2", len(resolved))
	}

	got := map[string]string{}
	for _, page := range resolved {
		got[strings.Join(page.Codes, " ")] = page.Filename
	}

	if got["503"] != "site.html" {
		t.Fatalf("expected site override for 503, got %q", got["503"])
	}
	if got["504"] != "default.html" {
		t.Fatalf("expected default page to remain for 504, got %q", got["504"])
	}
}
