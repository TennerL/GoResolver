package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"testing"

	"GoResolver/internal/models"
)

func TestSubmittedEditableSettingsSkipsOmittedFields(t *testing.T) {
	items := []models.SettingItem{
		{Key: "dns.dnssec_enabled"},
		{Key: "dns.dnssec_private_key_pem"},
		{Key: "dns.dnssec_public_key_json", ReadOnly: true},
	}

	form := url.Values{
		"dns.dnssec_enabled": []string{"1"},
	}

	values := submittedEditableSettings(form, items)

	if got := values["dns.dnssec_enabled"]; got != "1" {
		t.Fatalf("expected dns.dnssec_enabled to be preserved, got %q", got)
	}
	if _, ok := values["dns.dnssec_private_key_pem"]; ok {
		t.Fatal("expected omitted dns.dnssec_private_key_pem to be left untouched")
	}
	if _, ok := values["dns.dnssec_public_key_json"]; ok {
		t.Fatal("expected read-only settings to be ignored")
	}
}

func TestSubmittedEditableSettingsKeepsIntentionalEmptyValue(t *testing.T) {
	items := []models.SettingItem{
		{Key: "acme.email"},
	}

	form := url.Values{
		"acme.email": []string{""},
	}

	values := submittedEditableSettings(form, items)

	value, ok := values["acme.email"]
	if !ok {
		t.Fatal("expected posted empty setting to be included")
	}
	if value != "" {
		t.Fatalf("expected empty string, got %q", value)
	}
}

func TestParseRequestFormSupportsMultipart(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("dns.dnssec_enabled", "1"); err != nil {
		t.Fatalf("WriteField() error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	req := httptest.NewRequest("POST", "/settings", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	if err := parseRequestForm(req); err != nil {
		t.Fatalf("parseRequestForm() error: %v", err)
	}

	if got := req.Form.Get("dns.dnssec_enabled"); got != "1" {
		t.Fatalf("expected multipart form value 1, got %q", got)
	}
}
