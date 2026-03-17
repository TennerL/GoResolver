package services

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/miekg/dns"
	"strings"
	"testing"
)

func TestBuildDNSSECPublicKeyJSONIncludesDigests(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	raw := buildDNSSECPublicKeyJSON(publicKey, []string{"nihonsaba.net"})
	if raw == "" {
		t.Fatal("buildDNSSECPublicKeyJSON() returned empty JSON")
	}

	var payload struct {
		Domains []struct {
			Name       string `json:"name"`
			Extensions struct {
				SecDNS struct {
					DSData []struct {
						DigestType int    `json:"digestType"`
						Digest     string `json:"digest"`
					} `json:"dsData"`
				} `json:"secDns"`
			} `json:"extensions"`
		} `json:"domains"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("buildDNSSECPublicKeyJSON() invalid JSON: %v", err)
	}

	if len(payload.Domains) != 1 {
		t.Fatalf("expected 1 domain entry, got %d", len(payload.Domains))
	}
	if payload.Domains[0].Name != "nihonsaba.net" {
		t.Fatalf("expected domain nihonsaba.net, got %q", payload.Domains[0].Name)
	}

	digestTypes := map[int]string{}
	for _, entry := range payload.Domains[0].Extensions.SecDNS.DSData {
		if entry.Digest == "" {
			t.Fatal("expected non-empty DS digest")
		}
		digestTypes[entry.DigestType] = entry.Digest
	}

	if digestTypes[2] == "" {
		t.Fatal("expected SHA-256 DS digest entry")
	}
	if digestTypes[4] == "" {
		t.Fatal("expected SHA-384 DS digest entry")
	}
}

func TestBuildDNSSECPublicKeyJSONUsesZoneSpecificDigest(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

	raw := buildDNSSECPublicKeyJSON(publicKey, []string{"nihonsaba.net"})

	var payload struct {
		Domains []struct {
			Extensions struct {
				SecDNS struct {
					DSData []struct {
						DigestType int    `json:"digestType"`
						Digest     string `json:"digest"`
					} `json:"dsData"`
				} `json:"secDns"`
			} `json:"extensions"`
		} `json:"domains"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("buildDNSSECPublicKeyJSON() invalid JSON: %v", err)
	}
	if len(payload.Domains) != 1 {
		t.Fatalf("expected 1 domain entry, got %d", len(payload.Domains))
	}

	key := dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "nihonsaba.net.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: publicKey,
	}

	expected := key.ToDS(dns.SHA256)
	if expected == nil {
		t.Fatal("expected SHA-256 DS")
	}

	var actual string
	for _, entry := range payload.Domains[0].Extensions.SecDNS.DSData {
		if entry.DigestType == int(dns.SHA256) {
			actual = entry.Digest
			break
		}
	}
	if actual == "" {
		t.Fatal("expected SHA-256 digest entry in JSON")
	}
	if actual != expected.Digest {
		t.Fatalf("expected zone-specific digest %q, got %q", expected.Digest, actual)
	}
}

func TestPrepareSettingsValuesForSaveGeneratesDNSSECKeyWhenEnabled(t *testing.T) {
	current := map[string]string{
		"dns.dnssec_enabled":         "0",
		"dns.dnssec_private_key_pem": "",
	}
	updates := map[string]string{
		"dns.dnssec_enabled": "1",
	}

	prepared, err := prepareSettingsValuesForSave(current, updates)
	if err != nil {
		t.Fatalf("prepareSettingsValuesForSave() returned error: %v", err)
	}

	privateKeyPEM := prepared["dns.dnssec_private_key_pem"]
	if !strings.Contains(privateKeyPEM, "BEGIN PRIVATE KEY") {
		t.Fatalf("expected generated PKCS#8 private key, got %q", privateKeyPEM)
	}
	if _, err := deriveDNSSECPublicKey(privateKeyPEM); err != nil {
		t.Fatalf("generated private key should be parseable: %v", err)
	}
}

func TestPrepareSettingsValuesForSaveKeepsExistingDNSSECKey(t *testing.T) {
	existingKey, err := generateDNSSECPrivateKeyPEM()
	if err != nil {
		t.Fatalf("generateDNSSECPrivateKeyPEM() error: %v", err)
	}

	current := map[string]string{
		"dns.dnssec_enabled":         "1",
		"dns.dnssec_private_key_pem": existingKey,
	}
	updates := map[string]string{
		"dns.dnssec_enabled": "1",
	}

	prepared, err := prepareSettingsValuesForSave(current, updates)
	if err != nil {
		t.Fatalf("prepareSettingsValuesForSave() returned error: %v", err)
	}

	if _, ok := prepared["dns.dnssec_private_key_pem"]; ok {
		t.Fatal("expected existing key to be preserved without writing a replacement")
	}
}

func TestBuildDNSSECRegistrarValuesIncludesRegistrarFields(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))

	raw := buildDNSSECRegistrarValues(publicKey, []string{"nihonsaba.net"})

	if !strings.Contains(raw, "Zone: nihonsaba.net") {
		t.Fatalf("expected zone heading in registrar values, got %q", raw)
	}
	if !strings.Contains(raw, "Algorithm: 15") {
		t.Fatalf("expected algorithm in registrar values, got %q", raw)
	}
	if !strings.Contains(raw, "Digest Type 2 (SHA-256):") {
		t.Fatalf("expected SHA-256 digest in registrar values, got %q", raw)
	}
	if !strings.Contains(raw, "Digest Type 4 (SHA-384):") {
		t.Fatalf("expected SHA-384 digest in registrar values, got %q", raw)
	}
}
