package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/miekg/dns"
	"log"
	"strings"
)

type SettingDefinition struct {
	Key     string
	Label   string
	Group   string
	Help    string
	Default string
	ReadOnly bool
}

type SettingsService struct{}

func NewSettingsService() *SettingsService {
	return &SettingsService{}
}

var settingsDefinitions = []SettingDefinition{
	{Key: "app.base_url", Label: "Base URL", Group: "App", Help: "Displayed in logs and links", Default: "http://localhost:8888"},
	{Key: "app.listen_addr", Label: "Listen address", Group: "App", Help: "HTTP listen address", Default: ":8888"},
	{Key: "logging.nginx_access_json", Label: "Nginx access JSON log path", Group: "Logging", Help: "Path to the nginx JSON access log", Default: "/var/log/nginx/access.db.json"},
	{Key: "dns.enabled", Label: "DNS enabled", Group: "DNS", Help: "Enable built-in DNS server listener", Default: "1"},
	{Key: "dns.dnssec_enabled", Label: "DNSSEC enabled", Group: "DNS", Help: "Enable DNSSEC signing and DNSKEY/DS responses", Default: "0"},
	{Key: "dns.dnssec_private_key_pem", Label: "DNSSEC private key PEM", Group: "DNS", Help: "PKCS#8 Ed25519 private key used for DNSSEC signing", Default: ""},
	{Key: "dns.dnssec_public_key", Label: "DNSSEC public key", Group: "DNS", Help: "Derived from private key. Copy/paste for DNSKEY workflows", Default: "", ReadOnly: true},
	{Key: "dns.dnssec_public_key_json", Label: "DNSSEC public key JSON", Group: "DNS", Help: "Derived JSON payload for external integrations", Default: "", ReadOnly: true},
	{Key: "dns.ns_hosts", Label: "Authoritative NS hosts", Group: "DNS", Help: "Comma-separated list of NS hostnames", Default: "ns1.nsstatic.org.,ns2.nsstatic.org."},
	{Key: "dns.primary_ns", Label: "Primary NS hostname", Group: "DNS", Help: "Used for NS status check", Default: "ns1.nsstatic.org"},
	{Key: "dns.resolver_addr", Label: "DNS resolver address", Group: "DNS", Help: "Resolver used for NS checks", Default: "1.1.1.1:53"},
	{Key: "dns.caa_issuer", Label: "CAA issuer", Group: "DNS", Help: "Value for CAA issue record", Default: "letsencrypt.org"},
	{Key: "dns.soa_mname", Label: "SOA MNAME", Group: "DNS", Help: "Primary name server for SOA", Default: "ns1.nsstatic.org."},
	{Key: "dns.soa_rname_template", Label: "SOA RNAME template", Group: "DNS", Help: "Use {domain} placeholder", Default: "hostmaster.{domain}"},
	{Key: "system.dns_probe_addr", Label: "DNS probe address", Group: "System", Help: "Used for dashboard DNS status", Default: "127.0.0.1:53"},
	{Key: "paths.error_pages", Label: "Error pages path", Group: "Paths", Help: "Filesystem path for custom error pages", Default: "/var/www/error_pages"},
	{Key: "paths.nginx_sites_available", Label: "Nginx sites-available", Group: "Paths", Help: "Nginx sites-available directory", Default: "/etc/nginx/sites-available"},
	{Key: "paths.nginx_sites_enabled", Label: "Nginx sites-enabled", Group: "Paths", Help: "Nginx sites-enabled directory", Default: "/etc/nginx/sites-enabled"},
	{Key: "paths.nginx_conf_d", Label: "Nginx conf.d", Group: "Paths", Help: "Nginx conf.d directory", Default: "/etc/nginx/conf.d"},
	{Key: "paths.ssl_dir", Label: "SSL directory", Group: "Paths", Help: "Directory for issued certificates", Default: "/etc/ssl"},
	{Key: "openvpn.pki_dir", Label: "OpenVPN PKI dir", Group: "OpenVPN", Help: "PKI directory for OpenVPN CA", Default: "/root/openvpn-ca/pki"},
	{Key: "openvpn.ca_dir", Label: "OpenVPN CA dir", Group: "OpenVPN", Help: "Base directory for OpenVPN CA", Default: "/root/openvpn-ca"},
	{Key: "openvpn.easy_rsa_path", Label: "EasyRSA path", Group: "OpenVPN", Help: "Path to easyrsa binary", Default: "/usr/share/easy-rsa/easyrsa"},
	{Key: "openvpn.ccd_dir", Label: "OpenVPN CCD dir", Group: "OpenVPN", Help: "Client config directory", Default: "/etc/openvpn/ccd"},
	{Key: "openvpn.remote_host", Label: "OpenVPN remote host", Group: "OpenVPN", Help: "Remote host used in client config", Default: "nsstatic.org"},
	{Key: "openvpn.remote_port", Label: "OpenVPN remote port", Group: "OpenVPN", Help: "Remote port used in client config", Default: "1194"},
	{Key: "acme.email", Label: "ACME account email", Group: "ACME", Help: "Email for certificate registration", Default: "info@nihonsaba.net"},
	{Key: "acme.http01_host", Label: "HTTP-01 listen host", Group: "ACME", Help: "Host for HTTP-01 challenge server", Default: "127.0.0.1"},
	{Key: "acme.http01_port", Label: "HTTP-01 listen port", Group: "ACME", Help: "Port for HTTP-01 challenge server", Default: "8089"},
	{Key: "cdn.tailwind", Label: "Tailwind CDN URL", Group: "CDN", Help: "Tailwind CDN script URL", Default: "https://cdn.tailwindcss.com"},
	{Key: "cdn.alpine", Label: "Alpine.js CDN URL", Group: "CDN", Help: "Alpine.js CDN script URL", Default: "https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"},
	{Key: "cdn.echarts", Label: "ECharts CDN URL", Group: "CDN", Help: "ECharts CDN script URL", Default: "https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"},
	{Key: "cdn.leaflet_js", Label: "Leaflet JS CDN URL", Group: "CDN", Help: "Leaflet JS script URL", Default: "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"},
	{Key: "cdn.leaflet_css", Label: "Leaflet CSS CDN URL", Group: "CDN", Help: "Leaflet CSS stylesheet URL", Default: "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"},
	{Key: "abuseipdb.api_key", Label: "AbuseIPDB API key", Group: "Security", Help: "API key for IP reputation lookups", Default: ""},
	{Key: "abuseipdb.risk_threshold", Label: "AbuseIPDB risk threshold", Group: "Security", Help: "Minimum score to classify as suspicious", Default: "50"},
	{Key: "abuseipdb.max_age_days", Label: "AbuseIPDB max age days", Group: "Security", Help: "Max age of reports when querying AbuseIPDB", Default: "90"},
	{Key: "abuseipdb.cache_ttl_hours", Label: "AbuseIPDB cache TTL (hours)", Group: "Security", Help: "How long to cache reputation lookups", Default: "24"},
	{Key: "security.fail2ban_interval_seconds", Label: "Fail2Ban interval (seconds)", Group: "Security", Help: "How often Fail2Ban scans logs", Default: "30"},
	{Key: "nginx.transparent_proxy", Label: "Nginx transparent proxy", Group: "Nginx", Help: "Enable proxy_bind transparent to preserve client IP (requires OS routing setup)", Default: "0"},
}

func (s *SettingsService) EnsureTable() error {
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS app_settings (
			setting_key VARCHAR(128) PRIMARY KEY,
			setting_value TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Println("EnsureTable app_settings failed:", err)
	}
	return err
}

func (s *SettingsService) Defaults() map[string]string {
	defaults := make(map[string]string, len(settingsDefinitions))
	for _, d := range settingsDefinitions {
		defaults[d.Key] = d.Default
	}
	return defaults
}

func (s *SettingsService) GetAll() (map[string]string, error) {
	if err := s.EnsureTable(); err != nil {
		return nil, err
	}

	rows, err := db.DB.Query(`SELECT setting_key, setting_value FROM app_settings`)
	if err != nil {
		log.Println("GetAll settings failed:", err)
		return nil, err
	}
	defer rows.Close()

	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			log.Println("GetAll settings scan failed:", err)
			continue
		}
		values[key] = value
	}
	return values, nil
}

func (s *SettingsService) GetAllWithDefaults() map[string]string {
	defaults := s.Defaults()
	values, err := s.GetAll()
	if err != nil {
		return defaults
	}
	for k, v := range values {
		if v != "" {
			defaults[k] = v
		}
	}
	return defaults
}

func (s *SettingsService) GetValue(key string) string {
	defaults := s.Defaults()
	if err := s.EnsureTable(); err != nil {
		return defaults[key]
	}

	var value string
	err := db.DB.QueryRow(`SELECT setting_value FROM app_settings WHERE setting_key = ?`, key).Scan(&value)
	if err != nil || value == "" {
		return defaults[key]
	}
	return value
}

func (s *SettingsService) SetMany(values map[string]string) error {
	if err := s.EnsureTable(); err != nil {
		return err
	}

	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO app_settings (setting_key, setting_value)
		VALUES (?, ?)
		ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for key, value := range values {
		if _, err := stmt.Exec(key, value); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (s *SettingsService) EditableSettings() []models.SettingItem {
	values := s.GetAllWithDefaults()
	if derived, err := deriveDNSSECPublicKey(values["dns.dnssec_private_key_pem"]); err == nil {
		values["dns.dnssec_public_key"] = derived
		values["dns.dnssec_public_key_json"] = buildDNSSECPublicKeyJSON(derived)
	} else {
		values["dns.dnssec_public_key"] = ""
		values["dns.dnssec_public_key_json"] = ""
	}

	items := make([]models.SettingItem, 0, len(settingsDefinitions))
	for _, def := range settingsDefinitions {
		items = append(items, models.SettingItem{
			Key:      def.Key,
			Label:    def.Label,
			Value:    values[def.Key],
			Group:    def.Group,
			Help:     def.Help,
			ReadOnly: def.ReadOnly,
		})
	}
	return items
}

func deriveDNSSECPublicKey(rawPrivate string) (string, error) {
	priv, err := parseDNSSECPrivateKeyForSettings(rawPrivate)
	if err != nil {
		return "", err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub), nil
}

func buildDNSSECPublicKeyJSON(publicKey string) string {
	key := dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: publicKey,
	}

	payload := map[string]any{
		"extensions": map[string]any{
			"secDns": map[string]any{
				"dsData": []map[string]any{
					{
						"keyTag":     key.KeyTag(),
						"alg":        int(dns.ED25519),
						"digestType": 2,
						"digest":     "",
						"keyData": map[string]any{
							"flags":    257,
							"protocol": 3,
							"alg":      int(dns.ED25519),
							"pubKey":   publicKey,
						},
					},
				},
			},
		},
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func parseDNSSECPrivateKeyForSettings(raw string) (ed25519.PrivateKey, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, errors.New("empty private key")
	}
	value = strings.Trim(value, `"'`)
	if strings.Contains(value, `\n`) {
		value = strings.ReplaceAll(value, `\n`, "\n")
	}
	value = normalizeCompactPrivateKeyPEMForSettings(value)

	if block, _ := pem.Decode([]byte(value)); block != nil {
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if priv, ok := pk.(ed25519.PrivateKey); ok {
				return priv, nil
			}
			return nil, errors.New("dnssec private key must be Ed25519")
		}
	}

	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PrivateKey:") {
			continue
		}
		b64 := strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		rawKey, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		switch len(rawKey) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(rawKey), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(rawKey), nil
		}
	}

	return nil, errors.New("invalid dns.dnssec_private_key_pem")
}

func normalizeCompactPrivateKeyPEMForSettings(value string) string {
	const begin = "-----BEGIN PRIVATE KEY-----"
	const end = "-----END PRIVATE KEY-----"
	if !strings.Contains(value, begin) || !strings.Contains(value, end) {
		return value
	}
	bi := strings.Index(value, begin)
	ei := strings.Index(value, end)
	if bi < 0 || ei < 0 || ei <= bi {
		return value
	}
	body := strings.TrimSpace(value[bi+len(begin) : ei])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.ReplaceAll(body, "\t", "")
	body = strings.ReplaceAll(body, " ", "")
	if body == "" {
		return value
	}
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString("\n")
	for i := 0; i < len(body); i += 64 {
		j := i + 64
		if j > len(body) {
			j = len(body)
		}
		b.WriteString(body[i:j])
		b.WriteString("\n")
	}
	b.WriteString(end)
	b.WriteString("\n")
	return b.String()
}
