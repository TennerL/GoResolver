package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
)

type SettingDefinition struct {
	Key      string
	Label    string
	Group    string
	Help     string
	Default  string
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
	{Key: "dns.dnssec_registrar_values", Label: "DNSSEC registrar values", Group: "DNS", Help: "Registrar-ready DS values for each managed zone", Default: "", ReadOnly: true},
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
	{Key: "security.fail2ban_interval_seconds", Label: "Fail2Ban interval (seconds)", Group: "Security", Help: "How often Fail2Ban scans logs", Default: "5"},
	{Key: "analytics.retention_days", Label: "Analytics retention (days)", Group: "Analytics", Help: "Delete access log entries older than this many days", Default: "30"},
	{Key: "analytics.alert.error_rate_percent", Label: "Analytics error-rate alert (%)", Group: "Analytics", Help: "Trigger alert when 4xx/5xx share reaches this percentage", Default: "20"},
	{Key: "analytics.alert.avg_request_time_ms", Label: "Analytics latency alert (ms)", Group: "Analytics", Help: "Trigger alert when average request time reaches this threshold", Default: "800"},
	{Key: "analytics.alert.request_spike_factor", Label: "Analytics request-spike factor", Group: "Analytics", Help: "Trigger alert when request volume exceeds this multiplier of the previous window", Default: "2.0"},
	{Key: "analytics.alert.min_requests", Label: "Analytics alert minimum requests", Group: "Analytics", Help: "Require at least this many requests before threshold alerts trigger", Default: "100"},
	{Key: "analytics.alert.suspicious_ip_count", Label: "Analytics suspicious IP threshold", Group: "Analytics", Help: "Trigger alert when this many suspicious IPs appear in the current window", Default: "3"},
	{Key: "analytics.incident_window_minutes", Label: "Analytics incident window (minutes)", Group: "Analytics", Help: "Tracked incidents use this fixed monitoring window and ignore dashboard filter changes", Default: "60"},
	{Key: "mail.smtp_host", Label: "SMTP host", Group: "Mail", Help: "Hostname of the outgoing SMTP server", Default: ""},
	{Key: "mail.smtp_port", Label: "SMTP port", Group: "Mail", Help: "SMTP port, for example 465 or 587", Default: "465"},
	{Key: "mail.username", Label: "SMTP username", Group: "Mail", Help: "Username for SMTP authentication", Default: ""},
	{Key: "mail.password", Label: "SMTP password", Group: "Mail", Help: "Password for SMTP authentication", Default: ""},
	{Key: "mail.from", Label: "Mail from address", Group: "Mail", Help: "Sender address used for alert emails", Default: ""},
	{Key: "mail.to", Label: "Mail recipients", Group: "Mail", Help: "Comma-separated recipient addresses for alert emails", Default: ""},
	{Key: "mail.transport", Label: "Mail transport", Group: "Mail", Help: "Choose plain SMTP, SMTP with STARTTLS, or implicit TLS (SMTPS)", Default: "smtps"},
	{Key: "mail.starttls", Label: "Legacy TLS toggle", Group: "Mail", Help: "Legacy compatibility setting. Prefer mail.transport instead.", Default: "1"},
	{Key: "mail.notify_on_open", Label: "Notify on new/open incident", Group: "Mail", Help: "Send an email when a new incident is created or re-opened", Default: "1"},
	{Key: "mail.notify_on_resolved", Label: "Notify on resolved incident", Group: "Mail", Help: "Send an email when an incident resolves", Default: "0"},
	{Key: "mail.notify_on_fail2ban_ban", Label: "Notify on Fail2Ban ban", Group: "Mail", Help: "Send an email whenever Fail2Ban creates a new ban", Default: "1"},
	{Key: "mail.subject_template", Label: "Mail subject template", Group: "Mail", Help: "Supports {{title}}, {{severity}}, {{status}}, {{value}}, {{threshold}}", Default: "[GoResolver] {{severity}} {{status}}: {{title}}"},
	{Key: "mail.body_template", Label: "Mail body template", Group: "Mail", Help: "Supports {{title}}, {{severity}}, {{status}}, {{summary}}, {{value}}, {{threshold}}, {{first_seen}}, {{last_seen}}, {{top_hosts}}, {{top_ips}}, {{top_uris}}", Default: "GoResolver analytics incident\n\nTitle: {{title}}\nSeverity: {{severity}}\nStatus: {{status}}\nValue: {{value}}\nThreshold: {{threshold}}\nSummary: {{summary}}\nFirst seen: {{first_seen}}\nLast seen: {{last_seen}}\nTop hosts: {{top_hosts}}\nTop IPs: {{top_ips}}\nTop URIs: {{top_uris}}\n"},
	{Key: "mail.html_template", Label: "Mail HTML template", Group: "Mail", Help: "Optional HTML version. Supports the same placeholders as the text template.", Default: ""},
	{Key: "mail.fail2ban_subject_template", Label: "Fail2Ban mail subject template", Group: "Mail", Help: "Supports {{server_id}}, {{ip}}, {{hits}}, {{expires_at}}, {{reason}}", Default: "[GoResolver] Fail2Ban ban: {{ip}} on server {{server_id}}"},
	{Key: "mail.fail2ban_body_template", Label: "Fail2Ban mail body template", Group: "Mail", Help: "Supports {{server_id}}, {{ip}}, {{hits}}, {{banned_at}}, {{expires_at}}, {{reason}}", Default: "GoResolver Fail2Ban ban\n\nServer ID: {{server_id}}\nIP: {{ip}}\nHits: {{hits}}\nBanned at: {{banned_at}}\nExpires at: {{expires_at}}\nReason: {{reason}}\n"},
	{Key: "mail.fail2ban_html_template", Label: "Fail2Ban HTML template", Group: "Mail", Help: "Optional HTML version for Fail2Ban ban notifications. Supports the same placeholders as the text template.", Default: ""},
	{Key: "nginx.default_deny_enabled", Label: "Default deny site", Group: "Nginx", Help: "Enable the fallback default_server that blocks unmatched hosts while keeping ACME challenge handling available", Default: "1"},
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

	prepared, err := prepareSettingsValuesForSave(s.GetAllWithDefaults(), values)
	if err != nil {
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

	for key, value := range prepared {
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
		zones := s.dnssecDomainNames()
		values["dns.dnssec_public_key"] = derived
		values["dns.dnssec_registrar_values"] = buildDNSSECRegistrarValues(derived, zones)
		values["dns.dnssec_public_key_json"] = buildDNSSECPublicKeyJSON(derived, zones)
	} else {
		values["dns.dnssec_public_key"] = ""
		values["dns.dnssec_registrar_values"] = ""
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

func prepareSettingsValuesForSave(current, updates map[string]string) (map[string]string, error) {
	prepared := make(map[string]string, len(updates)+1)
	effective := make(map[string]string, len(current)+len(updates))
	for key, value := range current {
		effective[key] = value
	}
	for key, value := range updates {
		prepared[key] = value
		effective[key] = value
	}

	if settingEnabledForSettings(effective["dns.dnssec_enabled"], false) &&
		strings.TrimSpace(effective["dns.dnssec_private_key_pem"]) == "" {
		privateKeyPEM, err := generateDNSSECPrivateKeyPEM()
		if err != nil {
			return nil, err
		}
		prepared["dns.dnssec_private_key_pem"] = privateKeyPEM
	}

	return prepared, nil
}

func generateDNSSECPrivateKeyPEM() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})), nil
}

func buildDNSSECPublicKeyJSON(publicKey string, zones []string) string {
	domains := make([]map[string]any, 0, len(zones))
	for _, zone := range zones {
		payload := buildDNSSECDomainJSON(zone, publicKey)
		if len(payload) == 0 {
			continue
		}
		domains = append(domains, payload)
	}

	payload := map[string]any{
		"domains": domains,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func buildDNSSECRegistrarValues(publicKey string, zones []string) string {
	sections := make([]string, 0, len(zones))
	for _, zone := range zones {
		key := dnssecDNSKEYForZone(zone, publicKey)
		if key == nil {
			continue
		}

		lines := []string{
			fmt.Sprintf("Zone: %s", strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")),
			fmt.Sprintf("Key Tag: %d", key.KeyTag()),
			fmt.Sprintf("Flags: %d", key.Flags),
			fmt.Sprintf("Protocol: %d", key.Protocol),
			fmt.Sprintf("Algorithm: %d (%s)", key.Algorithm, dnssecAlgorithmName(key.Algorithm)),
			fmt.Sprintf("Public Key: %s", key.PublicKey),
		}

		for _, digestType := range []uint8{dns.SHA256, dns.SHA384} {
			ds := key.ToDS(digestType)
			if ds == nil {
				continue
			}
			lines = append(lines,
				fmt.Sprintf("Digest Type %d (%s): %s", ds.DigestType, dnssecDigestTypeName(ds.DigestType), ds.Digest),
				fmt.Sprintf("DS Record %s: %s", dnssecDigestTypeName(ds.DigestType), ds.String()),
			)
		}

		sections = append(sections, strings.Join(lines, "\n"))
	}

	return strings.Join(sections, "\n\n")
}

func buildDNSSECDomainJSON(zone, publicKey string) map[string]any {
	key := dnssecDNSKEYForZone(zone, publicKey)
	if key == nil {
		return nil
	}

	dsData := make([]map[string]any, 0, 2)
	for _, digestType := range []uint8{dns.SHA256, dns.SHA384} {
		ds := key.ToDS(digestType)
		if ds == nil {
			continue
		}
		dsData = append(dsData, map[string]any{
			"keyTag":     key.KeyTag(),
			"alg":        int(dns.ED25519),
			"digestType": int(digestType),
			"digest":     ds.Digest,
			"keyData": map[string]any{
				"flags":    257,
				"protocol": 3,
				"alg":      int(dns.ED25519),
				"pubKey":   publicKey,
			},
		})
	}

	return map[string]any{
		"name": strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), "."),
		"extensions": map[string]any{
			"secDns": map[string]any{
				"dsData": dsData,
			},
		},
	}
}

func (s *SettingsService) dnssecDomainNames() []string {
	rows, err := db.DB.Query(`SELECT name FROM domains ORDER BY name`)
	if err != nil {
		log.Println("dnssec domain lookup failed:", err)
		return nil
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	zones := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Println("dnssec domain scan failed:", err)
			continue
		}
		zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if zone == "" {
			continue
		}
		if _, ok := seen[zone]; ok {
			continue
		}
		seen[zone] = struct{}{}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		log.Println("dnssec domain rows failed:", err)
	}
	return zones
}

func dnssecDNSKEYForZone(zone, publicKey string) *dns.DNSKEY {
	normalizedZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if normalizedZone == "" || strings.TrimSpace(publicKey) == "" {
		return nil
	}

	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(normalizedZone),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: publicKey,
	}
}

func dnssecAlgorithmName(algorithm uint8) string {
	if name, ok := dns.AlgorithmToString[algorithm]; ok && name != "" {
		return name
	}
	return "Unknown"
}

func dnssecDigestTypeName(digestType uint8) string {
	switch digestType {
	case dns.SHA256:
		return "SHA-256"
	case dns.SHA384:
		return "SHA-384"
	default:
		return "Unknown"
	}
}

func settingEnabledForSettings(raw string, defaultValue bool) bool {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return defaultValue
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
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
