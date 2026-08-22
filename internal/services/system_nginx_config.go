package services

import (
	"GoResolver/internal/models"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	systemNginxConfigSettingKey = "nginx.system_server_config"
	systemNginxSitesSettingKey  = "nginx.system_server_sites"
	systemNginxConfigFilename   = "goresolver-system-object.conf"
)

func (s *ServerConfigurationService) GetSystemNginxConfig() string {
	return NewSettingsService().GetValue(systemNginxConfigSettingKey)
}

func (s *ServerConfigurationService) GetSystemNginxSites() []models.SystemNginxSite {
	raw := strings.TrimSpace(NewSettingsService().GetValue(systemNginxSitesSettingKey))
	if raw == "" {
		return nil
	}
	var sites []models.SystemNginxSite
	if err := json.Unmarshal([]byte(raw), &sites); err != nil {
		return nil
	}
	return normalizeSystemNginxSites(sites)
}

func (s *ServerConfigurationService) SaveSystemNginxConfig(raw string, sites []models.SystemNginxSite) error {
	settings := NewSettingsService()
	targetPath := filepath.Join(settings.GetValue("paths.nginx_conf_d"), systemNginxConfigFilename)
	normalizedRaw := normalizeSystemNginxConfig(raw)
	normalizedSites := normalizeSystemNginxSites(sites)
	previousRaw := s.GetSystemNginxConfig()
	previousSites := s.GetSystemNginxSites()
	policy, _ := s.GetDDoSPolicy(strconv.Itoa(systemServerID))

	content, err := renderSystemNginxConfig(normalizedSites, normalizedRaw, policy)
	if err != nil {
		return err
	}
	if err := writeSystemNginxConfigFile(targetPath, content); err != nil {
		return err
	}

	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		rollback := renderSystemNginxConfigOrEmpty(previousSites, normalizeSystemNginxConfig(previousRaw), policy)
		_ = writeSystemNginxConfigFile(targetPath, rollback)
		return fmt.Errorf("nginx -t failed: %v\n%s", err, string(out))
	}

	if out, err := exec.Command("nginx", "-s", "reload").CombinedOutput(); err != nil {
		rollback := renderSystemNginxConfigOrEmpty(previousSites, normalizeSystemNginxConfig(previousRaw), policy)
		_ = writeSystemNginxConfigFile(targetPath, rollback)
		_, _ = exec.Command("nginx", "-s", "reload").CombinedOutput()
		return fmt.Errorf("nginx reload failed: %v\n%s", err, string(out))
	}

	encodedSites, err := json.Marshal(normalizedSites)
	if err != nil {
		return err
	}

	return settings.SetMany(map[string]string{
		systemNginxConfigSettingKey: normalizedRaw,
		systemNginxSitesSettingKey:  string(encodedSites),
	})
}

func (s *ServerConfigurationService) DeploySystemNginxConfig() error {
	return s.SaveSystemNginxConfig(s.GetSystemNginxConfig(), s.GetSystemNginxSites())
}

func (s *ServerConfigurationService) ImportSystemNginxConfig(raw string) ([]models.SystemNginxSite, string, error) {
	blocks := splitServerBlocks(raw)
	if len(blocks) == 0 {
		return nil, "", fmt.Errorf("no nginx server blocks found")
	}

	sites := make([]models.SystemNginxSite, 0, len(blocks))
	remainderParts := make([]string, 0)
	for idx, block := range blocks {
		site, remainder, err := parseImportedSystemNginxSite(block, idx)
		if err != nil {
			return nil, "", err
		}
		if site.ServerName != "" {
			sites = append(sites, site)
		}
		if strings.TrimSpace(remainder) != "" {
			remainderParts = append(remainderParts, remainder)
		}
	}

	return normalizeSystemNginxSites(sites), normalizeSystemNginxConfig(strings.Join(remainderParts, "\n\n")), nil
}

func normalizeSystemNginxConfig(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return trimmed + "\n"
}

func normalizeSystemNginxSites(sites []models.SystemNginxSite) []models.SystemNginxSite {
	normalized := make([]models.SystemNginxSite, 0, len(sites))
	seen := map[string]struct{}{}
	for idx, site := range sites {
		site.ID = strings.TrimSpace(site.ID)
		if site.ID == "" {
			site.ID = fmt.Sprintf("system-site-%d", idx+1)
		}
		if _, ok := seen[site.ID]; ok {
			continue
		}
		seen[site.ID] = struct{}{}

		site.ServerName = strings.TrimSpace(site.ServerName)
		site.Mode = strings.ToLower(strings.TrimSpace(site.Mode))
		if site.Mode == "" {
			site.Mode = "proxy"
		}
		if site.ListenPort <= 0 {
			site.ListenPort = 443
		}
		site.CertPath = strings.TrimSpace(site.CertPath)
		site.KeyPath = strings.TrimSpace(site.KeyPath)
		site.SSLConfigPath = strings.TrimSpace(site.SSLConfigPath)
		site.SSLDhParamPath = strings.TrimSpace(site.SSLDhParamPath)
		site.RootPath = strings.TrimSpace(site.RootPath)
		site.IndexFiles = strings.TrimSpace(site.IndexFiles)
		if site.IndexFiles == "" {
			site.IndexFiles = "index.php index.html"
		}
		site.ProxyPassURL = strings.TrimSpace(site.ProxyPassURL)
		site.StaticAliasPath = strings.TrimSpace(site.StaticAliasPath)
		site.PHPSocket = strings.TrimSpace(site.PHPSocket)
		site.PHPMyAdminSocket = strings.TrimSpace(site.PHPMyAdminSocket)
		site.StaticExpires = strings.TrimSpace(site.StaticExpires)
		if site.StaticExpires == "" {
			site.StaticExpires = "1h"
		}
		site.StaticCacheControl = strings.TrimSpace(site.StaticCacheControl)
		if site.StaticCacheControl == "" {
			site.StaticCacheControl = "public"
		}
		if site.ServerName == "" {
			continue
		}
		normalized = append(normalized, site)
	}
	return normalized
}

func renderSystemNginxConfigOrEmpty(sites []models.SystemNginxSite, raw string, policy models.DDoSPolicy) string {
	content, err := renderSystemNginxConfig(sites, raw, policy)
	if err != nil {
		return normalizeSystemNginxConfig(raw)
	}
	return content
}

func renderSystemNginxConfig(sites []models.SystemNginxSite, raw string, policy models.DDoSPolicy) (string, error) {
	var b strings.Builder

	for idx, site := range normalizeSystemNginxSites(sites) {
		block, err := renderSystemNginxSite(site, policy)
		if err != nil {
			return "", err
		}
		if idx > 0 {
			b.WriteString("\n")
		}
		b.WriteString(block)
	}

	if raw != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(raw)
	}

	return normalizeSystemNginxConfig(b.String()), nil
}

func renderSystemNginxSite(site models.SystemNginxSite, policy models.DDoSPolicy) (string, error) {
	serverNames, err := validateServerNames(site.ServerName)
	if err != nil {
		return "", err
	}
	if err := validatePort(site.ListenPort); err != nil {
		return "", err
	}
	mode := strings.ToLower(strings.TrimSpace(site.Mode))
	if mode != "proxy" && mode != "static" {
		return "", fmt.Errorf("invalid system nginx mode %q", site.Mode)
	}

	var b strings.Builder
	if policy.Enabled {
		b.WriteString(renderDDoSGlobals(policy, systemSiteNumericID(site.ID)))
	}

	b.WriteString("server {\n")
	if site.SSL {
		listenLine := fmt.Sprintf(" listen %d ssl", site.ListenPort)
		if site.HTTP2 {
			listenLine += " http2"
		}
		b.WriteString(listenLine + ";\n")
	} else {
		fmt.Fprintf(&b, " listen %d;\n", site.ListenPort)
	}
	fmt.Fprintf(&b, " server_name %s;\n", strings.Join(serverNames, " "))

	if site.SSL {
		if site.CertPath != "" {
			fmt.Fprintf(&b, " ssl_certificate %s;\n", site.CertPath)
		}
		if site.KeyPath != "" {
			fmt.Fprintf(&b, " ssl_certificate_key %s;\n", site.KeyPath)
		}
		if site.SSLConfigPath != "" {
			fmt.Fprintf(&b, " include %s;\n", site.SSLConfigPath)
		}
		if site.SSLDhParamPath != "" {
			fmt.Fprintf(&b, " ssl_dhparam %s;\n", site.SSLDhParamPath)
		}
	}
	b.WriteString(renderBaselineSecurityHeaders())

	if site.RootPath != "" {
		fmt.Fprintf(&b, " root %s;\n", site.RootPath)
	}
	if site.IndexFiles != "" {
		fmt.Fprintf(&b, " index %s;\n", site.IndexFiles)
	}
	b.WriteString("\n")

	if policy.Enabled && strings.EqualFold(policy.Mode, "challenge") {
		b.WriteString(renderChallengeLocation(systemSiteNumericID(site.ID), policy))
	}

	if site.StaticAliasPath != "" {
		b.WriteString(" location /static/ {\n")
		fmt.Fprintf(&b, "  alias %s;\n", site.StaticAliasPath)
		b.WriteString("  try_files $uri =404;\n")
		if site.AccessLogOffStatic {
			b.WriteString("  access_log off;\n")
		}
		if site.StaticExpires != "" {
			fmt.Fprintf(&b, "  expires %s;\n", site.StaticExpires)
		}
		if site.StaticCacheControl != "" {
			fmt.Fprintf(&b, "  add_header Cache-Control %s;\n", strconv.Quote(site.StaticCacheControl))
		}
		b.WriteString(" }\n\n")
	}

	if site.PHPMyAdminEnabled {
		b.WriteString(" location /phpmyadmin/ {\n")
		b.WriteString("  index index.php;\n")
		b.WriteString("  try_files $uri $uri/ /phpmyadmin/index.php?$query_string;\n")
		b.WriteString(" }\n\n")

		b.WriteString(" location ~ ^/phpmyadmin/(.+\\.php)$ {\n")
		b.WriteString("  include fastcgi_params;\n")
		b.WriteString("  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")
		fmt.Fprintf(&b, "  fastcgi_pass unix:%s;\n", site.PHPMyAdminSocket)
		b.WriteString(" }\n\n")
	}

	if site.PHPEnabled {
		b.WriteString(" location ~ \\.php$ {\n")
		b.WriteString("  include fastcgi_params;\n")
		b.WriteString("  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")
		fmt.Fprintf(&b, "  fastcgi_pass unix:%s;\n", site.PHPSocket)
		b.WriteString(" }\n\n")
	}

	b.WriteString(" location / {\n")
	if policy.Enabled && strings.EqualFold(policy.Mode, "challenge") {
		fmt.Fprintf(&b, "  if ($gr_ddos_allow_%d = 0) { return 302 /__gr_challenge_%d?u=$request_uri; }\n", systemSiteNumericID(site.ID), systemSiteNumericID(site.ID))
	}
	if policy.Enabled && policy.RateLimit > 0 {
		fmt.Fprintf(&b, "  limit_req zone=gr_%d_req burst=%d nodelay;\n", systemSiteNumericID(site.ID), max(policy.Burst, 0))
	}
	if policy.Enabled && policy.ConnLimit > 0 {
		fmt.Fprintf(&b, "  limit_conn gr_%d_conn %d;\n", systemSiteNumericID(site.ID), policy.ConnLimit)
	}
	if mode == "proxy" {
		fmt.Fprintf(&b, "  proxy_pass %s;\n", site.ProxyPassURL)
		b.WriteString("  proxy_http_version 1.1;\n")
		b.WriteString("  proxy_set_header Host $host;\n")
		b.WriteString("  proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("  proxy_set_header X-Forwarded-Proto $scheme;\n")
		if site.ProxyBufferingOff {
			b.WriteString("  proxy_buffering off;\n")
		}
	} else {
		b.WriteString("  try_files $uri $uri/ =404;\n")
	}
	b.WriteString(" }\n")
	b.WriteString("}\n")

	return b.String(), nil
}

func systemSiteNumericID(id string) int {
	sum := 0
	for _, r := range id {
		sum += int(r)
	}
	if sum <= 0 {
		return 9000
	}
	return 9000 + (sum % 100000)
}

func splitServerBlocks(raw string) []string {
	var blocks []string
	start := -1
	depth := 0

scan:
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '#':
			for i+1 < len(raw) && raw[i+1] != '\n' {
				i++
			}
		case 's':
			if start == -1 && strings.HasPrefix(raw[i:], "server") {
				j := i + len("server")
				for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\r' || raw[j] == '\n') {
					j++
				}
				if j < len(raw) && raw[j] == '{' {
					start = i
					depth = 1
					i = j
				}
			}
		case '{':
			if start != -1 {
				depth++
			}
		case '}':
			if start != -1 {
				depth--
				if depth == 0 {
					blocks = append(blocks, strings.TrimSpace(raw[start:i+1]))
					start = -1
				} else if depth < 0 {
					break scan
				}
			}
		}
	}

	return blocks
}

func parseImportedSystemNginxSite(block string, idx int) (models.SystemNginxSite, string, error) {
	site := models.SystemNginxSite{
		ID:                 fmt.Sprintf("system-site-%d", idx+1),
		ListenPort:         443,
		SSL:                true,
		HTTP2:              false,
		Mode:               "static",
		IndexFiles:         "index.php index.html",
		SSLConfigPath:      "/etc/letsencrypt/options-ssl-nginx.conf",
		SSLDhParamPath:     "/etc/letsencrypt/ssl-dhparams.pem",
		PHPSocket:          "/run/php/php8.1-fpm.sock",
		PHPMyAdminSocket:   "/run/php/phpmyadmin.sock",
		ProxyBufferingOff:  false,
		AccessLogOffStatic: false,
		StaticExpires:      "1h",
		StaticCacheControl: "public",
	}

	listenLine := extractDirective(block, "listen")
	if listenLine != "" {
		if port := firstPort(listenLine); port > 0 {
			site.ListenPort = port
		}
		site.SSL = strings.Contains(listenLine, "ssl")
		site.HTTP2 = strings.Contains(listenLine, "http2")
	}

	site.ServerName = strings.TrimSpace(extractDirective(block, "server_name"))
	site.CertPath = strings.TrimSpace(extractDirective(block, "ssl_certificate"))
	site.KeyPath = strings.TrimSpace(extractDirective(block, "ssl_certificate_key"))
	if includePath := strings.TrimSpace(extractDirective(block, "include")); includePath != "" {
		site.SSLConfigPath = includePath
	}
	if dhParam := strings.TrimSpace(extractDirective(block, "ssl_dhparam")); dhParam != "" {
		site.SSLDhParamPath = dhParam
	}
	if root := strings.TrimSpace(extractDirective(block, "root")); root != "" {
		site.RootPath = root
	}
	if indexFiles := strings.TrimSpace(extractDirective(block, "index")); indexFiles != "" {
		site.IndexFiles = indexFiles
	}

	if strings.Contains(block, "location / {") && strings.Contains(block, "proxy_pass ") {
		site.Mode = "proxy"
		site.ProxyPassURL = strings.TrimSpace(extractDirective(block, "proxy_pass"))
		site.ProxyBufferingOff = strings.Contains(block, "proxy_buffering off;")
	}

	if strings.Contains(block, "location /static/") {
		site.StaticAliasPath = strings.TrimSpace(extractDirective(block, "alias"))
		site.AccessLogOffStatic = strings.Contains(block, "access_log off;")
		if expires := strings.TrimSpace(extractDirective(block, "expires")); expires != "" {
			site.StaticExpires = expires
		}
		if cacheControl := extractQuotedDirective(block, "add_header Cache-Control"); cacheControl != "" {
			site.StaticCacheControl = cacheControl
		}
	}

	if strings.Contains(block, "location /phpmyadmin/") {
		site.PHPMyAdminEnabled = true
		site.PHPMyAdminSocket = extractFastCGISocket(block, "^/phpmyadmin/")
	}

	if strings.Contains(block, "location ~ \\.php$") {
		site.PHPEnabled = true
		site.PHPSocket = extractFastCGISocket(block, "\\.php$")
	}

	if strings.TrimSpace(site.ServerName) == "" {
		return site, "", fmt.Errorf("imported nginx block is missing server_name")
	}

	return site, "", nil
}

func extractDirective(block, name string) string {
	lines := strings.Split(block, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, name))
		if idx := strings.Index(value, "#"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		value = strings.TrimSpace(strings.TrimSuffix(value, ";"))
		return value
	}
	return ""
}

func extractQuotedDirective(block, name string) string {
	value := extractDirective(block, name)
	return strings.Trim(value, "\"")
}

func firstPort(raw string) int {
	for _, field := range strings.Fields(raw) {
		port, err := strconv.Atoi(field)
		if err == nil {
			return port
		}
	}
	return 0
}

func extractFastCGISocket(block, locationNeedle string) string {
	lines := strings.Split(block, "\n")
	inTargetLocation := false
	locationDepth := 0

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "location ") {
			inTargetLocation = strings.Contains(line, locationNeedle)
			locationDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		if inTargetLocation && strings.HasPrefix(line, "fastcgi_pass ") {
			return stripUnixPrefix(extractDirective(line, "fastcgi_pass"))
		}
		if inTargetLocation {
			locationDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if locationDepth <= 0 {
				inTargetLocation = false
				locationDepth = 0
			}
		}
	}

	return ""
}

func stripUnixPrefix(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "unix:")
}

func writeSystemNginxConfigFile(path, content string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("nginx conf.d path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if strings.TrimSpace(content) == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}
