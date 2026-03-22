package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
)

const defaultLetsEncryptConfigFile = "/etc/nginx/snippets/letsencrypt.conf"

var errNoNginxSiteConfiguration = errors.New("no nginx site configuration")

type nginxSiteBundle struct {
	ServerID         string
	SiteName         string
	Sites            []models.ServerConfiguration
	Policy           models.DDoSPolicy
	ErrorPages       []models.ServerErrorPages
	ErrorFilesByID   map[string]models.ServerErrorFiles
	TransparentProxy bool
}

type resolvedErrorPage struct {
	Codes       []string
	Filename    string
	Path        string
	DefaultType string
}

type resolvedErrorPageFile struct {
	Filename    string
	Path        string
	DefaultType string
}

func buildNginxConfig(siteName string) (string, error) {
	if err := ensureServerConfigurationSchema(); err != nil {
		return "", err
	}
	if err := NewServerConfigurationService().EnsureDDoSTables(); err != nil {
		return "", err
	}

	sites, err := loadNginxSiteConfigurations(siteName)
	if err != nil {
		return "", err
	}
	if len(sites) == 0 {
		return "", fmt.Errorf("%w for %q", errNoNginxSiteConfiguration, siteName)
	}

	serverID := sites[0].ServerID
	for _, site := range sites[1:] {
		if site.ServerID != serverID {
			return "", fmt.Errorf("site %q spans multiple server ids", siteName)
		}
	}

	svc := NewServerConfigurationService()
	policy, err := svc.GetDDoSPolicy(serverID)
	if err != nil {
		return "", err
	}

	errorFilesByID := map[string]models.ServerErrorFiles{}
	for _, file := range svc.GetServerErrorFiles() {
		errorFilesByID[file.ID] = file
	}

	bundle := nginxSiteBundle{
		ServerID:         serverID,
		SiteName:         siteName,
		Sites:            sites,
		Policy:           policy,
		ErrorPages:       svc.GetServerErrorPages(serverID),
		ErrorFilesByID:   errorFilesByID,
		TransparentProxy: shouldEnableTransparentProxy(),
	}

	return renderNginxSiteBundle(bundle)
}

func loadNginxSiteConfigurations(siteName string) ([]models.ServerConfiguration, error) {
	rows, err := db.DB.Query(`
		SELECT
			CAST(sc.fk_server AS CHAR),
			sc.id,
			sc.server_name,
			sc.server_port,
			sc.ssl_enabled,
			sc.ssl_redirect,
			sc.hsts,
			sc.proxy_pass_port,
			sc.proxy_intercept_errors,
			sc.proxy_connect_timeout,
			sc.proxy_read_timeout,
			sc.proxy_send_timeout,
			sc.websockets,
			sc.letsencrypt_config_file,
			s.ip,
			IFNULL(c.cert_path, ''),
			IFNULL(c.key_path, '')
		FROM server_configuration sc
		LEFT JOIN servers s ON s.id = sc.fk_server
		LEFT JOIN certificates c ON c.site_id = sc.id
		WHERE sc.server_name = ?
			AND sc.site_enabled = 1
		ORDER BY sc.id
	`, strings.TrimSpace(siteName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sites []models.ServerConfiguration
	for rows.Next() {
		var site models.ServerConfiguration
		if err := rows.Scan(
			&site.ServerID,
			&site.ID,
			&site.Server_Name,
			&site.Server_Port,
			&site.SSL_Enabled,
			&site.SSL_Redirect,
			&site.HSTS,
			&site.Proxy_Pass_Port,
			&site.Proxy_Intercept_Errors,
			&site.Proxy_Connect_Timeout,
			&site.Proxy_Read_Timeout,
			&site.Proxy_Send_Timeout,
			&site.Websockets,
			&site.LetsEncryptConfigFile,
			&site.IP,
			&site.Cert_Path,
			&site.Key_Path,
		); err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

func renderNginxSiteBundle(bundle nginxSiteBundle) (string, error) {
	if len(bundle.Sites) == 0 {
		return "", fmt.Errorf("no sites to render")
	}

	var b strings.Builder

	if usesWebsockets(bundle.Sites) {
		b.WriteString("map $http_upgrade $connection_upgrade {\n")
		b.WriteString(" default upgrade;\n")
		b.WriteString(" '' close;\n")
		b.WriteString("}\n\n")
	}

	if globals := renderDDoSGlobals(bundle.Policy, bundle.Sites[0].ID); globals != "" {
		b.WriteString(globals)
	}

	for idx, site := range bundle.Sites {
		block, err := renderNginxSite(site, bundle)
		if err != nil {
			return "", err
		}
		if idx > 0 {
			b.WriteString("\n")
		}
		b.WriteString(block)
	}

	return b.String(), nil
}

func usesWebsockets(sites []models.ServerConfiguration) bool {
	for _, site := range sites {
		if site.Websockets == 1 {
			return true
		}
	}
	return false
}

func renderDDoSGlobals(policy models.DDoSPolicy, siteID int) string {
	if !policy.Enabled {
		return ""
	}

	var b strings.Builder
	whitelist := normalizeWhitelistEntries(policy.Whitelist)
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))

	if len(whitelist) > 0 {
		fmt.Fprintf(&b, "geo $gr_ddos_whitelist_%d {\n", siteID)
		b.WriteString(" default 0;\n")
		for _, entry := range whitelist {
			fmt.Fprintf(&b, " %s 1;\n", entry)
		}
		b.WriteString("}\n\n")
	}

	if policy.RateLimit > 0 {
		fmt.Fprintf(&b, "map $gr_ddos_whitelist_%d $gr_ddos_req_key_%d {\n", siteID, siteID)
		b.WriteString(" default $binary_remote_addr$host;\n")
		b.WriteString(" 1 \"\";\n")
		b.WriteString("}\n\n")
		fmt.Fprintf(&b, "limit_req_zone $gr_ddos_req_key_%d zone=gr_%d_req:10m rate=%dr/s;\n\n", siteID, siteID, policy.RateLimit)
	}

	if policy.ConnLimit > 0 {
		fmt.Fprintf(&b, "map $gr_ddos_whitelist_%d $gr_ddos_conn_key_%d {\n", siteID, siteID)
		b.WriteString(" default $binary_remote_addr$host;\n")
		b.WriteString(" 1 \"\";\n")
		b.WriteString("}\n\n")
		fmt.Fprintf(&b, "limit_conn_zone $gr_ddos_conn_key_%d zone=gr_%d_conn:10m;\n\n", siteID, siteID)
	}

	if mode == "challenge" {
		fmt.Fprintf(&b, "map $cookie_gr_challenge_%d $gr_challenge_valid_%d {\n", siteID, siteID)
		b.WriteString(" default 0;\n")
		b.WriteString(" \"1\" 1;\n")
		b.WriteString("}\n\n")
		fmt.Fprintf(&b, "map \"$gr_ddos_whitelist_%d:$gr_challenge_valid_%d\" $gr_ddos_allow_%d {\n", siteID, siteID, siteID)
		b.WriteString(" default 0;\n")
		b.WriteString(" \"1:0\" 1;\n")
		b.WriteString(" \"1:1\" 1;\n")
		b.WriteString(" \"0:1\" 1;\n")
		b.WriteString("}\n\n")
	}

	return b.String()
}

func renderNginxSite(site models.ServerConfiguration, bundle nginxSiteBundle) (string, error) {
	serverNames, err := validateServerNames(site.Server_Name)
	if err != nil {
		return "", err
	}
	if err := validatePort(site.Server_Port); err != nil {
		return "", fmt.Errorf("site %q listen port invalid: %w", site.Server_Name, err)
	}
	if err := validatePort(site.Proxy_Pass_Port); err != nil {
		return "", fmt.Errorf("site %q upstream port invalid: %w", site.Server_Name, err)
	}

	includePath, err := effectiveLetsEncryptConfigPath(site.LetsEncryptConfigFile)
	if err != nil {
		return "", err
	}
	if err := validateIP(site.IP); err != nil {
		return "", fmt.Errorf("site %q upstream ip invalid: %w", site.Server_Name, err)
	}

	errorPages := resolveErrorPagesForSite(site, bundle.ErrorPages, bundle.ErrorFilesByID)

	var b strings.Builder
	b.WriteString(renderForwardedProtoMaps(site.ID))
	b.WriteString(renderMainServerBlock(site, serverNames, includePath, bundle.Policy, errorPages, bundle.TransparentProxy))

	if site.SSL_Enabled == 1 && site.SSL_Redirect == 1 {
		b.WriteString("\n")
		b.WriteString(renderRedirectServerBlock(site, serverNames, includePath))
	}

	return b.String(), nil
}

func renderForwardedProtoMaps(siteID int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "map $http_x_forwarded_proto $gr_forwarded_proto_%d {\n", siteID)
	b.WriteString(" default $scheme;\n")
	b.WriteString(" ~*https https;\n")
	b.WriteString(" ~*http http;\n")
	b.WriteString("}\n\n")

	fmt.Fprintf(&b, "map $gr_forwarded_proto_%d $gr_forwarded_port_%d {\n", siteID, siteID)
	b.WriteString(" default $server_port;\n")
	b.WriteString(" https 443;\n")
	b.WriteString(" http 80;\n")
	b.WriteString("}\n\n")

	fmt.Fprintf(&b, "map $gr_forwarded_proto_%d $gr_forwarded_ssl_%d {\n", siteID, siteID)
	b.WriteString(" default off;\n")
	b.WriteString(" https on;\n")
	b.WriteString("}\n\n")

	return b.String()
}

func renderMainServerBlock(
	site models.ServerConfiguration,
	serverNames []string,
	includePath string,
	policy models.DDoSPolicy,
	errorPages []resolvedErrorPage,
	transparentProxy bool,
) string {
	var b strings.Builder

	b.WriteString("server {\n")
	if site.SSL_Enabled == 1 {
		fmt.Fprintf(&b, " listen %d ssl http2;\n", site.Server_Port)
		fmt.Fprintf(&b, " listen [::]:%d ssl http2;\n", site.Server_Port)
	} else {
		fmt.Fprintf(&b, " listen %d;\n", site.Server_Port)
		fmt.Fprintf(&b, " listen [::]:%d;\n", site.Server_Port)
	}

	fmt.Fprintf(&b, " server_name %s;\n\n", strings.Join(serverNames, " "))
	b.WriteString(" set $gr_ray_id \"GR-$request_id\";\n")
	b.WriteString(" add_header X-Ray-ID $gr_ray_id always;\n")
	b.WriteString(" add_header Content-Security-Policy \"upgrade-insecure-requests\" always;\n")

	if site.SSL_Enabled == 1 && site.HSTS == 1 {
		b.WriteString(" add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n")
	}

	if site.SSL_Enabled == 1 {
		fmt.Fprintf(&b, " ssl_certificate %s;\n", site.Cert_Path)
		fmt.Fprintf(&b, " ssl_certificate_key %s;\n", site.Key_Path)
	}

	fmt.Fprintf(&b, " include %s;\n", includePath)

	if site.Proxy_Intercept_Errors == 1 {
		b.WriteString(" proxy_intercept_errors on;\n")
		for _, page := range errorPages {
			fmt.Fprintf(&b, " error_page %s /%s;\n", strings.Join(page.Codes, " "), page.Filename)
		}
	}

	b.WriteString("\n")

	if policy.Enabled && strings.EqualFold(policy.Mode, "challenge") {
		b.WriteString(renderChallengeLocation(site.ID, policy))
	}

	b.WriteString(" location / {\n")
	if policy.Enabled && strings.EqualFold(policy.Mode, "challenge") {
		fmt.Fprintf(&b, "  if ($gr_ddos_allow_%d = 0) { return 302 /__gr_challenge_%d?u=$request_uri; }\n", site.ID, site.ID)
	}
	if policy.Enabled && policy.RateLimit > 0 {
		fmt.Fprintf(&b, "  limit_req zone=gr_%d_req burst=%d nodelay;\n", site.ID, max(policy.Burst, 0))
	}
	if policy.Enabled && policy.ConnLimit > 0 {
		fmt.Fprintf(&b, "  limit_conn gr_%d_conn %d;\n", site.ID, policy.ConnLimit)
	}

	fmt.Fprintf(&b, "  proxy_pass http://%s:%d;\n", site.IP, site.Proxy_Pass_Port)
	b.WriteString("  proxy_http_version 1.1;\n")
	fmt.Fprintf(&b, "  proxy_connect_timeout %ds;\n", clampTimeout(site.Proxy_Connect_Timeout, 5))
	fmt.Fprintf(&b, "  proxy_read_timeout %ds;\n", clampTimeout(site.Proxy_Read_Timeout, 300))
	fmt.Fprintf(&b, "  proxy_send_timeout %ds;\n", clampTimeout(site.Proxy_Send_Timeout, 300))
	b.WriteString("  proxy_buffering off;\n")
	b.WriteString("  proxy_request_buffering off;\n")
	b.WriteString("  proxy_force_ranges on;\n")

	if site.Websockets == 1 {
		b.WriteString("  proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("  proxy_set_header Connection $connection_upgrade;\n")
	}

	b.WriteString("  proxy_set_header Host $host;\n")
	b.WriteString("  proxy_set_header X-Forwarded-Host $host;\n")
	b.WriteString("  proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	if transparentProxy {
		b.WriteString("  set $gr_proxy_bind_addr off;\n")
		b.WriteString("  if ($remote_addr !~ \":\") { set $gr_proxy_bind_addr $remote_addr; }\n")
		b.WriteString("  proxy_bind $gr_proxy_bind_addr transparent;\n")
	}
	fmt.Fprintf(&b, "  proxy_set_header X-Forwarded-Port $gr_forwarded_port_%d;\n", site.ID)
	fmt.Fprintf(&b, "  proxy_set_header X-Forwarded-Proto $gr_forwarded_proto_%d;\n", site.ID)
	fmt.Fprintf(&b, "  proxy_set_header X-Forwarded-Ssl $gr_forwarded_ssl_%d;\n", site.ID)
	fmt.Fprintf(&b, "  proxy_set_header Forwarded \"for=$proxy_add_x_forwarded_for;proto=$gr_forwarded_proto_%d;host=$host\";\n", site.ID)
	if site.SSL_Enabled == 1 || site.SSL_Redirect == 1 {
		b.WriteString("  proxy_redirect http:// https://;\n")
	}
	b.WriteString(" }\n")

	for _, page := range errorPages {
		fmt.Fprintf(&b, "\n location = /%s {\n", page.Filename)
		fmt.Fprintf(&b, "  root %s;\n", page.Path)
		fmt.Fprintf(&b, "  default_type %s;\n", page.DefaultType)
		b.WriteString("  sub_filter_types text/html;\n")
		b.WriteString("  sub_filter_once off;\n")
		b.WriteString("  sub_filter \"__GR_RAY_ID__\" $gr_ray_id;\n")
		b.WriteString("  gzip off;\n")
		fmt.Fprintf(&b, "  try_files /%s =404;\n", page.Filename)
		b.WriteString(" }\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func renderRedirectServerBlock(site models.ServerConfiguration, serverNames []string, includePath string) string {
	var b strings.Builder
	b.WriteString("server {\n")
	b.WriteString(" listen 80;\n")
	b.WriteString(" listen [::]:80;\n")
	fmt.Fprintf(&b, " server_name %s;\n", strings.Join(serverNames, " "))
	b.WriteString(" set $gr_ray_id \"GR-$request_id\";\n")
	b.WriteString(" add_header X-Ray-ID $gr_ray_id always;\n")
	fmt.Fprintf(&b, " include %s;\n", includePath)
	b.WriteString(" location / {\n")
	b.WriteString("  return 301 https://$host$request_uri;\n")
	b.WriteString(" }\n")
	b.WriteString("}\n")
	return b.String()
}

func renderChallengeLocation(siteID int, policy models.DDoSPolicy) string {
	if policy.ChallengeDelay <= 0 {
		policy.ChallengeDelay = 5
	}
	if policy.CookieTTL <= 0 {
		policy.CookieTTL = 3600
	}

	var b strings.Builder
	fmt.Fprintf(&b, " location = /__gr_challenge_%d {\n", siteID)
	b.WriteString("  default_type text/html;\n")
	b.WriteString("  add_header Cache-Control \"no-store\";\n")
	fmt.Fprintf(&b, "  add_header Set-Cookie \"gr_challenge_%d=1; Path=/; Max-Age=%d; SameSite=Lax\";\n", siteID, policy.CookieTTL)
	fmt.Fprintf(&b, "  return 200 %s;\n", strconv.Quote(ddosChallengeHTML(siteID, policy.ChallengeDelay, policy.CookieTTL)))
	b.WriteString(" }\n\n")
	return b.String()
}

func ddosChallengeHTML(siteID, challengeDelay, cookieTTL int) string {
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking your browser</title><style>:root{--bg0:#070b14;--bg1:#0b1220;--panel:#0f1a2b;--border:rgba(255,255,255,.08);--text:#e5e7eb;--muted:#9ca3af;--muted2:#6b7280;--accent:#f48120;--link:#93c5fd}*{box-sizing:border-box}html,body{height:100%%}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,"Apple Color Emoji","Segoe UI Emoji";background:linear-gradient(180deg,var(--bg0),var(--bg1));color:var(--text);overflow-x:hidden}body:before{content:"";position:fixed;inset:-20vmax;pointer-events:none;background:radial-gradient(1200px 700px at 18%% 6%%,rgba(244,129,32,.10),transparent 60%%),radial-gradient(1100px 650px at 92%% 10%%,rgba(59,130,246,.09),transparent 62%%),radial-gradient(900px 520px at 50%% 110%%,rgba(255,255,255,.04),transparent 60%%);filter:blur(18px);transform:translateZ(0);opacity:.95}main{position:relative;max-width:760px;margin:8vh auto;padding:24px}header{display:flex;align-items:center;gap:12px;margin-bottom:18px}.logo{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,var(--accent),#fb7185);display:grid;place-items:center;color:#070b14;font-weight:800;letter-spacing:.5px}.brand{display:flex;flex-direction:column;gap:2px}.brand .name{font-weight:800}.brand .tag{color:var(--muted);font-size:13px}.card{background:linear-gradient(180deg,rgba(255,255,255,.045),rgba(255,255,255,.02));border:1px solid var(--border);border-radius:14px;padding:24px;box-shadow:0 14px 40px rgba(0,0,0,.38);backdrop-filter:blur(6px)}.muted{color:var(--muted);font-size:14px;line-height:1.5}.title{font-weight:800;font-size:18px;letter-spacing:.2px}.status{display:flex;align-items:center;gap:10px;margin:18px 0;padding:12px 14px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}.spinner{width:18px;height:18px;border:3px solid rgba(229,231,235,.18);border-top-color:var(--accent);border-radius:50%%;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.hr{height:1px;background:rgba(255,255,255,.07);margin:16px 0}.footer{margin-top:18px;font-size:12px;color:var(--muted2);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.pill{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);color:var(--muted)}.dot{width:8px;height:8px;border-radius:50%%;background:var(--accent);box-shadow:0 0 0 3px rgba(244,129,32,.15)}a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}@media (min-height:900px){main{margin:10vh auto}}@media (prefers-reduced-motion:reduce){.spinner{animation:none}}</style></head><body><main><header><div class="logo">GR</div><div class="brand"><div class="name">GoResolver Security</div><div class="tag">DDoS protection check</div></div></header><div class="card"><div class="title">Checking your browser before accessing the site</div><div class="muted">This process is automatic. Your browser will redirect shortly.</div><div class="status"><div class="spinner"></div><div class="muted">Verifying your connection…</div></div><div class="muted">Please allow up to a few seconds.</div><div class="hr"></div><div class="muted">If you are seeing this page repeatedly, enable cookies and disable any blockers for this site.</div></div><div class="footer"><span class="pill"><span class="dot"></span>Protected by GoResolver</span><span class="muted">Performance &amp; security by GoResolver</span></div></main><script>document.cookie="gr_challenge_%d=1; path=/; max-age=%d";var u=new URLSearchParams(window.location.search).get("u")||"/";setTimeout(function(){window.location=u;},%d000);</script></body></html>`, siteID, cookieTTL, challengeDelay)
}

func resolveErrorPagesForSite(
	site models.ServerConfiguration,
	pages []models.ServerErrorPages,
	filesByID map[string]models.ServerErrorFiles,
) []resolvedErrorPage {
	mergedByCode := map[string]resolvedErrorPageFile{}

	for _, page := range pages {
		if !page.Enabled || page.Server_ID != site.ServerID || page.Site_ID != "*" {
			continue
		}
		if codes, file, ok := resolveErrorPage(page, filesByID); ok {
			for _, code := range codes {
				mergedByCode[code] = file
			}
		}
	}
	siteID := strconv.Itoa(site.ID)
	for _, page := range pages {
		if !page.Enabled || page.Server_ID != site.ServerID || page.Site_ID != siteID {
			continue
		}
		if codes, file, ok := resolveErrorPage(page, filesByID); ok {
			for _, code := range codes {
				mergedByCode[code] = file
			}
		}
	}

	grouped := map[string]*resolvedErrorPage{}
	for code, file := range mergedByCode {
		key := file.Filename + "\x00" + file.Path + "\x00" + file.DefaultType
		page := grouped[key]
		if page == nil {
			page = &resolvedErrorPage{
				Filename:    file.Filename,
				Path:        file.Path,
				DefaultType: file.DefaultType,
			}
			grouped[key] = page
		}
		page.Codes = append(page.Codes, code)
	}

	out := make([]resolvedErrorPage, 0, len(grouped))
	for _, page := range grouped {
		sort.Strings(page.Codes)
		out = append(out, *page)
	}
	sort.Slice(out, func(i, j int) bool {
		if strings.Join(out[i].Codes, " ") == strings.Join(out[j].Codes, " ") {
			return out[i].Filename < out[j].Filename
		}
		return strings.Join(out[i].Codes, " ") < strings.Join(out[j].Codes, " ")
	})
	return out
}

func resolveErrorPage(page models.ServerErrorPages, filesByID map[string]models.ServerErrorFiles) ([]string, resolvedErrorPageFile, bool) {
	file, ok := filesByID[page.ErrorPage_ID]
	if !ok {
		log.Printf("nginx config: error page file %q missing", page.ErrorPage_ID)
		return nil, resolvedErrorPageFile{}, false
	}

	codes, err := parseNginxErrorCodes(file.Error_Code)
	if err != nil {
		log.Printf("nginx config: invalid error code %q for file %q", file.Error_Code, file.ID)
		return nil, resolvedErrorPageFile{}, false
	}

	filename := strings.TrimSpace(file.Filename)
	if filename == "" || strings.ContainsAny(filename, "/\\\r\n;") || strings.Contains(filename, "..") {
		log.Printf("nginx config: invalid error page filename %q", file.Filename)
		return nil, resolvedErrorPageFile{}, false
	}

	path := strings.TrimSpace(file.Path)
	if path == "" || strings.ContainsAny(path, "\r\n;") {
		log.Printf("nginx config: invalid error page path %q", file.Path)
		return nil, resolvedErrorPageFile{}, false
	}

	return codes, resolvedErrorPageFile{
		Filename:    filename,
		Path:        path,
		DefaultType: nginxDefaultType(file.ResponseType),
	}, true
}

func parseNginxErrorCodes(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty error code")
	}
	if strings.ContainsAny(trimmed, "\r\n;") {
		return nil, fmt.Errorf("invalid separator in error code")
	}

	tokens := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty error code")
	}

	seen := make(map[string]struct{}, len(tokens))
	codes := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if len(token) != 3 {
			return nil, fmt.Errorf("invalid status code %q", token)
		}
		if strings.IndexFunc(token, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, fmt.Errorf("invalid status code %q", token)
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		codes = append(codes, token)
	}

	if len(codes) == 0 {
		return nil, fmt.Errorf("empty error code")
	}
	sort.Strings(codes)
	return codes, nil
}

func normalizeNginxErrorCodes(raw string) (string, error) {
	codes, err := parseNginxErrorCodes(raw)
	if err != nil {
		return "", err
	}
	return strings.Join(codes, " "), nil
}

func nginxDefaultType(responseType string) string {
	switch strings.ToLower(strings.TrimSpace(responseType)) {
	case "html":
		return "text/html"
	case "plain", "text", "txt":
		return "text/plain"
	case "css":
		return "text/css"
	case "xml":
		return "application/xml"
	case "json":
		return "application/json"
	case "js", "javascript":
		return "application/javascript"
	default:
		return "text/plain"
	}
}

func effectiveLetsEncryptConfigPath(path string) (string, error) {
	value := strings.TrimSpace(path)
	if value == "" {
		value = defaultLetsEncryptConfigFile
	}
	if strings.ContainsAny(value, "\r\n;") {
		return "", fmt.Errorf("invalid letsencrypt config path %q", path)
	}
	return value, nil
}

func validateServerNames(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("server_name is empty")
	}

	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("server_name is empty")
	}
	for _, part := range parts {
		if strings.ContainsAny(part, "\r\n;") {
			return nil, fmt.Errorf("invalid server_name token %q", part)
		}
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '.', r == '-', r == '_', r == '*':
			default:
				return nil, fmt.Errorf("invalid server_name token %q", part)
			}
		}
	}
	return parts, nil
}

func validateIP(ip string) error {
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" {
		return fmt.Errorf("empty ip")
	}
	if net.ParseIP(trimmed) == nil {
		return fmt.Errorf("invalid ip %q", ip)
	}
	return nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range", port)
	}
	return nil
}

func clampTimeout(value, min int) int {
	if value < min {
		return min
	}
	return value
}

func renderDefaultDenyConfig(certPath, keyPath, letsEncryptConfigPath string) string {
	body := strconv.Quote(defaultDenyBody())

	var b strings.Builder
	b.WriteString("server {\n")
	b.WriteString("    listen 80 default_server;\n")
	b.WriteString("    listen [::]:80 default_server;\n")
	b.WriteString("    server_name _;\n")
	b.WriteString("    set $gr_ray_id \"GR-$request_id\";\n")
	b.WriteString("    add_header X-Ray-ID $gr_ray_id always;\n")
	if letsEncryptConfigPath != "" {
		fmt.Fprintf(&b, "    include %s;\n", letsEncryptConfigPath)
	}
	b.WriteString("    location / {\n")
	b.WriteString("        default_type text/html;\n")
	fmt.Fprintf(&b, "        return 403 %s;\n", body)
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("server {\n")
	b.WriteString("    listen 443 ssl http2 default_server;\n")
	b.WriteString("    listen [::]:443 ssl http2 default_server;\n")
	b.WriteString("    server_name _;\n")
	b.WriteString("    set $gr_ray_id \"GR-$request_id\";\n")
	b.WriteString("    add_header X-Ray-ID $gr_ray_id always;\n")
	fmt.Fprintf(&b, "    ssl_certificate %s;\n", certPath)
	fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", keyPath)
	b.WriteString("    location / {\n")
	b.WriteString("        default_type text/html;\n")
	fmt.Fprintf(&b, "        return 403 %s;\n", body)
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func defaultDenyBody() string {
	return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access blocked</title><style>body{margin:0;font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0}main{max-width:720px;margin:10vh auto;padding:24px}h1{font-size:22px;margin:0 0 8px}p{color:#94a3b8;margin:0 0 16px}a{color:#38bdf8;text-decoration:none}.card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:24px}.badge{display:inline-block;background:#ef4444;color:#fff;padding:4px 8px;border-radius:999px;font-size:12px}</style></head><body><main><div class="card"><div class="badge">Access denied</div><h1>Access via IP not allowed</h1><p>This host only serves configured domains. Please use a valid hostname.</p></div></main></body></html>`
}
