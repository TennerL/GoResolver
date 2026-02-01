package services

import (
	"database/sql"
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"crypto"
	"crypto/rsa"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"path/filepath"
	"time"
	"strconv"
	"strings"
	"sort"
	"math/big"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-acme/lego/v4/challenge/http01"
)

type ServerConfigurationService struct{}

// 32-byte AES-256 key
var aesKey = []byte("12345678901234567890123456789012") // Replace with secure key in production

func NewServerConfigurationService() *ServerConfigurationService {
	return &ServerConfigurationService{}
}

func (s *ServerConfigurationService) GetServerConfiguration(serverID string) []models.ServerConfiguration {
	rows, err := db.DB.Query(`
		SELECT
			sc.id,
			sc.server_name,
			sc.server_port,
			sc.ssl_enabled,
			sc.ssl_redirect,
			sc.proxy_pass_port,
			sc.proxy_intercept_errors,
			sc.proxy_connect_timeout,
			sc.proxy_read_timeout,
			sc.proxy_send_timeout,
			sc.websockets,
			s.ip,
			s.vpn_file,
			s.port,
			s.name,
			IFNULL(c.cert_path, ''),
			IFNULL(c.key_path, ''),
			IFNULL(c.updated_at, ''),
			IFNULL(c.expires_at, '')
		FROM server_configuration sc
		LEFT JOIN servers s ON s.id = sc.fk_server
        LEFT JOIN certificates c ON c.site_id = sc.id
		WHERE sc.fk_server = ?
		ORDER BY sc.id
	`, serverID)
	if err != nil {
		log.Println("SELECT serverconfig failed:", err)
		return nil
	}
	defer rows.Close()

	var serverConfigurations []models.ServerConfiguration

	for rows.Next() {
	var sc models.ServerConfiguration
	//var vpnBlob sql.NullBytes
	var vpnBlob []byte

	if err := rows.Scan(
		&sc.ID,
		&sc.Server_Name,
		&sc.Server_Port,
		&sc.SSL_Enabled,
		&sc.SSL_Redirect,
		&sc.Proxy_Pass_Port,
		&sc.Proxy_Intercept_Errors,
		&sc.Proxy_Connect_Timeout,
		&sc.Proxy_Read_Timeout,
		&sc.Proxy_Send_Timeout,
		&sc.Websockets,
		&sc.IP,
		&vpnBlob,
		&sc.Port,
		&sc.Name,
		&sc.Cert_Path,
		&sc.Key_Path,
		&sc.Cert_Issued,
		&sc.Cert_Expiration,
	); err != nil {
		log.Println("Row scan error:", err)
		continue
	}

	if len(vpnBlob) > 0 {
		decrypted, err := DecryptVPN(vpnBlob)
		if err != nil {
			sc.VPN_File = nil
		} else {
			sc.VPN_File = decrypted
		}
	} else {
		sc.VPN_File = nil
	}


	serverConfigurations = append(serverConfigurations, sc)
	}
	return serverConfigurations
}

func (s *ServerConfigurationService) GetServerBasics(serverID string) (models.Server, error) {
	var srv models.Server
	var vpnBlob []byte
	err := db.DB.QueryRow(`
		SELECT id, name, ip, vpn_file
		FROM servers
		WHERE id = ?
	`, serverID).Scan(&srv.ID, &srv.Name, &srv.IP, &vpnBlob)
	if err != nil {
		return srv, err
	}

	if len(vpnBlob) > 0 {
		decrypted, err := DecryptVPN(vpnBlob)
		if err == nil {
			srv.VPN_File = string(decrypted)
		}
	}

	return srv, nil
}

func (s *ServerConfigurationService) EnsureDDoSTables() error {
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS ddos_policies (
			server_id INT PRIMARY KEY,
			enabled TINYINT(1) NOT NULL DEFAULT 0,
			mode VARCHAR(16) NOT NULL DEFAULT 'off',
			preset VARCHAR(16) NOT NULL DEFAULT 'medium',
			rate_limit INT NOT NULL DEFAULT 0,
			burst INT NOT NULL DEFAULT 0,
			conn_limit INT NOT NULL DEFAULT 0,
			syn_rate INT NOT NULL DEFAULT 0,
			syn_burst INT NOT NULL DEFAULT 0,
			challenge_delay INT NOT NULL DEFAULT 5,
			cookie_ttl INT NOT NULL DEFAULT 3600,
			whitelist TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	_, _ = db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS ddos_overrides (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			server_id INT NOT NULL,
			path_pattern VARCHAR(255) NOT NULL,
			mode VARCHAR(16) NOT NULL DEFAULT 'off',
			rate_limit INT NOT NULL DEFAULT 0,
			burst INT NOT NULL DEFAULT 0,
			conn_limit INT NOT NULL DEFAULT 0,
			syn_rate INT NOT NULL DEFAULT 0,
			syn_burst INT NOT NULL DEFAULT 0,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX (server_id)
		)
	`)
	return nil
}

func (s *ServerConfigurationService) GetDDoSPolicy(serverID string) (models.DDoSPolicy, error) {
	if err := s.EnsureDDoSTables(); err != nil {
		return models.DDoSPolicy{}, err
	}

	var p models.DDoSPolicy
	var enabled int
	err := db.DB.QueryRow(`
		SELECT server_id, enabled, mode, preset, rate_limit, burst, conn_limit, syn_rate, syn_burst, challenge_delay, cookie_ttl, IFNULL(whitelist, '')
		FROM ddos_policies
		WHERE server_id = ?
	`, serverID).Scan(
		&p.ServerID,
		&enabled,
		&p.Mode,
		&p.Preset,
		&p.RateLimit,
		&p.Burst,
		&p.ConnLimit,
		&p.SynRate,
		&p.SynBurst,
		&p.ChallengeDelay,
		&p.CookieTTL,
		&p.Whitelist,
	)
	if err == sql.ErrNoRows {
		return models.DDoSPolicy{
			ServerID:       serverID,
			Enabled:        false,
			Mode:           "off",
			Preset:         "medium",
			ChallengeDelay: 5,
			CookieTTL:      3600,
		}, nil
	}
	if err != nil {
		return models.DDoSPolicy{}, err
	}
	p.Enabled = enabled == 1
	return p, nil
}

func (s *ServerConfigurationService) SaveDDoSPolicy(p models.DDoSPolicy) error {
	if err := s.EnsureDDoSTables(); err != nil {
		return err
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}

	_, err := db.DB.Exec(`
		INSERT INTO ddos_policies (
			server_id, enabled, mode, preset, rate_limit, burst, conn_limit, syn_rate, syn_burst, challenge_delay, cookie_ttl, whitelist
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			enabled = VALUES(enabled),
			mode = VALUES(mode),
			preset = VALUES(preset),
			rate_limit = VALUES(rate_limit),
			burst = VALUES(burst),
			conn_limit = VALUES(conn_limit),
			syn_rate = VALUES(syn_rate),
			syn_burst = VALUES(syn_burst),
			challenge_delay = VALUES(challenge_delay),
			cookie_ttl = VALUES(cookie_ttl),
			whitelist = VALUES(whitelist)
	`,
		p.ServerID, enabled, p.Mode, p.Preset, p.RateLimit, p.Burst, p.ConnLimit, p.SynRate, p.SynBurst, p.ChallengeDelay, p.CookieTTL, p.Whitelist,
	)
	return err
}

func (s *ServerConfigurationService) ApplyDDoSIptables(serverID string, p models.DDoSPolicy) error {
	if serverID == "" {
		return nil
	}
	var ip string
	if err := db.DB.QueryRow(`SELECT ip FROM servers WHERE id = ?`, serverID).Scan(&ip); err != nil {
		return err
	}
	if ip == "" {
		return nil
	}

	comments := []string{
		fmt.Sprintf("GoResolver:DDoS:%s:RL80", serverID),
		fmt.Sprintf("GoResolver:DDoS:%s:RL443", serverID),
		fmt.Sprintf("GoResolver:DDoS:%s:CL80", serverID),
		fmt.Sprintf("GoResolver:DDoS:%s:CL443", serverID),
		fmt.Sprintf("GoResolver:DDoS:%s:SYN80", serverID),
		fmt.Sprintf("GoResolver:DDoS:%s:SYN443", serverID),
	}
	for _, comment := range comments {
		_ = s.DeleteRuleByComment("INPUT", "filter", comment)
	}

	if !p.Enabled {
		return nil
	}

	ports := []int{80, 443}
	for _, port := range ports {
		if p.ConnLimit > 0 {
			cl := p.ConnLimit
			if err := s.AddRule(models.IPTablesRuleSpec{
				Table:    "filter",
				Chain:    "INPUT",
				Action:   "append",
				Protocol: "tcp",
				DestIP:   ip,
				DestPort: port,
				ConnLimit: &cl,
				Target:   "DROP",
				Comment:  fmt.Sprintf("GoResolver:DDoS:%s:CL%d", serverID, port),
			}); err != nil {
				return err
			}
		}

		if p.RateLimit > 0 {
			args := []string{
				"-m", "hashlimit",
				"--hashlimit-above", fmt.Sprintf("%d/second", p.RateLimit),
				"--hashlimit-burst", strconv.Itoa(max(1, p.Burst)),
				"--hashlimit-mode", "srcip",
				"--hashlimit-name", fmt.Sprintf("gr_%s_rl_%d", serverID, port),
			}
			if err := s.AddRule(models.IPTablesRuleSpec{
				Table:    "filter",
				Chain:    "INPUT",
				Action:   "append",
				Protocol: "tcp",
				DestIP:   ip,
				DestPort: port,
				ExtraArgs: args,
				Target:   "DROP",
				Comment:  fmt.Sprintf("GoResolver:DDoS:%s:RL%d", serverID, port),
			}); err != nil {
				return err
			}
		}

		if p.SynRate > 0 {
			args := []string{
				"-m", "hashlimit",
				"--hashlimit-above", fmt.Sprintf("%d/second", p.SynRate),
				"--hashlimit-burst", strconv.Itoa(max(1, p.SynBurst)),
				"--hashlimit-mode", "srcip",
				"--hashlimit-name", fmt.Sprintf("gr_%s_syn_%d", serverID, port),
			}
			if err := s.AddRule(models.IPTablesRuleSpec{
				Table:    "filter",
				Chain:    "INPUT",
				Action:   "append",
				Protocol: "tcp",
				SynOnly:  true,
				DestIP:   ip,
				DestPort: port,
				ExtraArgs: args,
				Target:   "DROP",
				Comment:  fmt.Sprintf("GoResolver:DDoS:%s:SYN%d", serverID, port),
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *ServerConfigurationService) InsertServerConfiguration(sc models.ServerConfiguration) error {
	result, err := db.DB.Exec(`
		INSERT INTO server_configuration (
			fk_server,
			server_name,
			server_port,
			ssl_enabled,
			ssl_redirect,
			proxy_pass_port,
			proxy_intercept_errors,
			websockets
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		sc.ServerID,
		sc.Server_Name,
		sc.Server_Port,
		sc.SSL_Enabled,
		sc.SSL_Redirect,
		sc.Proxy_Pass_Port,
		sc.Proxy_Intercept_Errors,
		sc.Websockets,
	)

	if err != nil {
		log.Println("INSERT server_configuration failed:", err)
		return err
	}

	rows, _ := result.RowsAffected()
	log.Println("Rows inserted into server_configuration:", rows)
	DeployNginxConfig(sc.Server_Name)

	return nil
}

func (s *ServerConfigurationService) UpdateServerConfiguration(sc models.ServerConfiguration) error {
	result, err := db.DB.Exec(`
		UPDATE server_configuration SET
			server_name = ?,
			server_port = ?,
			ssl_enabled = ?,
			ssl_redirect = ?,
			proxy_pass_port = ?,
			proxy_intercept_errors = ?,
			websockets = ?
		WHERE id = ?`,
		sc.Server_Name,
		sc.Server_Port,
		sc.SSL_Enabled,
		sc.SSL_Redirect,
		sc.Proxy_Pass_Port,
		sc.Proxy_Intercept_Errors,
		sc.Websockets,
		sc.ID,
	)
	if err != nil {
		log.Println("UPDATE server_configuration failed:", err)
		return err
	}
	rows, _ := result.RowsAffected()
	log.Println("Rows affected in server_configuration:", rows)
	DeployNginxConfig(sc.Server_Name)

	encryptedVPN, err := EncryptVPN(sc.VPN_File)
	if err != nil {
		log.Println("Encryption failed:", err)
		return err
	}

	updateQuery := `UPDATE servers SET name = ?, vpn_file = ? WHERE id = ?`
	updateArgs := []any{sc.Name, encryptedVPN, sc.ServerID}
	if sc.IP != "" {
		updateQuery = `UPDATE servers SET name = ?, ip = ?, vpn_file = ? WHERE id = ?`
		updateArgs = []any{sc.Name, sc.IP, encryptedVPN, sc.ServerID}
	}

	result2, err := db.DB.Exec(updateQuery, updateArgs...)
	if err != nil {
		log.Println("UPDATE servers failed:", err)
		return err
	}
	rows2, _ := result2.RowsAffected()
	log.Println("Rows affected in servers:", rows2)

	return nil
}

func (s *ServerConfigurationService) GetServerErrorPages(serverID string) []models.ServerErrorPages {
	rows, err := db.DB.Query(`
		SELECT 
			ep.id,
			ep.server_id,
			ep.site_id,
			ep.error_page_id,
			IFNULL(sc.server_name, '*'),
			ef.Filename as Name,
			ep.enabled,
			ep.is_default
		FROM error_pages ep
		LEFT JOIN error_page_files ef ON ef.id = ep.error_page_id
        LEFT JOIN server_configuration sc ON sc.id = ep.site_id
		WHERE ep.server_id = ? OR ep.site_id = '*'
	`, serverID)
	if err != nil {
		log.Println("SELECT error_pages failed:", err)
		return nil
	}
	defer rows.Close()

	var pages []models.ServerErrorPages

	for rows.Next() {
		var ep models.ServerErrorPages
		if err := rows.Scan(
			&ep.ID,
			&ep.Server_ID,
			&ep.Site_ID,
			&ep.ErrorPage_ID,
			&ep.Server_Name,
			&ep.Name,
			&ep.Enabled,
			&ep.Is_Default,
		); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		pages = append(pages, ep)
	}
	return pages
}

func (s *ServerConfigurationService) GetServerErrorFiles() []models.ServerErrorFiles {
		rows, err := db.DB.Query(`
		SELECT  id,
				error_code,
				response_type,
				filename,
				file,
				path
		FROM error_page_files 
		ORDER BY updated_at
	`,)
	if err != nil {
		log.Println("SELECT error_page_files failed:", err)
		return nil
	}
	defer rows.Close()

	var epfiles []models.ServerErrorFiles

	for rows.Next() {
		var ef models.ServerErrorFiles
		if err := rows.Scan(
			&ef.ID,
			&ef.Error_Code,
			&ef.ResponseType,
			&ef.Filename,
			&ef.File,
			&ef.Path,
		); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		epfiles = append(epfiles, ef)
	}
	return epfiles
}

func (s *ServerConfigurationService) SaveErrorPage(ep models.ServerErrorPages) error {
	_, err := db.DB.Exec(`
		UPDATE error_pages SET
			enabled = ?,
			error_page_id = ? 
		WHERE id = ?
	`,
		ep.Enabled,
		ep.ErrorPage_ID,
		ep.ID,
	)
	if err != nil {
		log.Println("UPDATE error_page failed:", err)
		return err
	}
	return nil
}
func (s *ServerConfigurationService) InsertErrorPage(ep models.ServerErrorPages) error {
	_, err := db.DB.Exec(`
		INSERT INTO error_pages (
			id, server_id,
			site_id, error_page_id,
			enabled 
		) VALUES (UUID(), ?, ?, ?, ?)
	`,
		ep.Server_ID,
		ep.Site_ID,
		ep.ErrorPage_ID,
		ep.Enabled,
	)
	if err != nil {
		log.Println("INSERT error_page failed:",err)
		return err
	}
	return nil 
}

func (s *ServerConfigurationService) UploadErrorPage(ef models.ServerErrorFiles) error {
	_, err := db.DB.Exec(`
		INSERT INTO error_page_files (
			id, 
			error_code, response_type,
			filename, file 
		) VALUES (UUID(), ?, ?, ?, ?)
	`,
		ef.Error_Code,
		ef.ResponseType,
		ef.Filename,
		ef.File,
	)
	if err != nil {
		log.Println("INSERT error_page failed:", err)
		return err
	}

	if ef.Path == "" {
		return nil 
	}

	path := filepath.Join(ef.Path, ef.Filename)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Println("mkdir failed:", err)
		return err
	}

	if err := os.WriteFile(path, ef.File, 0644); err != nil {
		return err
	}

	return nil
}
func (s *ServerConfigurationService) UpdateErrorFiles(ef models.ServerErrorFiles) error {
	_, err := db.DB.Exec(`
		UPDATE error_page_files 
		SET error_code = ?, response_type = ? 
		WHERE id = ?
	`,
	ef.Error_Code,
	ef.ResponseType,
	ef.ID,
	)
	if err != nil {
		log.Println("Update error_page_files failed:", err)
	}
	return err 
}

func (s *ServerConfigurationService) DeleteErrorPage(id string) error {
	_, err := db.DB.Exec(`
		DELETE FROM error_pages WHERE id = ?
	`, id)

	if err != nil {
		log.Println("DELETE error_page failed:", err)
	}
	return err
}

func (s *ServerConfigurationService) DeleteErrorFile(ef models.ServerErrorFiles) error {
	_, err := db.DB.Exec(`
		DELETE FROM error_page_files WHERE id = ?
	`, ef.ID)

	if err != nil {
		log.Println("DELETE FROM error_page_files failed:", err)
	}
	

	efPath  := filepath.Join(ef.Path, ef.Filename)

	if err := os.Remove(efPath); err != nil {
		log.Fatal(err)
	}
	return err

}

func (s *ServerConfigurationService) GetErrorFile(id string) ([]byte, error) {
	var content []byte
	err := db.DB.QueryRow(`
		SELECT file FROM error_page_files WHERE id = ?
	`, id).Scan(&content)
	if err != nil {
		log.Println("GetErrorFile failed:", err)
		return nil, err
	}
	return content, nil
}

func (s *ServerConfigurationService) UpdateErrorFile(id string, content []byte) error {
	_, err := db.DB.Exec(`
		UPDATE error_page_files
		SET file = ?
		WHERE id = ?
	`, content, id)
	if err != nil {
		log.Println("UpdateErrorFile DB failed:", err)
		return err
	}

	var path, filename string
	err = db.DB.QueryRow(`
		SELECT path, filename
		FROM error_page_files
		WHERE id = ?
	`, id).Scan(&path, &filename)
	if err != nil {
		log.Println("Fetching path/filename failed:", err)
		return err
	}

	if path == "" || filename == "" {
		return nil
	}

	fullPath := filepath.Join(path, filename)

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Println("MkdirAll failed:", err)
		return err
	}

	if err := os.WriteFile(fullPath, content, 0644); err != nil {
		log.Println("WriteFile failed:", err)
		return err
	}

	return nil
}


func GenerateNginxConfig(SiteName string) (string, error) {
	var config string

	if err := NewServerConfigurationService().EnsureDDoSTables(); err != nil {
		return "", err
	}

	err := db.DB.QueryRow(`
		SELECT 
		GROUP_CONCAT(site_config SEPARATOR '\n\n') AS nginx_config
		FROM (
		SELECT 
			CONCAT(
			-- Websockets map if enabled
			IF(sc.websockets = 1, 
				'map $http_upgrade $connection_upgrade {\n default upgrade;\n ''''      close;\n}\n\n', 
				''
			),

			-- DDoS zones and challenge map
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.rate_limit, 0) > 0
				AND sc.id = (SELECT MIN(id) FROM server_configuration WHERE server_name = sc.server_name),
				CONCAT('limit_req_zone $binary_remote_addr zone=gr_', sc.id, '_req:10m rate=', dp.rate_limit, 'r/s;\n'),
				''
			),
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.conn_limit, 0) > 0
				AND sc.id = (SELECT MIN(id) FROM server_configuration WHERE server_name = sc.server_name),
				CONCAT('limit_conn_zone $binary_remote_addr zone=gr_', sc.id, '_conn:10m;\n'),
				''
			),
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.mode, '') = 'challenge'
				AND sc.id = (SELECT MIN(id) FROM server_configuration WHERE server_name = sc.server_name),
				CONCAT(
					'map $cookie_gr_challenge_', sc.id, ' $gr_challenge_valid_', sc.id, ' {\n',
					' default 0;\n',
					' \"1\" 1;\n',
					'}\n\n'
				),
				''
			),

			-- Main server block
			'server {\n',
			IF(sc.ssl_enabled = 0, CONCAT(' listen ', sc.server_port, ';\n'), ''),
			IF(sc.ssl_enabled = 1, CONCAT(
				' listen ', sc.server_port, ' ssl http2;\n',
				' listen [::]:', sc.server_port, ' ssl http2;\n'
			), ''),
			' server_name ', IFNULL(sc.server_name, ''), ';\n\n',
			' set $gr_ray_id \"GR-$request_id\";\n',
			' add_header X-Ray-ID $gr_ray_id always;\n',

			-- SSL certificate if enabled
			IF(sc.ssl_enabled = 1, CONCAT(
				' ssl_certificate ', c.cert_path, ';\n',
				' ssl_certificate_key ', c.key_path, ';\n'
			), ''),

			' include ', sc.letsencrypt_config_file, ';\n',

			-- Proxy error intercept
			IF(sc.proxy_intercept_errors = 1, ' proxy_intercept_errors on;\n\n', ''),

			-- DDoS challenge location
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.mode, '') = 'challenge',
				CONCAT(
					' location = /__gr_challenge_', sc.id, ' {\n',
					'  default_type text/html;\n',
					'  add_header Cache-Control \"no-store\";\n',
					'  add_header Set-Cookie \"gr_challenge_', sc.id, '=1; Path=/; Max-Age=', IFNULL(dp.cookie_ttl, 3600), '; SameSite=Lax\";\n',
					'  return 200 \"<!doctype html><html><head><meta charset=\\\"utf-8\\\"><meta name=\\\"viewport\\\" content=\\\"width=device-width,initial-scale=1\\\"><title>Checking your browser</title><style>body{margin:0;font-family:Arial,sans-serif;background:#f5f7fb;color:#111827}main{max-width:720px;margin:8vh auto;padding:24px}header{display:flex;align-items:center;gap:12px;margin-bottom:18px}.logo{width:40px;height:40px;border-radius:8px;background:linear-gradient(135deg,#f97316,#f43f5e);display:grid;place-items:center;color:#fff;font-weight:700}.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px;box-shadow:0 6px 16px rgba(15,23,42,.08)}.muted{color:#6b7280;font-size:14px} .status{display:flex;align-items:center;gap:10px;margin:18px 0} .spinner{width:18px;height:18px;border:3px solid #e5e7eb;border-top-color:#2563eb;border-radius:50%;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}} .footer{margin-top:18px;font-size:12px;color:#9ca3af}</style></head><body><main><header><div class=\\\"logo\\\">GR</div><div><div style=\\\"font-weight:700\\\">GoResolver Security</div><div class=\\\"muted\\\">DDoS protection check</div></div></header><div class=\\\"card\\\"><div style=\\\"font-weight:700;font-size:18px\\\">Checking your browser before accessing the site</div><div class=\\\"muted\\\">This process is automatic. Your browser will redirect shortly.</div><div class=\\\"status\\\"><div class=\\\"spinner\\\"></div><div class=\\\"muted\\\">Analyzing request...</div></div><div class=\\\"muted\\\">Please allow up to a few seconds.</div></div><div class=\\\"footer\\\">Protected by GoResolver</div></main><script>document.cookie=\\\"gr_challenge_', sc.id, '=1; path=/; max-age=', IFNULL(dp.cookie_ttl, 3600), '\\\";var u=new URLSearchParams(window.location.search).get(\\\"u\\\")||\\\"/\\\";setTimeout(function(){window.location=u;},', IFNULL(dp.challenge_delay, 5), '000);</script></body></html>\";\n',
					' }\n\n'
				),
				''
			),

			-- Main location
			' location / {\n',
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.mode, '') = 'challenge',
				CONCAT('  if ($gr_challenge_valid_', sc.id, ' = 0) { return 302 /__gr_challenge_', sc.id, '?u=$request_uri; }\n'),
				''
			),
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.rate_limit, 0) > 0,
				CONCAT('  limit_req zone=gr_', sc.id, '_req burst=', IFNULL(dp.burst, 0), ' nodelay;\n'),
				''
			),
			IF(IFNULL(dp.enabled, 0) = 1 AND IFNULL(dp.conn_limit, 0) > 0,
				CONCAT('  limit_conn gr_', sc.id, '_conn ', IFNULL(dp.conn_limit, 0), ';\n'),
				''
			),
			' proxy_pass http://', IFNULL(s.ip, ''), ':', IFNULL(sc.proxy_pass_port, ''), ';\n',
			IF(sc.proxy_intercept_errors = 1, CONCAT(
				' proxy_connect_timeout ', sc.proxy_connect_timeout, 's;\n',
				' proxy_read_timeout ', sc.proxy_read_timeout, 's;\n',
				' proxy_send_timeout ', sc.proxy_send_timeout, 's;\n'
			), ''),
			IF(sc.websockets = 1, 
				' proxy_http_version 1.1;\n proxy_set_header Upgrade $http_upgrade;\n proxy_set_header Connection $connection_upgrade;\n', 
				''
			),
			' proxy_set_header Host $host;\n',
			' proxy_set_header X-Forwarded-For $remote_addr;\n',
			' proxy_set_header X-Forwarded-Proto https;\n',

			-- Error pages directives
			IF(sc.proxy_intercept_errors = 1, CONCAT(
				GROUP_CONCAT(
				CONCAT(' error_page ', ef.error_code, ' /', ef.Filename, ';\n') SEPARATOR ''
				)
			, ''), ''),

			' }\n\n',

			IF(sc.proxy_intercept_errors = 1, CONCAT(
				GROUP_CONCAT(
				CONCAT(
					' location /', ef.Filename, ' {\n',
					' root ', ef.Path, ';\n',
					' default_type text/',ef.response_type,';\n',
					' sub_filter_types text/html;\n',
					' sub_filter_once off;\n',
					' sub_filter \"__GR_RAY_ID__\" $gr_ray_id;\n',
					' gzip off;\n',
					' try_files /', ef.Filename, ' =404;\n',
					' }\n'
				) SEPARATOR '\n'
				)
			, ''), ''),

			'}\n\n',

			-- SSL redirect server
			IF(sc.ssl_redirect = 1, CONCAT(
				'server {\n',
				' listen 80;\n listen [::]:80;\n',
				' server_name ', sc.server_name, ';\n',
				' return 301 https://$host$request_uri;\n',
				'}'
			), '')
			) AS site_config
		FROM server_configuration sc
		LEFT JOIN servers s ON s.id = sc.fk_server
		LEFT JOIN ddos_policies dp ON dp.server_id = s.id
		LEFT JOIN certificates c ON c.site_id = sc.id
		LEFT JOIN error_pages ep ON ep.server_id = sc.fk_server AND ep.site_id = sc.id OR ep.site_id = '*'
        LEFT JOIN error_page_files ef ON ef.id = ep.error_page_id
		WHERE sc.server_name = ?
		) t

	`, SiteName).Scan(&config)

	if err != nil {
		return "", err
	}

	return config, nil
}

// func (s *ServerConfigurationService) DeployNginxConfig(serverName string) error {
func DeployNginxConfig(serverName string) error {
	config, err := GenerateNginxConfig(serverName)
	if err != nil {
		return fmt.Errorf("generate config failed: %w", err)
	}

	serverName = strings.ReplaceAll(serverName, " ", "_")

	settings := NewSettingsService()
	availablePath := filepath.Join(settings.GetValue("paths.nginx_sites_available"), serverName)
	enabledPath := filepath.Join(settings.GetValue("paths.nginx_sites_enabled"), serverName)

	if err := os.WriteFile(availablePath, []byte(config), 0644); err != nil {
		return fmt.Errorf("write config failed: %w", err)
	}

	if _, err := os.Lstat(enabledPath); os.IsNotExist(err) {
		if err := os.Symlink(availablePath, enabledPath); err != nil {
			return fmt.Errorf("symlink failed: %w", err)
		}
	}

	if err := ensureDefaultDenySite(); err != nil {
		return fmt.Errorf("default deny config failed: %w", err)
	}
	if err := ensureNginxLogFormat(); err != nil {
		return fmt.Errorf("nginx log config failed: %w", err)
	}

	testCmd := exec.Command("nginx", "-t")
	testOut, err := testCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed:\n%s", string(testOut))
	}

	reloadCmd := exec.Command("nginx", "-s", "reload")
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload failed:\n%s", string(out))
	}

	return nil
}

func ensureNginxLogFormat() error {
	settings := NewSettingsService()
	confDir := settings.GetValue("paths.nginx_conf_d")
	if confDir == "" {
		confDir = "/etc/nginx/conf.d"
	}
	logPath := settings.GetValue("logging.nginx_access_json")
	if logPath == "" {
		return nil
	}
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return err
	}

	configPath := filepath.Join(confDir, "gresolver_log_format.conf")
	config := `log_format gr_json escape=json
'["$time_iso8601", {"time":"$time_iso8601","remote_addr":"$remote_addr","x_forwarded_for":"$http_x_forwarded_for","method":"$request_method","uri":"$request_uri","status":$status,"bytes":$body_bytes_sent,"referer":"$http_referer","user_agent":"$http_user_agent","request_time":$request_time,"upstream_time":"$upstream_response_time","host":"$host","ray_id":"$gr_ray_id"}]';

access_log ` + logPath + ` gr_json;` + "\n"

	return os.WriteFile(configPath, []byte(config), 0644)
}

func ensureDefaultDenySite() error {
	settings := NewSettingsService()
	availablePath := filepath.Join(settings.GetValue("paths.nginx_sites_available"), "00-default-deny")
	enabledPath := filepath.Join(settings.GetValue("paths.nginx_sites_enabled"), "00-default-deny")

	certPath, keyPath, err := ensureDefaultDenyCert()
	if err != nil {
		return err
	}

	config := `server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    set $gr_ray_id "GR-$request_id";
    add_header X-Ray-ID $gr_ray_id always;
    default_type text/html;
    return 403 "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Access blocked</title><style>body{margin:0;font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0}main{max-width:720px;margin:10vh auto;padding:24px}h1{font-size:22px;margin:0 0 8px}p{color:#94a3b8;margin:0 0 16px}a{color:#38bdf8;text-decoration:none} .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:24px} .badge{display:inline-block;background:#ef4444;color:#fff;padding:4px 8px;border-radius:999px;font-size:12px}</style></head><body><main><div class=\"card\"><div class=\"badge\">Access denied</div><h1>Access via IP not allowed</h1><p>This host only serves configured domains. Please use a valid hostname.</p></div></main></body></html>";
}
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    set $gr_ray_id "GR-$request_id";
    add_header X-Ray-ID $gr_ray_id always;
    ssl_certificate ` + certPath + `;
    ssl_certificate_key ` + keyPath + `;
    default_type text/html;
    return 403 "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Access blocked</title><style>body{margin:0;font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0}main{max-width:720px;margin:10vh auto;padding:24px}h1{font-size:22px;margin:0 0 8px}p{color:#94a3b8;margin:0 0 16px}a{color:#38bdf8;text-decoration:none} .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:24px} .badge{display:inline-block;background:#ef4444;color:#fff;padding:4px 8px;border-radius:999px;font-size:12px}</style></head><body><main><div class=\"card\"><div class=\"badge\">Access denied</div><h1>Access via IP not allowed</h1><p>This host only serves configured domains. Please use a valid hostname.</p></div></main></body></html>";
}
`

	if err := os.WriteFile(availablePath, []byte(config), 0644); err != nil {
		return err
	}
	if _, err := os.Lstat(enabledPath); os.IsNotExist(err) {
		if err := os.Symlink(availablePath, enabledPath); err != nil {
			return err
		}
	}
	return nil
}

func ensureDefaultDenyCert() (string, string, error) {
	settings := NewSettingsService()
	sslDir := settings.GetValue("paths.ssl_dir")
	if sslDir == "" {
		sslDir = "/etc/ssl"
	}
	certPath := filepath.Join(sslDir, "gr-default-deny.crt")
	keyPath := filepath.Join(sslDir, "gr-default-deny.key")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}

	if err := os.MkdirAll(sslDir, 0755); err != nil {
		return "", "", err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "GoResolver Default Deny",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:  []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

func DeleteNginxConfig(serverName string) error {
	serverName = strings.ReplaceAll(serverName, " ", "_")

	settings := NewSettingsService()
	availablePath := filepath.Join(settings.GetValue("paths.nginx_sites_available"), serverName)
	enabledPath := filepath.Join(settings.GetValue("paths.nginx_sites_enabled"), serverName)

	if err := os.Remove(availablePath); err != nil {
		return fmt.Errorf("Delete from sites-avaliable failed.")
	}

	if err := os.Remove(enabledPath); err != nil {
		return fmt.Errorf("Delete from sites-enabled failed.")
	}

	testCmd := exec.Command("nginx", "-t")
	testOut, err := testCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed:\n%s", string(testOut))
	}

	reloadCmd := exec.Command("nginx", "-s", "reload")
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload failed:\n%s", string(out))
	}

	return nil
}

func (s *ServerConfigurationService) Delete(id string, serverName string) error {
	_, err := db.DB.Exec(
		"DELETE FROM server_configuration WHERE id=?",
		 id,
	)
	if err != nil {
		log.Println("DELETE record failed:", err)
	}

	DeleteNginxConfig(serverName)

	return err
}

func (s *ServerConfigurationService) GenerateVPNClientConfig(
    serverID string,
    clientName string,
    caPassphrase string, 
) (string, error) {

    settings := NewSettingsService()
    pkiDir := settings.GetValue("openvpn.pki_dir")
    easyRSADir := settings.GetValue("openvpn.ca_dir")
    easyRSA := settings.GetValue("openvpn.easy_rsa_path")

    caCertPath := filepath.Join(pkiDir, "ca.crt")
    clientCertPath := filepath.Join(pkiDir, "issued", clientName+".crt")
    clientKeyPath := filepath.Join(pkiDir, "private", clientName+".key")
    taKeyPath := filepath.Join(easyRSADir, "ta.key")

    if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {

        args := []string{"build-client-full", clientName, "nopass"}
        cmd := exec.Command(easyRSA, args...)
        cmd.Dir = easyRSADir

        env := os.Environ()
        env = append(env, "EASYRSA_BATCH=1")

        if caPassphrase != "" {
            env = append(env, "EASYRSA_PASSIN=pass:"+caPassphrase)
        }

        cmd.Env = env

        output, err := cmd.CombinedOutput()
        if err != nil {
            return "", fmt.Errorf(
                "easy-rsa failed: %v\n%s",
                err,
                string(output),
            )
        }
    }

    ca, err := os.ReadFile(caCertPath)
    if err != nil {
        return "", err
    }

    cert, err := os.ReadFile(clientCertPath)
    if err != nil {
        return "", err
    }

    key, err := os.ReadFile(clientKeyPath)
    if err != nil {
        return "", err
    }

    taKey, _ := os.ReadFile(taKeyPath)

    conf := fmt.Sprintf(`client
dev tun
proto udp
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
key-direction 1

<ca>
%s
</ca>

<cert>
%s
</cert>

<key>
%s
</key>
`,
        settings.GetValue("openvpn.remote_host"),
        settings.GetValue("openvpn.remote_port"),
        string(ca),
        string(cert),
        string(key),
    )

    if len(taKey) > 0 {
        conf += fmt.Sprintf(`
<tls-auth>
%s
</tls-auth>
`, string(taKey))
    }

    return conf, nil
}

func (s *ServerConfigurationService) SaveVPNConfig(serverID string, config []byte) error {
    query := `UPDATE servers SET vpn_file = ? WHERE id = ?`

	if len(config) > 0 {
		encrypted, err := EncryptVPN(config)
		if err != nil {
			log.Println("Encryption failed:", err)
		} else {
			config = encrypted
		}
	}

    _, err := db.DB.Exec(query, config, serverID)
    return err
}

func (s *ServerConfigurationService) UpdateServerIP(serverID, ip string) error {
	if strings.TrimSpace(ip) == "" {
		return nil
	}
	_, err := db.DB.Exec(`UPDATE servers SET ip = ? WHERE id = ?`, ip, serverID)
	return err
}

func (s *ServerConfigurationService) AssignStaticVPNIP(clientName, ip string) error {
    settings := NewSettingsService()
    ccdDir := settings.GetValue("openvpn.ccd_dir")
    path := filepath.Join(ccdDir, clientName)

    content := fmt.Sprintf(
        "ifconfig-push %s 255.255.255.0\n",
        ip,
    )

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return err
	}

    return nil
}


func EncryptVPN(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil) 
	return ciphertext, nil
}

func DecryptVPN(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

type User struct {
	Email string 
	Registration *registration.Resource
	Key crypto.PrivateKey
}

func(u *User) GetEmail() string {
	return u.Email
}

func(u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}


func (s *ServerConfigurationService) IssueCert(
	siteID string,
	domain string,
) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	settings := NewSettingsService()
	user := &User{
		Email: settings.GetValue("acme.email"),
		Key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	err = client.Challenge.SetHTTP01Provider(
		http01.NewProviderServer(
			settings.GetValue("acme.http01_host"),
			settings.GetValue("acme.http01_port"),
		),
	)
	if err != nil {
		return err
	}

	reg, err := client.Registration.Register(
		registration.RegisterOptions{TermsOfServiceAgreed: true},
	)
	if err != nil {
		return err
	}
	user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	certPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".crt")
	keyPath  := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".key")

	if err := os.WriteFile(certPath, certRes.Certificate, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0600); err != nil {
		return err
	}

	expiry := extractExpiration(certRes.Certificate)

	insertCert(
		siteID,
		domain,
		certPath,
		keyPath,
		expiry,
	)

	return nil
}

func (s *ServerConfigurationService) RenewCert(siteID string) error {
	var certPath, domain, keyPath string
	row := db.DB.QueryRow(`
		SELECT cert_path, key_path, domain
		FROM certificates
		WHERE site_id = ?
	`, siteID)

	err := row.Scan(&certPath, &keyPath, &domain)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("no certificate found for site_id=%s", siteID)
		}
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	settings := NewSettingsService()
	user := &User{
		Email: settings.GetValue("acme.email"),
		Key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	err = client.Challenge.SetHTTP01Provider(
		http01.NewProviderServer(
			settings.GetValue("acme.http01_host"),
			settings.GetValue("acme.http01_port"),
		),
	)
	if err != nil {
		return err
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(
			registration.RegisterOptions{TermsOfServiceAgreed: true},
		)
		if err != nil {
			return err
		}
		user.Registration = reg
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	if err := os.WriteFile(certPath, certRes.Certificate, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0600); err != nil {
		return err
	}

	expiry := extractExpiration(certRes.Certificate)
	if err := updateCert(siteID, domain, certPath, keyPath, expiry); err != nil {
		return err
	}

	return nil
}



func extractExpiration(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert.NotAfter
}

func insertCert(
	siteID string,
	domain string,
	certPath string,
	keyPath string,
	expires time.Time,
) {
	_, err := db.DB.Exec(`
		INSERT INTO certificates
			(site_id, domain, cert_path, key_path, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			site_id = VALUES(site_id),
			cert_path = VALUES(cert_path),
			key_path  = VALUES(key_path),
			expires_at = VALUES(expires_at),
			updated_at = NOW()
	`,
		siteID,
		domain,
		certPath,
		keyPath,
		expires,
	)
	if err != nil {
		log.Fatal(err)
	}
	activateSSL(siteID, domain)
}

func updateCert(
	siteID string,
	domain string,
	certPath string,
	keyPath string,
	expires time.Time,
) error {
	result, err := db.DB.Exec(`
		UPDATE certificates
		SET cert_path = ?, 
		    key_path = ?, 
		    expires_at = ?, 
		    updated_at = NOW()
		WHERE site_id = ? AND domain = ?
	`, certPath, keyPath, expires, siteID, domain)

	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no certificate found for site_id=%s domain=%s", siteID, domain)
	}

	activateSSL(siteID, domain)
	return nil
}


func activateSSL(siteID string, domain string) {
	_, err := db.DB.Exec(`
		UPDATE server_configuration 
		SET ssl_enabled = 1, server_port = 443, ssl_redirect = 1
		WHERE id = ?
	`, siteID)
	if err != nil {
		log.Fatal(err)
	}
	DeployNginxConfig(domain)
}

func (s *ServerConfigurationService) DeleteCert(siteID string) error {

	var certPath, domain, keyPath string
	var privKey crypto.PrivateKey

	row := db.DB.QueryRow(`
		SELECT cert_path, key_path, domain
		FROM certificates
		WHERE site_id = ?
	`, siteID)

	err := row.Scan(&certPath, &keyPath, &domain)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("no certificate found for site_id=%s", siteID)
		}
		return err
	}

	certPEM, err := os.ReadFile(certPath)

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read cert private key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("invalid private key PEM")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}


	user := &User{
		Email: NewSettingsService().GetValue("acme.email"),
		Key:   privKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create lego client: %w", err)
	}

	if len(certPEM) > 0 {
		if err := client.Certificate.Revoke(certPEM); err != nil {
			return fmt.Errorf("certificate revocation failed for %s: %w", domain, err)
		}
	}
	
	_, err = db.DB.Exec(`
		UPDATE server_configuration 
		SET ssl_enabled = 0, server_port = 80, ssl_redirect = 0
		WHERE id = ?
	`, siteID)
	if err != nil {
		return fmt.Errorf("failed to update server config: %w", err)
	}

	_, err = db.DB.Exec(`
		DELETE FROM certificates 
		WHERE site_id = ?
	`, siteID)
	if err != nil {
		return fmt.Errorf("failed to delete certificate from DB: %w", err)
	}

	fsRemoveCert(domain)

	if err := DeployNginxConfig(domain); err != nil {
		return fmt.Errorf("failed to deploy nginx config: %w", err)
	}

	return nil
}


func fsRemoveCert(domain string) {
	settings := NewSettingsService()
	certPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".crt")
	keyPath  := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".key")

	if err := os.Remove(certPath); err != nil {
		log.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		log.Fatal(err)
	}
}


func (s *ServerConfigurationService) ListIPTablesRules() ([]models.IPTablesRule, error) {
    var rules []models.IPTablesRule

    tables := []string{"filter", "nat"}

    reConnLimit := regexp.MustCompile(`#conn src/32 > (\d+)`)
    reComment := regexp.MustCompile(`/\* (.+?) \*/`)

    for _, table := range tables {
        args := []string{}
        if table != "filter" {
            args = append(args, "-t", table)
        }
        args = append(args, "-L", "-v", "-n", "--line-numbers")

        cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
        out, err := cmd.CombinedOutput()
        if err != nil {
            return nil, fmt.Errorf("iptables list (%s) failed: %s", table, out)
        }

        lines := strings.Split(string(out), "\n")

        currentChain := ""

        for _, line := range lines {
            line = strings.TrimSpace(line)

            if strings.HasPrefix(line, "Chain ") {
                // Example: Chain INPUT (policy ACCEPT)
                parts := strings.Fields(line)
                if len(parts) >= 2 {
                    currentChain = parts[1]
                }
                continue
            }

            if line == "" || strings.HasPrefix(line, "pkts") {
                continue
            }

            fields := strings.Fields(line)
            if len(fields) < 10 {
                continue
            }

            extra := strings.Join(fields[10:], " ")

            // Extract limit
            limit := ""
            if m := reConnLimit.FindStringSubmatch(extra); len(m) == 2 {
                limit = m[1]
            }

            // Extract comment
            comment := ""
            if m := reComment.FindStringSubmatch(extra); len(m) == 2 {
                comment = m[1]
            }

            rule := models.IPTablesRule{
                Table:       table,
                Chain:       currentChain,
                Num:         fields[0],
                Pkts:        fields[1],
                Bytes:       fields[2],
                Target:      fields[3],
                Prot:        fields[4],
                Opt:         fields[5],
                In:          fields[6],
                Out:         fields[7],
                Source:      fields[8],
                Destination: fields[9],
                Extra:       comment,
                Limit:       limit,
            }

            rules = append(rules, rule)
        }
    }

    sort.SliceStable(rules, func(i, j int) bool {
        if rules[i].Table != rules[j].Table {
            return rules[i].Table < rules[j].Table
        }
        if rules[i].Chain != rules[j].Chain {
            return rules[i].Chain < rules[j].Chain
        }
        ni, _ := strconv.Atoi(rules[i].Num)
        nj, _ := strconv.Atoi(rules[j].Num)
        return ni < nj
    })

    return rules, nil
}


func (s *ServerConfigurationService) AddRule(spec models.IPTablesRuleSpec) error {
    args := []string{}

    if spec.Table != "" && spec.Table != "filter" {
        args = append(args, "-t", spec.Table)
    }

    action := "-A"
    if strings.EqualFold(spec.Action, "insert") {
        action = "-I"
    }
    args = append(args, action, spec.Chain)
    if action == "-I" && spec.Position > 0 {
        args = append(args, strconv.Itoa(spec.Position))
    }

    if spec.Protocol != "" && spec.Protocol != "all" {
        args = append(args, "-p", spec.Protocol)
    }

    if spec.InInterface != "" {
        args = append(args, "-i", spec.InInterface)
    }

    if spec.OutInterface != "" {
        args = append(args, "-o", spec.OutInterface)
    }

    if spec.SynOnly {
        args = append(args, "--syn")
    }

    if spec.SourceIP != "" {
        args = append(args, "-s", spec.SourceIP)
    }

    if spec.DestIP != "" {
        args = append(args, "-d", spec.DestIP)
    }

    if spec.SourcePort > 0 {
        args = append(args, "--sport", strconv.Itoa(spec.SourcePort))
    }

    if spec.DestPort > 0 {
        args = append(args, "--dport", strconv.Itoa(spec.DestPort))
    }

    if spec.ConnLimit != nil {
        args = append(args,
            "-m", "connlimit",
            "--connlimit-above", strconv.Itoa(*spec.ConnLimit),
            "--connlimit-mask", "32",
        )
    }

    if spec.LimitRate != "" {
        args = append(args,
            "-m", "limit",
            "--limit", spec.LimitRate,
        )
        if spec.LimitBurst != "" {
            args = append(args, "--limit-burst", spec.LimitBurst)
        }
    }

    if spec.ConnState != "" {
        args = append(args, "-m", "conntrack", "--ctstate", spec.ConnState)
    }

    if spec.IcmpType != "" {
        args = append(args, "--icmp-type", spec.IcmpType)
    }

    hasJump := hasJumpArg(spec.ExtraArgs)
    if len(spec.ExtraArgs) > 0 {
        args = append(args, spec.ExtraArgs...)
    }

    if !hasJump && spec.Target == "DNAT" {
        args = append(args,
            "-j", "DNAT",
            "--to-destination", fmt.Sprintf("%s:%d", spec.ToIP, spec.ToPort),
        )
    } else if !hasJump && spec.Target != "" {
        args = append(args, "-j", spec.Target)

        if spec.Target == "LOG" && spec.LogPrefix != "" {
            args = append(args, "--log-prefix", spec.LogPrefix)
        }
        if spec.Target == "LOG" && spec.LogLevel != "" {
            args = append(args, "--log-level", spec.LogLevel)
        }
        if spec.Target == "REJECT" && spec.RejectWith != "" {
            args = append(args, "--reject-with", spec.RejectWith)
        }
    }

    if spec.Comment != "" {
        args = append(args, "-m", "comment", "--comment", spec.Comment)
    }

    cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables error: %s", out)
    }

    return nil
}

func hasJumpArg(args []string) bool {
    for i := 0; i < len(args); i++ {
        if args[i] == "-j" || args[i] == "--jump" {
            return true
        }
    }
    return false
}

func (s *ServerConfigurationService) DeleteRule(chain string, num int, table string) error {
    args := []string{}
    if table != "" && table != "filter" {
        args = append(args, "-t", table)
    }
    args = append(args, "-D", chain, strconv.Itoa(num))

    cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables delete failed: %s", string(out))
    }
    return nil
}

func (s *ServerConfigurationService) DeleteRuleByComment(chain, table, comment string) error {
    args := []string{"-t", table, "-L", chain, "-n", "--line-numbers"}
    cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables list failed: %s", string(out))
    }

    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        if strings.Contains(line, comment) {
            fields := strings.Fields(line)
            if len(fields) > 0 {
                num, _ := strconv.Atoi(fields[0])
                return s.DeleteRule(chain, num, table)
            }
        }
    }
    return fmt.Errorf("rule with comment '%s' not found in %s:%s", comment, table, chain)
}
