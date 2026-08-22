package services

import (
	"GoResolver/internal/config"
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ServerConfigurationService struct{}

var ensureServerConfigurationSchemaOnce sync.Once
var ensureCertificatesSchemaOnce sync.Once
var certificateOperationMu sync.Mutex

const (
	certificateAutoRenewLeadTime = 30 * 24 * time.Hour
)

func NewServerConfigurationService() *ServerConfigurationService {
	return &ServerConfigurationService{}
}

func ensureServerConfigurationSchema() error {
	var ensureErr error
	ensureServerConfigurationSchemaOnce.Do(func() {
		statements := []struct {
			column string
			query  string
		}{
			{
				column: "hsts",
				query: `
					ALTER TABLE server_configuration
					ADD COLUMN hsts TINYINT(1) NOT NULL DEFAULT 0 AFTER ssl_redirect
				`,
			},
			{
				column: "site_enabled",
				query: `
					ALTER TABLE server_configuration
					ADD COLUMN site_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER server_name
				`,
			},
			{
				column: "proxy_connect_timeout",
				query: `
					ALTER TABLE server_configuration
					ADD COLUMN proxy_connect_timeout INT NOT NULL DEFAULT 5 AFTER proxy_intercept_errors
				`,
			},
			{
				column: "proxy_read_timeout",
				query: `
					ALTER TABLE server_configuration
					ADD COLUMN proxy_read_timeout INT NOT NULL DEFAULT 300 AFTER proxy_connect_timeout
				`,
			},
			{
				column: "proxy_send_timeout",
				query: `
					ALTER TABLE server_configuration
					ADD COLUMN proxy_send_timeout INT NOT NULL DEFAULT 300 AFTER proxy_read_timeout
				`,
			},
		}
		for _, statement := range statements {
			_, err := db.DB.Exec(statement.query)
			if err == nil {
				continue
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "duplicate column") || !strings.Contains(msg, statement.column) {
				ensureErr = err
				return
			}
		}
	})
	return ensureErr
}

func ensureCertificatesSchema() error {
	var ensureErr error
	ensureCertificatesSchemaOnce.Do(func() {
		_, err := db.DB.Exec(`
			CREATE TABLE IF NOT EXISTS certificates (
				site_id BIGINT PRIMARY KEY,
				domain VARCHAR(255) NOT NULL,
				cert_path TEXT NOT NULL,
				key_path TEXT NOT NULL,
				expires_at DATETIME NOT NULL,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			ensureErr = err
		}
	})
	return ensureErr
}

func (s *ServerConfigurationService) GetServerConfiguration(serverID string) []models.ServerConfiguration {
	if err := ensureServerConfigurationSchema(); err != nil {
		log.Println("schema ensure failed:", err)
		return nil
	}
	if err := ensureCertificatesSchema(); err != nil {
		log.Println("certificate schema ensure failed:", err)
		return nil
	}

	rows, err := db.DB.Query(`
			SELECT
				sc.id,
				sc.server_name,
				sc.site_enabled,
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
				s.vpn_file,
				s.port,
			s.name,
			IFNULL(c.cert_path, ''),
			IFNULL(c.key_path, ''),
			IFNULL(DATE_FORMAT(c.updated_at, '%Y-%m-%d %H:%i:%s'), ''),
			IFNULL(DATE_FORMAT(c.expires_at, '%Y-%m-%d %H:%i:%s'), ''),
			IFNULL(DATE_FORMAT(DATE_SUB(c.expires_at, INTERVAL 30 DAY), '%Y-%m-%d %H:%i:%s'), '')
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
			&sc.Site_Enabled,
			&sc.Server_Port,
			&sc.SSL_Enabled,
			&sc.SSL_Redirect,
			&sc.HSTS,
			&sc.Proxy_Pass_Port,
			&sc.Proxy_Intercept_Errors,
			&sc.Proxy_Connect_Timeout,
			&sc.Proxy_Read_Timeout,
			&sc.Proxy_Send_Timeout,
			&sc.Websockets,
			&sc.LetsEncryptConfigFile,
			&sc.IP,
			&vpnBlob,
			&sc.Port,
			&sc.Name,
			&sc.Cert_Path,
			&sc.Key_Path,
			&sc.Cert_Issued,
			&sc.Cert_Expiration,
			&sc.Cert_Renew_Scheduled,
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
	if IsSystemServerID(serverID) {
		return systemServer(), nil
	}

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
	normalizedWhitelist := normalizeWhitelistEntries(p.Whitelist)
	p.Whitelist = strings.Join(normalizedWhitelist, ",")

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

	ddosPrefix := fmt.Sprintf("GoResolver:DDoS:%s:", serverID)
	_ = s.DeleteRuleByComment("INPUT", "filter", ddosPrefix)

	if !p.Enabled || !IsSystemServerID(serverID) {
		return nil
	}

	ip, err := s.getServerIP(serverID)
	if err != nil {
		return err
	}

	ports := s.getServerPorts(serverID)
	if len(ports) == 0 {
		ports = []int{80, 443}
	}

	whitelist := normalizeWhitelistEntries(p.Whitelist)
	families, err := firewallFamiliesForServer(ip, whitelist)
	if err != nil {
		return err
	}

	for _, family := range families {
		familyDestIP := s.resolveManagedRuleDestinationIP(serverID, ip, family)
		familyWhitelist := filterIPsByFirewallFamily(whitelist, family)

		if len(familyWhitelist) > 0 {
			insertAt, err := s.findLastRulePositionByComment("INPUT", "filter", "GoResolver:Fail2Ban:", family)
			if err != nil {
				return err
			}
			if insertAt <= 0 {
				insertAt = 1
			} else {
				insertAt++
			}
			for _, port := range ports {
				for _, entry := range familyWhitelist {
					if err := s.AddRule(models.IPTablesRuleSpec{
						Family:   family,
						Table:    "filter",
						Chain:    "INPUT",
						Action:   "insert",
						Position: insertAt,
						Protocol: "tcp",
						SourceIP: entry,
						DestIP:   familyDestIP,
						DestPort: port,
						Target:   "ACCEPT",
						Comment:  fmt.Sprintf("GoResolver:DDoS:%s:WL:%d:%s", serverID, port, entry),
					}); err != nil {
						return err
					}
					insertAt++
				}
			}
		}

		for _, port := range ports {
			if p.ConnLimit > 0 {
				cl := p.ConnLimit
				if err := s.AddRule(models.IPTablesRuleSpec{
					Family:    family,
					Table:     "filter",
					Chain:     "INPUT",
					Action:    "append",
					Protocol:  "tcp",
					DestIP:    familyDestIP,
					DestPort:  port,
					ConnLimit: &cl,
					Target:    "DROP",
					Comment:   fmt.Sprintf("GoResolver:DDoS:%s:CL%d", serverID, port),
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
					"--hashlimit-name", fmt.Sprintf("gr_%s_rl_%s_%d", serverID, firewallHashSuffix(family), port),
				}
				if err := s.AddRule(models.IPTablesRuleSpec{
					Family:    family,
					Table:     "filter",
					Chain:     "INPUT",
					Action:    "append",
					Protocol:  "tcp",
					DestIP:    familyDestIP,
					DestPort:  port,
					ExtraArgs: args,
					Target:    "DROP",
					Comment:   fmt.Sprintf("GoResolver:DDoS:%s:RL%d", serverID, port),
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
					"--hashlimit-name", fmt.Sprintf("gr_%s_syn_%s_%d", serverID, firewallHashSuffix(family), port),
				}
				if err := s.AddRule(models.IPTablesRuleSpec{
					Family:    family,
					Table:     "filter",
					Chain:     "INPUT",
					Action:    "append",
					Protocol:  "tcp",
					SynOnly:   true,
					DestIP:    familyDestIP,
					DestPort:  port,
					ExtraArgs: args,
					Target:    "DROP",
					Comment:   fmt.Sprintf("GoResolver:DDoS:%s:SYN%d", serverID, port),
				}); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (s *ServerConfigurationService) getServerPorts(serverID string) []int {
	rows, err := db.DB.Query(`
		SELECT DISTINCT server_port
		FROM server_configuration
		WHERE fk_server = ? AND server_port > 0
	`, serverID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	ports := []int{}
	seen := map[int]struct{}{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

func isLocalIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ipNet = v
			case *net.IPAddr:
				ipNet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
			}
			if ipNet == nil {
				continue
			}
			if ipNet.IP.Equal(parsed) {
				return true
			}
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *ServerConfigurationService) InsertServerConfiguration(sc models.ServerConfiguration) error {
	if err := ensureServerConfigurationSchema(); err != nil {
		return err
	}

	result, err := db.DB.Exec(`
		INSERT INTO server_configuration (
			fk_server,
			server_name,
			site_enabled,
			server_port,
			ssl_enabled,
			ssl_redirect,
			hsts,
			proxy_pass_port,
			proxy_intercept_errors,
			proxy_connect_timeout,
			proxy_read_timeout,
			proxy_send_timeout,
			websockets
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		sc.ServerID,
		sc.Server_Name,
		sc.Site_Enabled,
		sc.Server_Port,
		sc.SSL_Enabled,
		sc.SSL_Redirect,
		sc.HSTS,
		sc.Proxy_Pass_Port,
		sc.Proxy_Intercept_Errors,
		sc.Proxy_Connect_Timeout,
		sc.Proxy_Read_Timeout,
		sc.Proxy_Send_Timeout,
		sc.Websockets,
	)

	if err != nil {
		log.Println("INSERT server_configuration failed:", err)
		return err
	}

	rows, _ := result.RowsAffected()
	log.Println("Rows inserted into server_configuration:", rows)
	if err := DeployNginxConfig(sc.Server_Name); err != nil {
		log.Println("nginx deploy failed:", err)
	}

	return nil
}

func (s *ServerConfigurationService) UpdateServerConfiguration(sc models.ServerConfiguration) error {
	if err := ensureServerConfigurationSchema(); err != nil {
		return err
	}

	oldServerName := strings.TrimSpace(sc.Server_Name)
	_ = db.DB.QueryRow(`SELECT server_name FROM server_configuration WHERE id = ?`, sc.ID).Scan(&oldServerName)

	result, err := db.DB.Exec(`
		UPDATE server_configuration SET
			server_name = ?,
			site_enabled = ?,
			server_port = ?,
			ssl_enabled = ?,
			ssl_redirect = ?,
			hsts = ?,
			proxy_pass_port = ?,
			proxy_intercept_errors = ?,
			proxy_connect_timeout = ?,
			proxy_read_timeout = ?,
			proxy_send_timeout = ?,
			websockets = ?
		WHERE id = ?`,
		sc.Server_Name,
		sc.Site_Enabled,
		sc.Server_Port,
		sc.SSL_Enabled,
		sc.SSL_Redirect,
		sc.HSTS,
		sc.Proxy_Pass_Port,
		sc.Proxy_Intercept_Errors,
		sc.Proxy_Connect_Timeout,
		sc.Proxy_Read_Timeout,
		sc.Proxy_Send_Timeout,
		sc.Websockets,
		sc.ID,
	)
	if err != nil {
		log.Println("UPDATE server_configuration failed:", err)
		return err
	}
	rows, _ := result.RowsAffected()
	log.Println("Rows affected in server_configuration:", rows)

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
	if oldServerName != "" && oldServerName != sc.Server_Name {
		if err := DeployNginxConfig(oldServerName); err != nil {
			log.Println("nginx cleanup deploy failed:", err)
		}
	}
	if err := DeployNginxConfig(sc.Server_Name); err != nil {
		log.Println("nginx deploy failed:", err)
	}

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
	defaultPath := NewSettingsService().GetValue("paths.error_pages")
	rows, err := db.DB.Query(`
		SELECT  id,
				error_code,
				response_type,
				filename,
				file,
				COALESCE(NULLIF(path, ''), ?)
		FROM error_page_files 
		ORDER BY updated_at
	`, defaultPath)
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

func normalizeWhitelistEntries(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			if _, netw, err := net.ParseCIDR(p); err == nil && netw != nil {
				key := netw.String()
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					out = append(out, key)
				}
			}
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			key := ip.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, key)
			}
		}
	}
	return out
}

func (s *ServerConfigurationService) findLastRulePositionByComment(chain, table, comment, family string) (int, error) {
	args := []string{"-t", table, "-L", chain, "-n", "--line-numbers"}
	out, err := runFirewallCommand(family, args)
	if err != nil {
		return 0, fmt.Errorf("iptables list failed: %s", string(out))
	}

	lines := strings.Split(string(out), "\n")
	maxNum := 0
	for _, line := range lines {
		if !strings.Contains(line, comment) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		num, _ := strconv.Atoi(fields[0])
		if num > maxNum {
			maxNum = num
		}
	}
	return maxNum, nil
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
		log.Println("INSERT error_page failed:", err)
		return err
	}
	return nil
}

func (s *ServerConfigurationService) UploadErrorPage(ef models.ServerErrorFiles) error {
	normalizedCodes, err := normalizeNginxErrorCodes(ef.Error_Code)
	if err != nil {
		return err
	}

	_, err = db.DB.Exec(`
		INSERT INTO error_page_files (
			id, 
			error_code, response_type,
			filename, file, path
		) VALUES (UUID(), ?, ?, ?, ?, ?)
	`,
		normalizedCodes,
		ef.ResponseType,
		ef.Filename,
		ef.File,
		ef.Path,
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
	normalizedCodes, err := normalizeNginxErrorCodes(ef.Error_Code)
	if err != nil {
		return err
	}

	_, err = db.DB.Exec(`
		UPDATE error_page_files 
		SET error_code = ?, response_type = ? 
		WHERE id = ?
	`,
		normalizedCodes,
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

	efPath := filepath.Join(ef.Path, ef.Filename)

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
	return buildNginxConfig(SiteName)
}

func shouldEnableTransparentProxy() bool {
	val := strings.TrimSpace(NewSettingsService().GetValue("nginx.transparent_proxy"))
	if val == "" {
		return false
	}
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// func (s *ServerConfigurationService) DeployNginxConfig(serverName string) error {
func DeployNginxConfig(serverName string) error {
	config, err := GenerateNginxConfig(serverName)
	if err != nil {
		if errors.Is(err, errNoNginxSiteConfiguration) {
			return removeNginxSiteConfig(serverName)
		}
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

	return testAndReloadNginx()
}

func testAndReloadNginx() error {
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

func removeNginxSiteConfig(serverName string) error {
	serverName = strings.ReplaceAll(serverName, " ", "_")

	settings := NewSettingsService()
	availablePath := filepath.Join(settings.GetValue("paths.nginx_sites_available"), serverName)
	enabledPath := filepath.Join(settings.GetValue("paths.nginx_sites_enabled"), serverName)

	if err := removeNginxPathIfPresent(enabledPath); err != nil {
		return fmt.Errorf("remove enabled site failed: %w", err)
	}
	if err := removeNginxPathIfPresent(availablePath); err != nil {
		return fmt.Errorf("remove available site failed: %w", err)
	}

	if err := ensureDefaultDenySite(); err != nil {
		return fmt.Errorf("default deny config failed: %w", err)
	}
	if err := ensureNginxLogFormat(); err != nil {
		return fmt.Errorf("nginx log config failed: %w", err)
	}

	return testAndReloadNginx()
}

func removeNginxPathIfPresent(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
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
	enabledValue := strings.TrimSpace(settings.GetValue("nginx.default_deny_enabled"))

	switch strings.ToLower(enabledValue) {
	case "", "1", "true", "yes", "on":
	default:
		removeIfExists(enabledPath)
		removeIfExists(availablePath)
		return nil
	}

	certPath, keyPath, err := ensureDefaultDenyCert()
	if err != nil {
		return err
	}

	includePath, err := effectiveLetsEncryptConfigPath(defaultLetsEncryptConfigFile)
	if err != nil {
		return err
	}

	config := renderDefaultDenyConfig(certPath, keyPath, includePath)

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
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
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
	return removeNginxSiteConfig(serverName)
}

func (s *ServerConfigurationService) Delete(id string, serverName string) error {
	_, err := db.DB.Exec(
		"DELETE FROM server_configuration WHERE id=?",
		id,
	)
	if err != nil {
		log.Println("DELETE record failed:", err)
	}

	if deployErr := DeployNginxConfig(serverName); deployErr != nil {
		log.Println("nginx deploy failed:", deployErr)
	}

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
	if len(data) == 0 {
		return nil, nil
	}

	keys, err := vpnEncryptionKeys()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keys[0])
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
	if len(ciphertext) == 0 {
		return nil, nil
	}

	keys, err := vpnEncryptionKeys()
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, key := range keys {
		plaintext, err := decryptVPNWithKey(ciphertext, key)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("decryption failed: %w", lastErr)
}

func vpnEncryptionKeys() ([][]byte, error) {
	currentSecret, err := config.RequiredSecret("GORESOLVER_VPN_ENCRYPTION_SECRET")
	if err != nil {
		return nil, err
	}

	currentKey, err := config.DeriveKey(currentSecret, "goresolver-vpn-aes-gcm", 32)
	if err != nil {
		return nil, err
	}

	keys := [][]byte{currentKey}

	previousSecret, ok, err := config.OptionalSecret("GORESOLVER_VPN_ENCRYPTION_SECRET_PREVIOUS")
	if err != nil {
		return nil, err
	}
	if ok {
		previousKey, err := config.DeriveKey(previousSecret, "goresolver-vpn-aes-gcm", 32)
		if err != nil {
			return nil, err
		}
		keys = append(keys, previousKey)
	}

	return keys, nil
}

func decryptVPNWithKey(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
	return gcm.Open(nil, nonce, ct, nil)
}

type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (s *ServerConfigurationService) IssueCert(
	siteID string,
	domain string,
) error {
	certificateOperationMu.Lock()
	defer certificateOperationMu.Unlock()

	if err := ensureCertificatesSchema(); err != nil {
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
	keyPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".key")

	if err := os.WriteFile(certPath, certRes.Certificate, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0600); err != nil {
		return err
	}

	expiry, err := extractExpiration(certRes.Certificate)
	if err != nil {
		return err
	}

	if err := insertCert(
		siteID,
		domain,
		certPath,
		keyPath,
		expiry,
	); err != nil {
		return err
	}

	return nil
}

func (s *ServerConfigurationService) RenewCert(siteID string) error {
	certificateOperationMu.Lock()
	defer certificateOperationMu.Unlock()

	if err := ensureCertificatesSchema(); err != nil {
		return err
	}

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

	expiry, err := extractExpiration(certRes.Certificate)
	if err != nil {
		return err
	}
	if err := updateCert(siteID, domain, certPath, keyPath, expiry); err != nil {
		return err
	}

	return nil
}

func extractExpiration(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func insertCert(
	siteID string,
	domain string,
	certPath string,
	keyPath string,
	expires time.Time,
) error {
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
		return err
	}
	return activateSSL(siteID, domain)
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

	return activateSSL(siteID, domain)
}

func activateSSL(siteID string, domain string) error {
	_, err := db.DB.Exec(`
		UPDATE server_configuration 
		SET ssl_enabled = 1, server_port = 443, ssl_redirect = 1
		WHERE id = ?
	`, siteID)
	if err != nil {
		return err
	}
	return DeployNginxConfig(domain)
}

func (s *ServerConfigurationService) DeleteCert(siteID string) error {
	certificateOperationMu.Lock()
	defer certificateOperationMu.Unlock()

	if err := ensureCertificatesSchema(); err != nil {
		return err
	}

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

	if err := fsRemoveCert(domain); err != nil {
		return err
	}

	if err := DeployNginxConfig(domain); err != nil {
		return fmt.Errorf("failed to deploy nginx config: %w", err)
	}

	return nil
}

func fsRemoveCert(domain string) error {
	settings := NewSettingsService()
	certPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".crt")
	keyPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".key")

	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func certificateRenewSchedule(expiresAt time.Time) time.Time {
	if expiresAt.IsZero() {
		return time.Time{}
	}
	return expiresAt.Add(-certificateAutoRenewLeadTime)
}

func (s *ServerConfigurationService) DueCertificateSiteIDs(now time.Time, limit int) ([]string, error) {
	if err := ensureCertificatesSchema(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 25
	}
	cutoff := now.UTC().Add(certificateAutoRenewLeadTime)
	rows, err := db.DB.Query(`
		SELECT CAST(site_id AS CHAR)
		FROM certificates
		WHERE expires_at <= ?
		ORDER BY expires_at ASC, site_id ASC
		LIMIT ?
	`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	siteIDs := make([]string, 0, limit)
	for rows.Next() {
		var siteID string
		if err := rows.Scan(&siteID); err != nil {
			return nil, err
		}
		siteIDs = append(siteIDs, strings.TrimSpace(siteID))
	}
	return siteIDs, rows.Err()
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
	family, err := inferFirewallFamily(spec)
	if err != nil {
		return err
	}

	args := buildFirewallRuleArgs(spec, family)
	out, err := runFirewallCommand(family, args)
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

func (s *ServerConfigurationService) DeleteRule(chain string, num int, table, family string) error {
	args := []string{}
	if table != "" && table != "filter" {
		args = append(args, "-t", table)
	}
	args = append(args, "-D", chain, strconv.Itoa(num))

	out, err := runFirewallCommand(family, args)
	if err != nil {
		return fmt.Errorf("iptables delete failed: %s", string(out))
	}
	return nil
}

func (s *ServerConfigurationService) DeleteRuleByComment(chain, table, comment string) error {
	found := false
	var lastErr error
	for _, family := range []string{firewallFamilyIPv4, firewallFamilyIPv6} {
		if !firewallBinaryAvailable(family) {
			continue
		}
		deleted, err := s.deleteRuleByCommentForFamily(chain, table, comment, family)
		if deleted {
			found = true
		}
		if err != nil {
			lastErr = err
		}
	}
	if found {
		return lastErr
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("rule with comment '%s' not found in %s:%s", comment, table, chain)
}

func (s *ServerConfigurationService) deleteRuleByCommentForFamily(chain, table, comment, family string) (bool, error) {
	args := []string{"-t", table, "-L", chain, "-n", "--line-numbers"}
	out, err := runFirewallCommand(family, args)
	if err != nil {
		return false, fmt.Errorf("iptables list failed: %s", string(out))
	}

	lines := strings.Split(string(out), "\n")
	var nums []int
	for _, line := range lines {
		if strings.Contains(line, comment) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				num, _ := strconv.Atoi(fields[0])
				if num > 0 {
					nums = append(nums, num)
				}
			}
		}
	}
	if len(nums) == 0 {
		return false, nil
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	var lastErr error
	for _, num := range nums {
		if err := s.DeleteRule(chain, num, table, family); err != nil {
			lastErr = err
		}
	}
	return true, lastErr
}
