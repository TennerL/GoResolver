package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ServerService struct{}

func NewServerService() *ServerService {
	return &ServerService{}
}

func (s *ServerService) GetServers() []models.Server {
	rows, err := db.DB.Query("SELECT id, domain_id, name, ip FROM servers ORDER BY id")
	if err != nil {
		log.Println("DB query error:", err)
		return []models.Server{systemServer()}
	}
	defer rows.Close()

	servers := []models.Server{systemServer()}
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.Domain_ID, &srv.Name, &srv.IP); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		srv.Status = DefaultStatusMonitor().GetPingStatus(srv.IP)
		srv.Uptime = DefaultStatusMonitor().GetPingObservedUptime(srv.IP)
		servers = append(servers, srv)
	}

	if err := rows.Err(); err != nil {
		log.Println("Rows iteration error:", err)
	}

	return servers
}

func (s *ServerService) SuggestNextVPNIP() (string, error) {
	usedIPs, err := s.getUsedServerIPs()
	if err != nil {
		return "", err
	}

	healthIP := strings.TrimSpace(NewSettingsService().GetValue("vpn.healthcheck_ip"))
	prefix := ipPrefixFromList(append(usedIPs, healthIP)...)
	if prefix == "" {
		return "", fmt.Errorf("no IPv4 prefix available for VPN IP suggestion")
	}

	reserved := make(map[string]bool, len(usedIPs)+2)
	for _, ip := range usedIPs {
		reserved[ip] = true
	}
	if healthIP != "" {
		reserved[healthIP] = true
	}
	reserved[prefix+".1"] = true

	for i := 2; i <= 254; i++ {
		ip := fmt.Sprintf("%s.%d", prefix, i)
		if !reserved[ip] {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no available VPN IPs in %s.0/24", prefix)
}

func (s *ServerService) getUsedServerIPs() ([]string, error) {
	rows, err := db.DB.Query("SELECT ip FROM servers WHERE ip <> ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		if isIPv4(ip) {
			ips = append(ips, ip)
		}
	}
	return ips, rows.Err()
}

func ipPrefixFromList(candidates ...string) string {
	for _, candidate := range candidates {
		if !isIPv4(candidate) {
			continue
		}
		parts := strings.Split(candidate, ".")
		if len(parts) != 4 {
			continue
		}
		return strings.Join(parts[:3], ".")
	}
	return ""
}

func isIPv4(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

func (s *ServerService) AddServer(srv models.Server) error {
	result, err := db.DB.Exec(`
		INSERT INTO servers (name, ip)
		VALUES (?,?)
	`,
		strings.TrimSpace(srv.Name),
		strings.TrimSpace(srv.IP),
	)
	if err != nil {
		log.Println("Error adding new server:", err)
		return err
	}

	rows, rowsErr := result.RowsAffected()
	if rowsErr == nil {
		log.Println("Rows inserted into servers:", rows)
	}

	return rowsErr
}

func (s *ServerService) DeleteServer(serverID string) error {
	if IsSystemServerID(serverID) {
		return fmt.Errorf("system server cannot be deleted")
	}

	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.Query(`
		SELECT id, server_name
		FROM server_configuration
		WHERE fk_server = ?
	`, serverID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var siteIDs []int
	var siteNames []string
	for rows.Next() {
		var id int
		var name string
		if scanErr := rows.Scan(&id, &name); scanErr != nil {
			err = scanErr
			return err
		}
		siteIDs = append(siteIDs, id)
		siteNames = append(siteNames, name)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	var certFiles [][2]string
	if len(siteIDs) > 0 {
		placeholders, args := buildPlaceholders(siteIDs)
		certRows, queryErr := tx.Query(
			`SELECT cert_path, key_path FROM certificates WHERE site_id IN (`+placeholders+`)`,
			args...,
		)
		if queryErr != nil {
			err = queryErr
			return err
		}
		for certRows.Next() {
			var certPath, keyPath string
			if scanErr := certRows.Scan(&certPath, &keyPath); scanErr != nil {
				_ = certRows.Close()
				err = scanErr
				return err
			}
			certFiles = append(certFiles, [2]string{certPath, keyPath})
		}
		if closeErr := certRows.Close(); closeErr != nil {
			err = closeErr
			return err
		}

		_, err = tx.Exec(`DELETE FROM certificates WHERE site_id IN (`+placeholders+`)`, args...)
		if err != nil {
			return err
		}

		_, err = tx.Exec(
			`DELETE FROM error_pages WHERE server_id = ? OR site_id IN (`+placeholders+`)`,
			append([]any{serverID}, args...)...,
		)
		if err != nil {
			return err
		}
	} else {
		_, err = tx.Exec(`DELETE FROM error_pages WHERE server_id = ?`, serverID)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec(`DELETE FROM server_configuration WHERE fk_server = ?`, serverID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`DELETE FROM servers WHERE id = ?`, serverID)
	if err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	settings := NewSettingsService()
	nginxAvailable := settings.GetValue("paths.nginx_sites_available")
	nginxEnabled := settings.GetValue("paths.nginx_sites_enabled")
	removedNginx := false

	for _, siteName := range siteNames {
		name := strings.ReplaceAll(siteName, " ", "_")
		availablePath := filepath.Join(nginxAvailable, name)
		enabledPath := filepath.Join(nginxEnabled, name)

		if removeIfExists(availablePath) {
			removedNginx = true
		}
		if removeIfExists(enabledPath) {
			removedNginx = true
		}
	}

	for _, pair := range certFiles {
		removeIfExists(pair[0])
		removeIfExists(pair[1])
	}

	clientName := fmt.Sprintf("client-%s", serverID)
	ccdPath := filepath.Join(settings.GetValue("openvpn.ccd_dir"), clientName)
	removeIfExists(ccdPath)

	pkiDir := settings.GetValue("openvpn.pki_dir")
	removeIfExists(filepath.Join(pkiDir, "issued", clientName+".crt"))
	removeIfExists(filepath.Join(pkiDir, "private", clientName+".key"))
	removeIfExists(filepath.Join(pkiDir, "reqs", clientName+".req"))

	if removedNginx {
		if out, nginxErr := exec.Command("nginx", "-t").CombinedOutput(); nginxErr != nil {
			log.Printf("nginx -t failed after server delete: %s", string(out))
		} else if out, nginxErr = exec.Command("nginx", "-s", "reload").CombinedOutput(); nginxErr != nil {
			log.Printf("nginx reload failed after server delete: %s", string(out))
		}
	}

	return nil
}

func buildPlaceholders(ids []int) (string, []any) {
	parts := make([]string, len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		parts[i] = "?"
		args = append(args, id)
	}
	return strings.Join(parts, ","), args
}

func removeIfExists(path string) bool {
	if path == "" {
		return false
	}
	if err := os.Remove(path); err != nil {
		return false
	}
	return true
}
