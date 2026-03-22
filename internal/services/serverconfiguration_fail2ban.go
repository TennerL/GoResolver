package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"database/sql"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	fail2BanDefaultMaxRetry = 10
	fail2BanDefaultFindTime = 600
	fail2BanDefaultBanTime  = 3600
	fail2BanDefaultStatuses = "403"
)

func (s *ServerConfigurationService) EnsureFail2BanTables() error {
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS fail2ban_policies (
			server_id INT PRIMARY KEY,
			enabled TINYINT(1) NOT NULL DEFAULT 0,
			max_retry INT NOT NULL DEFAULT 10,
			find_time_seconds INT NOT NULL DEFAULT 600,
			ban_time_seconds INT NOT NULL DEFAULT 3600,
			status_codes VARCHAR(128) NOT NULL DEFAULT '403',
			ignore_ips TEXT,
			use_x_forwarded_for TINYINT(1) NOT NULL DEFAULT 0,
			ban_globally TINYINT(1) NOT NULL DEFAULT 0,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	_, _ = db.DB.Exec(`ALTER TABLE fail2ban_policies ADD COLUMN ban_globally TINYINT(1) NOT NULL DEFAULT 0`)
	_, err = db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS fail2ban_bans (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			server_id INT NOT NULL,
			ip VARCHAR(64) NOT NULL,
			hit_count INT NOT NULL DEFAULT 0,
			banned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			reason VARCHAR(255),
			UNIQUE KEY uniq_server_ip (server_id, ip),
			INDEX idx_expires (expires_at),
			INDEX idx_server (server_id)
		)
	`)
	return err
}

func (s *ServerConfigurationService) GetFail2BanPolicy(serverID string) (models.Fail2BanPolicy, error) {
	if err := s.EnsureFail2BanTables(); err != nil {
		return models.Fail2BanPolicy{}, err
	}
	var p models.Fail2BanPolicy
	var enabled int
	var useXff int
	var banGlobally int
	err := db.DB.QueryRow(`
		SELECT server_id, enabled, max_retry, find_time_seconds, ban_time_seconds, status_codes, IFNULL(ignore_ips, ''), use_x_forwarded_for, ban_globally
		FROM fail2ban_policies
		WHERE server_id = ?
	`, serverID).Scan(
		&p.ServerID,
		&enabled,
		&p.MaxRetry,
		&p.FindTimeSeconds,
		&p.BanTimeSeconds,
		&p.StatusCodes,
		&p.IgnoreIPs,
		&useXff,
		&banGlobally,
	)
	if err == sql.ErrNoRows {
		return models.Fail2BanPolicy{
			ServerID:         serverID,
			Enabled:          false,
			MaxRetry:         fail2BanDefaultMaxRetry,
			FindTimeSeconds:  fail2BanDefaultFindTime,
			BanTimeSeconds:   fail2BanDefaultBanTime,
			StatusCodes:      fail2BanDefaultStatuses,
			UseXForwardedFor: false,
			BanGlobally:      false,
		}, nil
	}
	if err != nil {
		return models.Fail2BanPolicy{}, err
	}
	p.Enabled = enabled == 1
	p.UseXForwardedFor = useXff == 1
	p.BanGlobally = banGlobally == 1
	if p.MaxRetry <= 0 {
		p.MaxRetry = fail2BanDefaultMaxRetry
	}
	if p.FindTimeSeconds <= 0 {
		p.FindTimeSeconds = fail2BanDefaultFindTime
	}
	if p.BanTimeSeconds <= 0 {
		p.BanTimeSeconds = fail2BanDefaultBanTime
	}
	if strings.TrimSpace(p.StatusCodes) == "" {
		p.StatusCodes = fail2BanDefaultStatuses
	}
	return p, nil
}

func (s *ServerConfigurationService) SaveFail2BanPolicy(p models.Fail2BanPolicy) error {
	if err := s.EnsureFail2BanTables(); err != nil {
		return err
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	useXff := 0
	if p.UseXForwardedFor {
		useXff = 1
	}
	banGlobally := 0
	if p.BanGlobally {
		banGlobally = 1
	}
	if p.MaxRetry <= 0 {
		p.MaxRetry = fail2BanDefaultMaxRetry
	}
	if p.FindTimeSeconds <= 0 {
		p.FindTimeSeconds = fail2BanDefaultFindTime
	}
	if p.BanTimeSeconds <= 0 {
		p.BanTimeSeconds = fail2BanDefaultBanTime
	}
	if strings.TrimSpace(p.StatusCodes) == "" {
		p.StatusCodes = fail2BanDefaultStatuses
	}

	_, err := db.DB.Exec(`
		INSERT INTO fail2ban_policies (
			server_id, enabled, max_retry, find_time_seconds, ban_time_seconds, status_codes, ignore_ips, use_x_forwarded_for, ban_globally
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			enabled = VALUES(enabled),
			max_retry = VALUES(max_retry),
			find_time_seconds = VALUES(find_time_seconds),
			ban_time_seconds = VALUES(ban_time_seconds),
			status_codes = VALUES(status_codes),
			ignore_ips = VALUES(ignore_ips),
			use_x_forwarded_for = VALUES(use_x_forwarded_for),
			ban_globally = VALUES(ban_globally)
	`,
		p.ServerID, enabled, p.MaxRetry, p.FindTimeSeconds, p.BanTimeSeconds, p.StatusCodes, p.IgnoreIPs, useXff, banGlobally,
	)
	return err
}

func (s *ServerConfigurationService) ListFail2BanBans(serverID string) []models.Fail2BanBan {
	if err := s.EnsureFail2BanTables(); err != nil {
		return nil
	}
	rows, err := db.DB.Query(`
		SELECT server_id, ip, hit_count,
			DATE_FORMAT(banned_at, '%Y-%m-%d %H:%i:%s'),
			DATE_FORMAT(expires_at, '%Y-%m-%d %H:%i:%s')
		FROM fail2ban_bans
		WHERE server_id = ?
		ORDER BY expires_at DESC
	`, serverID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var bans []models.Fail2BanBan
	for rows.Next() {
		var b models.Fail2BanBan
		if err := rows.Scan(&b.ServerID, &b.IP, &b.HitCount, &b.BannedAt, &b.ExpiresAt); err != nil {
			continue
		}
		bans = append(bans, b)
	}
	return bans
}

func (s *ServerConfigurationService) UnbanFail2BanIP(serverID, ip string) error {
	if err := s.EnsureFail2BanTables(); err != nil {
		return err
	}
	if strings.TrimSpace(ip) == "" {
		return nil
	}
	comment := fail2BanRuleComment(serverID, ip)
	_ = s.DeleteRuleByComment("INPUT", "filter", comment)
	_ = s.DeleteRuleByComment("FORWARD", "filter", comment)
	_, err := db.DB.Exec(`DELETE FROM fail2ban_bans WHERE server_id = ? AND ip = ?`, serverID, ip)
	return err
}

func (s *ServerConfigurationService) EnforceFail2BanOnce() {
	if err := s.EnsureFail2BanTables(); err != nil {
		log.Println("fail2ban: ensure tables failed:", err)
		return
	}

	if err := s.cleanupExpiredFail2BanBans(); err != nil {
		log.Println("fail2ban: cleanup expired bans failed:", err)
	}

	rows, err := db.DB.Query(`
		SELECT server_id, enabled, max_retry, find_time_seconds, ban_time_seconds, status_codes, IFNULL(ignore_ips, ''), use_x_forwarded_for, ban_globally
		FROM fail2ban_policies
		WHERE enabled = 1
	`)
	if err != nil {
		log.Println("fail2ban: load policies failed:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var p models.Fail2BanPolicy
		var enabled int
		var useXff int
		var banGlobally int
		if err := rows.Scan(
			&p.ServerID,
			&enabled,
			&p.MaxRetry,
			&p.FindTimeSeconds,
			&p.BanTimeSeconds,
			&p.StatusCodes,
			&p.IgnoreIPs,
			&useXff,
			&banGlobally,
		); err != nil {
			continue
		}
		p.Enabled = enabled == 1
		p.UseXForwardedFor = useXff == 1
		p.BanGlobally = banGlobally == 1
		if !p.Enabled {
			continue
		}
		if p.MaxRetry <= 0 {
			p.MaxRetry = fail2BanDefaultMaxRetry
		}
		if p.FindTimeSeconds <= 0 {
			p.FindTimeSeconds = fail2BanDefaultFindTime
		}
		if p.BanTimeSeconds <= 0 {
			p.BanTimeSeconds = fail2BanDefaultBanTime
		}
		if strings.TrimSpace(p.StatusCodes) == "" {
			p.StatusCodes = fail2BanDefaultStatuses
		}
		if err := s.applyFail2BanPolicy(p); err != nil {
			log.Println("fail2ban: apply failed:", err)
		}
	}
}

func (s *ServerConfigurationService) StartFail2BanEnforcer() {
	settings := NewSettingsService()
	intervalSeconds, err := strconv.Atoi(settings.GetValue("security.fail2ban_interval_seconds"))
	if err != nil || intervalSeconds <= 0 {
		intervalSeconds = 30
	}
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		s.EnforceFail2BanOnce()
		<-ticker.C
	}
}

func (s *ServerConfigurationService) applyFail2BanPolicy(p models.Fail2BanPolicy) error {
	serverIP, err := s.getServerIP(p.ServerID)
	if err != nil || serverIP == "" {
		serverIP = ""
	}
	hosts, err := s.getServerHosts(p.ServerID)
	if err != nil {
		return err
	}
	effectiveHosts := fail2BanEffectiveHosts(p, hosts)
	if !p.BanGlobally && len(effectiveHosts) == 0 {
		return nil
	}

	statuses := parseStatusCodes(p.StatusCodes)
	if len(statuses) == 0 {
		statuses = []int{403}
	}

	ignoreMatchers := parseIPMatchers(p.IgnoreIPs)
	offenders, err := s.findFail2BanOffenders(p, effectiveHosts, statuses)
	if err != nil {
		return err
	}

	for _, offender := range offenders {
		if offender.IP == "" {
			continue
		}
		if ipIgnored(offender.IP, ignoreMatchers) {
			continue
		}
		if err := s.banFail2BanIP(p, serverIP, offender.IP, offender.Count); err != nil {
			log.Println("fail2ban: ban error:", err)
		}
	}

	return nil
}

type fail2banOffender struct {
	IP    string
	Count int
}

func (s *ServerConfigurationService) findFail2BanOffenders(p models.Fail2BanPolicy, hosts []string, statuses []int) ([]fail2banOffender, error) {
	ipExpr := fail2BanClientIPExpr(p)

	query := fmt.Sprintf(`SELECT %s AS ip, COUNT(*) AS hits FROM nginx_logs WHERE time >= NOW() - INTERVAL ? SECOND`, ipExpr)
	args := []any{p.FindTimeSeconds}

	if len(statuses) > 0 {
		query += " AND status IN (" + placeholders(len(statuses)) + ")"
		for _, st := range statuses {
			args = append(args, st)
		}
	}

	if len(hosts) > 0 {
		query += " AND host IN (" + placeholders(len(hosts)) + ")"
		for _, h := range hosts {
			args = append(args, h)
		}
	}

	query += " GROUP BY ip HAVING hits >= ?"
	args = append(args, p.MaxRetry)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var offenders []fail2banOffender
	for rows.Next() {
		var o fail2banOffender
		if err := rows.Scan(&o.IP, &o.Count); err != nil {
			continue
		}
		offenders = append(offenders, o)
	}
	return offenders, nil
}

func (s *ServerConfigurationService) banFail2BanIP(p models.Fail2BanPolicy, serverIP, ip string, hits int) error {
	now := time.Now().UTC()
	expires := now.Add(time.Duration(p.BanTimeSeconds) * time.Second)
	family := firewallFamilyForValue(ip)
	if family == "" {
		return fmt.Errorf("invalid fail2ban ip %q", ip)
	}

	var existingExpires sql.NullTime
	err := db.DB.QueryRow(`
		SELECT expires_at FROM fail2ban_bans WHERE server_id = ? AND ip = ?
	`, p.ServerID, ip).Scan(&existingExpires)
	if err == nil && existingExpires.Valid && existingExpires.Time.After(now) {
		_, _ = db.DB.Exec(`
			UPDATE fail2ban_bans SET hit_count = ?, expires_at = ? WHERE server_id = ? AND ip = ?
		`, hits, expires, p.ServerID, ip)
		return nil
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	comment := fail2BanRuleComment(p.ServerID, ip)
	chain := "INPUT"
	sourceIP := ip
	destIP := s.resolveFail2BanDestinationIP(p.ServerID, serverIP, family)
	if err := s.AddRule(models.IPTablesRuleSpec{
		Family:   family,
		Table:    "filter",
		Chain:    chain,
		Action:   "insert",
		Position: 1,
		Protocol: "tcp",
		SourceIP: sourceIP,
		DestIP:   destIP,
		Target:   "DROP",
		Comment:  comment,
	}); err != nil {
		return err
	}

	_, err = db.DB.Exec(`
		INSERT INTO fail2ban_bans (server_id, ip, hit_count, banned_at, expires_at, reason)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			hit_count = VALUES(hit_count),
			banned_at = VALUES(banned_at),
			expires_at = VALUES(expires_at),
			reason = VALUES(reason)
	`, p.ServerID, ip, hits, now, expires, fmt.Sprintf("status=%s", p.StatusCodes))
	if err != nil {
		return err
	}

	if shouldNotifyFail2BanBan() {
		_ = sendFail2BanBanMail(buildFail2BanMailData(
			p.ServerID,
			ip,
			hits,
			expires,
			formatFail2BanReason(p.StatusCodes),
		))
	}
	return nil
}

func (s *ServerConfigurationService) cleanupExpiredFail2BanBans() error {
	now := time.Now().UTC()
	rows, err := db.DB.Query(`
		SELECT server_id, ip FROM fail2ban_bans WHERE expires_at <= ?
	`, now)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var serverID, ip string
		if err := rows.Scan(&serverID, &ip); err != nil {
			continue
		}
		comment := fail2BanRuleComment(serverID, ip)
		_ = s.DeleteRuleByComment("INPUT", "filter", comment)
		_ = s.DeleteRuleByComment("FORWARD", "filter", comment)
		_, _ = db.DB.Exec(`DELETE FROM fail2ban_bans WHERE server_id = ? AND ip = ?`, serverID, ip)
	}
	return nil
}

func (s *ServerConfigurationService) getServerHosts(serverID string) ([]string, error) {
	rows, err := db.DB.Query(`
		SELECT DISTINCT server_name
		FROM server_configuration
		WHERE fk_server = ?
		  AND server_name <> ''
		  AND server_name <> 'dummy'
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			continue
		}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}

func (s *ServerConfigurationService) getServerIP(serverID string) (string, error) {
	if IsSystemServerID(serverID) {
		return systemServer().IP, nil
	}

	var ip string
	if err := db.DB.QueryRow(`SELECT ip FROM servers WHERE id = ?`, serverID).Scan(&ip); err != nil {
		return "", err
	}
	return strings.TrimSpace(ip), nil
}

func parseStatusCodes(input string) []int {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	out := make([]int, 0, len(parts))
	seen := map[int]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil || v <= 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

type ipMatcher struct {
	ip      net.IP
	network *net.IPNet
}

func parseIPMatchers(input string) []ipMatcher {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	matchers := make([]ipMatcher, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			if _, netw, err := net.ParseCIDR(p); err == nil {
				matchers = append(matchers, ipMatcher{network: netw})
			}
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			matchers = append(matchers, ipMatcher{ip: ip})
		}
	}
	return matchers
}

func ipIgnored(ipStr string, matchers []ipMatcher) bool {
	if len(matchers) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, m := range matchers {
		if m.ip != nil && m.ip.Equal(ip) {
			return true
		}
		if m.network != nil && m.network.Contains(ip) {
			return true
		}
	}
	return false
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", n), ",")
}

func fail2BanRuleComment(serverID, ip string) string {
	return fmt.Sprintf("GoResolver:Fail2Ban:%s:%s", serverID, ip)
}

func fail2BanClientIPExpr(p models.Fail2BanPolicy) string {
	// This remains configurable because some deployments intentionally ban on the
	// original client IP forwarded by a trusted upstream. Analytics stays pinned
	// to remote_addr to avoid skewing charts with spoofed X-Forwarded-For values.
	if p.UseXForwardedFor {
		return analyticsClientIPExpr()
	}
	return "TRIM(remote_addr)"
}

func fail2BanEffectiveHosts(p models.Fail2BanPolicy, hosts []string) []string {
	if p.BanGlobally || IsSystemServerID(p.ServerID) {
		return nil
	}
	return hosts
}

func (s *ServerConfigurationService) resolveManagedRuleDestinationIP(serverID, serverIP, family string) string {
	if !IsSystemServerID(serverID) {
		return firewallDestinationForFamily(serverIP, family)
	}
	settings := NewSettingsService()
	return resolveLocalFirewallDestinationIP(
		family,
		strings.TrimSpace(settings.GetValue("app.base_url")),
		strings.TrimSpace(settings.GetValue("openvpn.remote_host")),
	)
}

func (s *ServerConfigurationService) resolveFail2BanDestinationIP(serverID, serverIP, family string) string {
	if resolved := resolveLocalFirewallDestinationIP(
		family,
		NewSettingsService().GetValue("app.base_url"),
		NewSettingsService().GetValue("openvpn.remote_host"),
	); resolved != "" {
		return resolved
	}
	return s.resolveManagedRuleDestinationIP(serverID, serverIP, family)
}
