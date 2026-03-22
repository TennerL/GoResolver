package services

import (
	"GoResolver/internal/db"
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"sync"
	"time"
)

var analyticsIncidentSyncMu sync.Mutex

type AnalyticsIncident struct {
	ID             int64                    `json:"id"`
	Fingerprint    string                   `json:"fingerprint"`
	Status         string                   `json:"status"`
	Severity       string                   `json:"severity"`
	Title          string                   `json:"title"`
	Summary        string                   `json:"summary"`
	Value          string                   `json:"value"`
	Threshold      string                   `json:"threshold"`
	FirstSeen      string                   `json:"first_seen"`
	LastSeen       string                   `json:"last_seen"`
	LastNotifiedAt string                   `json:"last_notified_at"`
	Context        AnalyticsIncidentContext `json:"context"`
}

type mailConfig struct {
	Host       string
	Port       string
	From       string
	Recipients []string
	Username   string
	Password   string
	Transport  string
}

func (s *AnalyticsService) EnsureAnalyticsIncidentsTable() error {
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS analytics_incidents (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			fingerprint VARCHAR(191) NOT NULL,
			status VARCHAR(32) NOT NULL,
			severity VARCHAR(32) NOT NULL,
			title VARCHAR(255) NOT NULL,
			summary TEXT NOT NULL,
			current_value VARCHAR(255) NOT NULL,
			threshold_value VARCHAR(255) NOT NULL,
			context_json LONGTEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			last_notified_at DATETIME NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_analytics_incidents_fingerprint_status_last_seen (fingerprint, status, last_seen),
			INDEX idx_analytics_incidents_status (status),
			INDEX idx_analytics_incidents_last_seen (last_seen)
		)
	`)
	if err != nil {
		return err
	}
	return s.ensureAnalyticsIncidentIndexes()
}

func (s *AnalyticsService) ensureAnalyticsIncidentIndexes() error {
	uniqueIndexes, err := s.analyticsIncidentUniqueFingerprintIndexes()
	if err != nil {
		return err
	}
	for _, indexName := range uniqueIndexes {
		if _, err := db.DB.Exec(fmt.Sprintf("ALTER TABLE analytics_incidents DROP INDEX `%s`", strings.ReplaceAll(indexName, "`", "``"))); err != nil {
			return err
		}
	}
	hasCompositeIndex, err := s.analyticsIncidentIndexExists("idx_analytics_incidents_fingerprint_status_last_seen")
	if err != nil {
		return err
	}
	if hasCompositeIndex {
		return nil
	}
	_, err = db.DB.Exec(`
		CREATE INDEX idx_analytics_incidents_fingerprint_status_last_seen
		ON analytics_incidents (fingerprint, status, last_seen)
	`)
	return err
}

func (s *AnalyticsService) analyticsIncidentUniqueFingerprintIndexes() ([]string, error) {
	rows, err := db.DB.Query(`
		SELECT DISTINCT index_name
		FROM information_schema.statistics
		WHERE table_schema = DATABASE()
			AND table_name = 'analytics_incidents'
			AND column_name = 'fingerprint'
			AND non_unique = 0
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	indexes := make([]string, 0, 1)
	for rows.Next() {
		var indexName string
		if err := rows.Scan(&indexName); err != nil {
			return nil, err
		}
		if indexName != "" {
			indexes = append(indexes, indexName)
		}
	}
	return indexes, rows.Err()
}

func (s *AnalyticsService) analyticsIncidentIndexExists(indexName string) (bool, error) {
	var found string
	err := db.DB.QueryRow(`
		SELECT index_name
		FROM information_schema.statistics
		WHERE table_schema = DATABASE()
			AND table_name = 'analytics_incidents'
			AND index_name = ?
		LIMIT 1
	`, indexName).Scan(&found)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return found != "", nil
}

func analyticsIncidentIsActiveStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open", "dismissed":
		return true
	default:
		return false
	}
}

func analyticsIncidentsByID(items []AnalyticsIncident) map[int64]AnalyticsIncident {
	byID := make(map[int64]AnalyticsIncident, len(items))
	for _, item := range items {
		byID[item.ID] = item
	}
	return byID
}

func analyticsActiveIncidentsByFingerprint(items []AnalyticsIncident) map[string]AnalyticsIncident {
	byFingerprint := make(map[string]AnalyticsIncident)
	for _, item := range items {
		if !analyticsIncidentIsActiveStatus(item.Status) {
			continue
		}
		current, exists := byFingerprint[item.Fingerprint]
		if !exists || item.LastSeen > current.LastSeen {
			byFingerprint[item.Fingerprint] = item
		}
	}
	return byFingerprint
}

func analyticsIncidentNeedsNotification(previous AnalyticsIncident, existedBefore bool, current AnalyticsIncident) bool {
	if !shouldNotifyIncident(current.Status) {
		return false
	}
	if !existedBefore {
		return current.Status == "open"
	}
	if previous.Status != current.Status {
		return true
	}
	return current.Status == "open" && previous.LastNotifiedAt == ""
}

func (s *AnalyticsService) SyncIncidents() ([]AnalyticsIncident, error) {
	alerts, err := s.buildAlerts(analyticsIncidentFilters())
	if err != nil {
		return nil, err
	}
	return s.syncIncidents(alerts)
}

func (s *AnalyticsService) syncIncidents(alerts []AnalyticsAlert) ([]AnalyticsIncident, error) {
	analyticsIncidentSyncMu.Lock()
	defer analyticsIncidentSyncMu.Unlock()

	if err := s.EnsureAnalyticsIncidentsTable(); err != nil {
		return nil, err
	}

	existing, err := s.Incidents()
	if err != nil {
		return nil, err
	}
	existingByID := analyticsIncidentsByID(existing)
	activeByFingerprint := analyticsActiveIncidentsByFingerprint(existing)

	now := time.Now().UTC()
	seenIDs := make(map[int64]struct{}, len(alerts))
	touchedIDs := make(map[int64]struct{}, len(alerts))
	for _, alert := range alerts {
		fingerprint := alert.ID
		contextJSON, _ := json.Marshal(alert.Context)
		current, exists := activeByFingerprint[fingerprint]
		if !exists {
			result, err := db.DB.Exec(`
				INSERT INTO analytics_incidents
					(fingerprint, status, severity, title, summary, current_value, threshold_value, context_json, first_seen, last_seen)
				VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
			`, fingerprint, alert.Severity, alert.Title, alert.Summary, alert.Value, alert.Threshold, string(contextJSON), now, now)
			if err != nil {
				return nil, err
			}
			insertedID, err := result.LastInsertId()
			if err != nil {
				return nil, err
			}
			touchedIDs[insertedID] = struct{}{}
			continue
		}
		seenIDs[current.ID] = struct{}{}
		touchedIDs[current.ID] = struct{}{}
		nextStatus := "open"
		if current.Status == "dismissed" {
			nextStatus = "dismissed"
		}
		if _, err := db.DB.Exec(`
			UPDATE analytics_incidents
			SET status = ?,
				severity = ?,
				title = ?,
				summary = ?,
				current_value = ?,
				threshold_value = ?,
				context_json = ?,
				last_seen = ?
			WHERE id = ?
		`, nextStatus, alert.Severity, alert.Title, alert.Summary, alert.Value, alert.Threshold, string(contextJSON), now, current.ID); err != nil {
			return nil, err
		}
	}

	for _, incident := range existing {
		if !analyticsIncidentIsActiveStatus(incident.Status) {
			continue
		}
		if _, ok := seenIDs[incident.ID]; ok {
			continue
		}
		touchedIDs[incident.ID] = struct{}{}
		if _, err := db.DB.Exec(`
			UPDATE analytics_incidents
			SET status = 'resolved', last_seen = ?
			WHERE id = ?
		`, now, incident.ID); err != nil {
			return nil, err
		}
	}

	updated, err := s.Incidents()
	if err != nil {
		return nil, err
	}
	updatedByID := analyticsIncidentsByID(updated)
	for incidentID := range touchedIDs {
		incident, ok := updatedByID[incidentID]
		if !ok {
			continue
		}
		existingIncident, existedBefore := existingByID[incidentID]
		if !analyticsIncidentNeedsNotification(existingIncident, existedBefore, incident) {
			continue
		}
		if err := sendAnalyticsIncidentMail(incident); err == nil {
			_, _ = db.DB.Exec(`UPDATE analytics_incidents SET last_notified_at = ? WHERE id = ?`, time.Now().UTC(), incident.ID)
		}
	}

	return updated, nil
}

func (s *AnalyticsService) Incidents() ([]AnalyticsIncident, error) {
	if err := s.EnsureAnalyticsIncidentsTable(); err != nil {
		return nil, err
	}
	rows, err := db.DB.Query(`
		SELECT id, fingerprint, status, severity, title, summary, current_value, threshold_value, context_json, first_seen, last_seen, last_notified_at
		FROM analytics_incidents
		ORDER BY
			CASE status WHEN 'open' THEN 0 WHEN 'dismissed' THEN 1 ELSE 2 END,
			last_seen DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AnalyticsIncident, 0, 16)
	for rows.Next() {
		var (
			item           AnalyticsIncident
			contextJSON    string
			firstSeen      time.Time
			lastSeen       time.Time
			lastNotifiedAt *time.Time
		)
		if err := rows.Scan(&item.ID, &item.Fingerprint, &item.Status, &item.Severity, &item.Title, &item.Summary, &item.Value, &item.Threshold, &contextJSON, &firstSeen, &lastSeen, &lastNotifiedAt); err != nil {
			return nil, err
		}
		item.FirstSeen = firstSeen.UTC().Format(time.RFC3339)
		item.LastSeen = lastSeen.UTC().Format(time.RFC3339)
		if lastNotifiedAt != nil {
			item.LastNotifiedAt = lastNotifiedAt.UTC().Format(time.RFC3339)
		}
		_ = json.Unmarshal([]byte(contextJSON), &item.Context)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status != items[j].Status {
			return analyticsIncidentStatusRank(items[i].Status) < analyticsIncidentStatusRank(items[j].Status)
		}
		return items[i].LastSeen > items[j].LastSeen
	})
	return items, nil
}

func (s *AnalyticsService) DismissIncident(id int64) error {
	if err := s.EnsureAnalyticsIncidentsTable(); err != nil {
		return err
	}
	if id <= 0 {
		return fmt.Errorf("invalid incident id")
	}
	_, err := db.DB.Exec(`
		UPDATE analytics_incidents
		SET status = 'dismissed'
		WHERE id = ? AND status = 'open'
	`, id)
	return err
}

func (s *AnalyticsService) DeleteIncident(id int64) error {
	if err := s.EnsureAnalyticsIncidentsTable(); err != nil {
		return err
	}
	if id <= 0 {
		return fmt.Errorf("invalid incident id")
	}
	result, err := db.DB.Exec(`
		DELETE FROM analytics_incidents
		WHERE id = ? AND status <> 'open'
	`, id)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("incident not found or still open")
	}
	return nil
}

func analyticsIncidentStatusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open":
		return 0
	case "dismissed":
		return 1
	case "resolved":
		return 2
	default:
		return 3
	}
}

func shouldNotifyIncident(status string) bool {
	settings := NewSettingsService()
	switch status {
	case "open":
		return settingEnabledForSettings(settings.GetValue("mail.notify_on_open"), true)
	case "resolved":
		return settingEnabledForSettings(settings.GetValue("mail.notify_on_resolved"), false)
	default:
		return false
	}
}

func sendAnalyticsIncidentMail(incident AnalyticsIncident) error {
	settings := NewSettingsService()
	config, err := loadMailConfig(settings)
	if err != nil {
		return err
	}
	subjectTemplate := settings.GetValue("mail.subject_template")
	if strings.TrimSpace(subjectTemplate) == "" {
		subjectTemplate = "[GoResolver] {{severity}} {{status}}: {{title}}"
	}
	bodyTemplate := settings.GetValue("mail.body_template")
	if strings.TrimSpace(bodyTemplate) == "" {
		bodyTemplate = "GoResolver analytics incident\n\nTitle: {{title}}\nSeverity: {{severity}}\nStatus: {{status}}\nValue: {{value}}\nThreshold: {{threshold}}\nSummary: {{summary}}\nFirst seen: {{first_seen}}\nLast seen: {{last_seen}}\nTop hosts: {{top_hosts}}\nTop IPs: {{top_ips}}\nTop URIs: {{top_uris}}\n"
	}
	htmlTemplate := settings.GetValue("mail.html_template")
	if strings.TrimSpace(htmlTemplate) == "" {
		htmlTemplate = defaultIncidentHTMLTemplate()
	}

	subject := renderIncidentTemplate(subjectTemplate, incident)
	textBody := strings.ReplaceAll(renderIncidentTemplate(bodyTemplate, incident), "\n", "\r\n")
	htmlBody := renderIncidentHTMLTemplate(htmlTemplate, incident)
	return sendRenderedMail(config, subject, textBody, htmlBody)
}

func loadMailConfig(settings *SettingsService) (mailConfig, error) {
	host := strings.TrimSpace(settings.GetValue("mail.smtp_host"))
	port := strings.TrimSpace(settings.GetValue("mail.smtp_port"))
	from := strings.TrimSpace(settings.GetValue("mail.from"))
	toRaw := strings.TrimSpace(settings.GetValue("mail.to"))
	username := strings.TrimSpace(settings.GetValue("mail.username"))
	password := settings.GetValue("mail.password")
	transport := normalizeMailTransport(settings.GetValue("mail.transport"), settings.GetValue("mail.starttls"))
	if host == "" || port == "" || from == "" || toRaw == "" {
		return mailConfig{}, fmt.Errorf("mail settings incomplete")
	}
	recipients := make([]string, 0, 4)
	for _, part := range strings.Split(toRaw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			recipients = append(recipients, part)
		}
	}
	if len(recipients) == 0 {
		return mailConfig{}, fmt.Errorf("no recipients configured")
	}
	return mailConfig{
		Host: host, Port: port, From: from, Recipients: recipients,
		Username: username, Password: password, Transport: transport,
	}, nil
}

func sendRenderedMail(config mailConfig, subject, textBody, htmlBody string) error {
	message := buildMultipartMailMessage(config.From, config.Recipients, subject, textBody, htmlBody)
	addr := config.Host + ":" + config.Port
	switch config.Transport {
	case "smtp":
		return sendMailPlainSMTP(config.Host, addr, config.From, config.Recipients, message, config.Username, config.Password)
	case "smtps":
		return sendMailImplicitTLS(config.Host, addr, config.From, config.Recipients, message, config.Username, config.Password)
	case "starttls":
		return sendMailSTARTTLS(config.Host, addr, config.From, config.Recipients, message, config.Username, config.Password)
	default:
		return fmt.Errorf("unsupported mail transport: %s", config.Transport)
	}
}

func buildMultipartMailMessage(from string, recipients []string, subject, textBody, htmlBody string) []byte {
	boundary := fmt.Sprintf("goresolver-%d", time.Now().UnixNano())
	var builder strings.Builder
	builder.WriteString("To: " + strings.Join(recipients, ", ") + "\r\n")
	builder.WriteString("Subject: " + subject + "\r\n")
	builder.WriteString("From: " + from + "\r\n")
	builder.WriteString("MIME-Version: 1.0\r\n")
	builder.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	builder.WriteString("--" + boundary + "\r\n")
	builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	builder.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	builder.WriteString(textBody + "\r\n")
	builder.WriteString("--" + boundary + "\r\n")
	builder.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	builder.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	builder.WriteString(htmlBody + "\r\n")
	builder.WriteString("--" + boundary + "--\r\n")
	return []byte(builder.String())
}

func defaultIncidentHTMLTemplate() string {
	return `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#f3f4f6;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;">
    <div style="max-width:760px;margin:0 auto;padding:24px;">
      <div style="background:linear-gradient(135deg,#111827,#1f2937);color:#f8fafc;border-radius:18px;padding:24px 28px;">
        <div style="font-size:12px;letter-spacing:0.14em;text-transform:uppercase;color:#93c5fd;margin-bottom:8px;">GoResolver Incident Report</div>
        <h1 style="margin:0 0 10px;font-size:28px;line-height:1.1;">{{title}}</h1>
        <p style="margin:0;color:#cbd5e1;font-size:15px;line-height:1.6;">{{summary}}</p>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px;">
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Severity</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{severity}}</div></div>
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Status</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{status}}</div></div>
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Value</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{value}}</div></div>
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Threshold</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{threshold}}</div></div>
      </div>
      <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:18px;padding:22px 24px;margin-top:16px;">
        <h2 style="margin:0 0 14px;font-size:18px;">Incident context</h2>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr><td style="padding:8px 0;color:#64748b;width:140px;">First seen</td><td style="padding:8px 0;">{{first_seen}}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Last seen</td><td style="padding:8px 0;">{{last_seen}}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Top hosts</td><td style="padding:8px 0;">{{top_hosts}}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Top IPs</td><td style="padding:8px 0;">{{top_ips}}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Top URIs</td><td style="padding:8px 0;">{{top_uris}}</td></tr>
        </table>
      </div>
      <div style="margin-top:12px;color:#64748b;font-size:12px;text-align:center;">Sent by GoResolver analytics.</div>
    </div>
  </body>
</html>`
}

func renderIncidentHTMLTemplate(template string, incident AnalyticsIncident) string {
	replacements := map[string]string{
		"{{title}}":      html.EscapeString(incident.Title),
		"{{severity}}":   html.EscapeString(strings.ToUpper(incident.Severity)),
		"{{status}}":     html.EscapeString(strings.ToUpper(incident.Status)),
		"{{summary}}":    html.EscapeString(incident.Summary),
		"{{value}}":      html.EscapeString(incident.Value),
		"{{threshold}}":  html.EscapeString(incident.Threshold),
		"{{first_seen}}": html.EscapeString(incident.FirstSeen),
		"{{last_seen}}":  html.EscapeString(incident.LastSeen),
		"{{top_hosts}}":  html.EscapeString(strings.Join(incident.Context.Hosts, ", ")),
		"{{top_ips}}":    html.EscapeString(strings.Join(incident.Context.TopIPs, ", ")),
		"{{top_uris}}":   html.EscapeString(strings.Join(incident.Context.TopURIs, ", ")),
	}
	out := template
	for key, value := range replacements {
		out = strings.ReplaceAll(out, key, value)
	}
	return out
}

func normalizeMailTransport(rawTransport, legacyStartTLS string) string {
	switch strings.ToLower(strings.TrimSpace(rawTransport)) {
	case "smtp", "starttls", "smtps":
		return strings.ToLower(strings.TrimSpace(rawTransport))
	}
	if settingEnabledForSettings(legacyStartTLS, true) {
		return "smtps"
	}
	return "smtp"
}

func sendMailImplicitTLS(host, addr, from string, recipients []string, message []byte, username, password string) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	return sendWithSMTPClient(client, host, from, recipients, message, username, password)
}

func sendMailSTARTTLS(host, addr, from string, recipients []string, message []byte, username, password string) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("smtp server does not support STARTTLS")
	}
	if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
		return err
	}
	return sendWithSMTPClient(client, host, from, recipients, message, username, password)
}

func sendMailPlainSMTP(host, addr, from string, recipients []string, message []byte, username, password string) error {
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return sendWithSMTPClient(client, host, from, recipients, message, username, password)
}

func sendWithSMTPClient(client *smtp.Client, host, from string, recipients []string, message []byte, username, password string) error {
	defer client.Close()

	if err := authenticateSMTPClient(client, host, username, password); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func authenticateSMTPClient(client *smtp.Client, host, username, password string) error {
	if username == "" {
		return nil
	}
	ok, authLine := client.Extension("AUTH")
	if !ok {
		return fmt.Errorf("smtp server does not advertise AUTH")
	}

	mechanisms := strings.Fields(strings.ToUpper(strings.TrimSpace(authLine)))
	for _, mechanism := range mechanisms {
		switch mechanism {
		case "LOGIN":
			return client.Auth(loginAuth(username, password))
		case "PLAIN":
			return client.Auth(smtp.PlainAuth("", username, password, host))
		}
	}
	return fmt.Errorf("smtp server does not support a compatible auth mechanism (offered: %s)", authLine)
}

func renderIncidentTemplate(template string, incident AnalyticsIncident) string {
	replacements := map[string]string{
		"{{title}}":      incident.Title,
		"{{severity}}":   incident.Severity,
		"{{status}}":     incident.Status,
		"{{summary}}":    incident.Summary,
		"{{value}}":      incident.Value,
		"{{threshold}}":  incident.Threshold,
		"{{first_seen}}": incident.FirstSeen,
		"{{last_seen}}":  incident.LastSeen,
		"{{top_hosts}}":  strings.Join(incident.Context.Hosts, ", "),
		"{{top_ips}}":    strings.Join(incident.Context.TopIPs, ", "),
		"{{top_uris}}":   strings.Join(incident.Context.TopURIs, ", "),
	}
	out := template
	for key, value := range replacements {
		out = strings.ReplaceAll(out, key, value)
	}
	return out
}

func (s *AnalyticsService) SendTestMail() error {
	incident := AnalyticsIncident{
		Fingerprint: "test",
		Status:      "test",
		Severity:    "info",
		Title:       "Test mail",
		Summary:     "This is a test email from GoResolver.",
		Value:       "n/a",
		Threshold:   "n/a",
		FirstSeen:   time.Now().UTC().Format(time.RFC3339),
		LastSeen:    time.Now().UTC().Format(time.RFC3339),
		Context: AnalyticsIncidentContext{
			Hosts:   []string{"example.com"},
			TopIPs:  []string{"203.0.113.10"},
			TopURIs: []string{"/health", "/login"},
		},
	}
	return sendAnalyticsIncidentMail(incident)
}

type smtpLoginAuth struct {
	username string
	password string
}

func loginAuth(username, password string) smtp.Auth {
	return &smtpLoginAuth{username: username, password: password}
}

func (a *smtpLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *smtpLoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := strings.ToLower(strings.TrimSpace(string(bytes.TrimSpace(fromServer))))
	switch {
	case strings.Contains(prompt, "username"):
		return []byte(a.username), nil
	case strings.Contains(prompt, "password"):
		return []byte(a.password), nil
	default:
		if len(fromServer) == 0 {
			return []byte(a.username), nil
		}
		rawPrompt := strings.ToLower(strings.TrimSpace(string(bytes.TrimSpace(fromServer))))
		if strings.Contains(rawPrompt, "username") {
			return []byte(a.username), nil
		}
		if strings.Contains(rawPrompt, "password") {
			return []byte(a.password), nil
		}
		return nil, fmt.Errorf("unexpected LOGIN challenge")
	}
}
