package services

import (
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"
)

type fail2BanMailData struct {
	ServerID  string
	IP        string
	Hits      int
	BannedAt  string
	ExpiresAt string
	Reason    string
}

func shouldNotifyFail2BanBan() bool {
	settings := NewSettingsService()
	return settingEnabledForSettings(settings.GetValue("mail.notify_on_fail2ban_ban"), true)
}

func sendFail2BanBanMail(data fail2BanMailData) error {
	settings := NewSettingsService()
	config, err := loadMailConfig(settings)
	if err != nil {
		return err
	}

	subjectTemplate := settings.GetValue("mail.fail2ban_subject_template")
	if strings.TrimSpace(subjectTemplate) == "" {
		subjectTemplate = "[GoResolver] Fail2Ban ban: {{ip}} on server {{server_id}}"
	}
	bodyTemplate := settings.GetValue("mail.fail2ban_body_template")
	if strings.TrimSpace(bodyTemplate) == "" {
		bodyTemplate = "GoResolver Fail2Ban ban\n\nServer ID: {{server_id}}\nIP: {{ip}}\nHits: {{hits}}\nBanned at: {{banned_at}}\nExpires at: {{expires_at}}\nReason: {{reason}}\n"
	}
	htmlTemplate := settings.GetValue("mail.fail2ban_html_template")
	if strings.TrimSpace(htmlTemplate) == "" {
		htmlTemplate = defaultFail2BanHTMLTemplate()
	}

	subject := renderFail2BanTemplate(subjectTemplate, data)
	textBody := strings.ReplaceAll(renderFail2BanTemplate(bodyTemplate, data), "\n", "\r\n")
	htmlBody := renderFail2BanHTMLTemplate(htmlTemplate, data)
	return sendRenderedMail(config, subject, textBody, htmlBody)
}

func renderFail2BanTemplate(template string, data fail2BanMailData) string {
	replacements := map[string]string{
		"{{server_id}}":  data.ServerID,
		"{{ip}}":         data.IP,
		"{{hits}}":       strconv.Itoa(data.Hits),
		"{{banned_at}}":  data.BannedAt,
		"{{expires_at}}": data.ExpiresAt,
		"{{reason}}":     data.Reason,
	}
	out := template
	for key, value := range replacements {
		out = strings.ReplaceAll(out, key, value)
	}
	return out
}

func renderFail2BanHTMLTemplate(template string, data fail2BanMailData) string {
	replacements := map[string]string{
		"{{server_id}}":  html.EscapeString(data.ServerID),
		"{{ip}}":         html.EscapeString(data.IP),
		"{{hits}}":       html.EscapeString(strconv.Itoa(data.Hits)),
		"{{banned_at}}":  html.EscapeString(data.BannedAt),
		"{{expires_at}}": html.EscapeString(data.ExpiresAt),
		"{{reason}}":     html.EscapeString(data.Reason),
	}
	out := template
	for key, value := range replacements {
		out = strings.ReplaceAll(out, key, value)
	}
	return out
}

func defaultFail2BanHTMLTemplate() string {
	return `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#f3f4f6;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;">
    <div style="max-width:700px;margin:0 auto;padding:24px;">
      <div style="background:linear-gradient(135deg,#7f1d1d,#991b1b);color:#fff;border-radius:18px;padding:24px 28px;">
        <div style="font-size:12px;letter-spacing:0.14em;text-transform:uppercase;color:#fecaca;margin-bottom:8px;">GoResolver Fail2Ban</div>
        <h1 style="margin:0;font-size:28px;line-height:1.1;">IP blocked: {{ip}}</h1>
      </div>
      <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:16px;">
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Server</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{server_id}}</div></div>
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Hits</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{hits}}</div></div>
        <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;">Expires</div><div style="margin-top:8px;font-size:20px;font-weight:700;">{{expires_at}}</div></div>
      </div>
      <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:18px;padding:22px 24px;margin-top:16px;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr><td style="padding:8px 0;color:#64748b;width:140px;">Blocked at</td><td style="padding:8px 0;">{{banned_at}}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b;">Reason</td><td style="padding:8px 0;">{{reason}}</td></tr>
        </table>
      </div>
      <div style="margin-top:12px;color:#64748b;font-size:12px;text-align:center;">Sent by GoResolver Fail2Ban.</div>
    </div>
  </body>
</html>`
}

func buildFail2BanMailData(serverID, ip string, hits int, expires time.Time, reason string) fail2BanMailData {
	now := time.Now().UTC()
	return fail2BanMailData{
		ServerID:  serverID,
		IP:        ip,
		Hits:      hits,
		BannedAt:  now.Format(time.RFC3339),
		ExpiresAt: expires.UTC().Format(time.RFC3339),
		Reason:    strings.TrimSpace(reason),
	}
}

func formatFail2BanReason(statusCodes string) string {
	statusCodes = strings.TrimSpace(statusCodes)
	if statusCodes == "" {
		return "Matched Fail2Ban policy"
	}
	return fmt.Sprintf("Matched configured status codes: %s", statusCodes)
}
