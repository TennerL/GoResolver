package services

import (
	"fmt"
	"html"
	"strings"
	"time"
)

func sendLoginFailureMail(username, ip string, attemptedAt time.Time, reason string, ipFailures, userFailures int, blockedUntil time.Time) error {
	config, err := loadMailConfig(NewSettingsService())
	if err != nil {
		return err
	}
	blocked := "no"
	if blockedUntil.After(attemptedAt) {
		blocked = blockedUntil.UTC().Format(time.RFC3339)
	}
	subject := fmt.Sprintf("[GoResolver] Failed login from %s", ip)
	textBody := fmt.Sprintf("GoResolver failed login\n\nTime: %s\nIP: %s\nUsername: %s\nReason: %s\nIP failures: %d/%d\nUser failures: %d/%d\nIP blocked until: %s\n", attemptedAt.UTC().Format(time.RFC3339), ip, username, reason, ipFailures, loginIPMaxFailures, userFailures, loginUserMaxFailures, blocked)
	htmlBody := fmt.Sprintf("<h2>GoResolver failed login</h2><p><b>Time:</b> %s<br><b>IP:</b> %s<br><b>Username:</b> %s<br><b>Reason:</b> %s<br><b>IP failures:</b> %d/%d<br><b>User failures:</b> %d/%d<br><b>IP blocked until:</b> %s</p>", html.EscapeString(attemptedAt.UTC().Format(time.RFC3339)), html.EscapeString(ip), html.EscapeString(username), html.EscapeString(reason), ipFailures, loginIPMaxFailures, userFailures, loginUserMaxFailures, html.EscapeString(blocked))
	return sendRenderedMail(config, subject, strings.ReplaceAll(textBody, "\n", "\r\n"), htmlBody)
}
