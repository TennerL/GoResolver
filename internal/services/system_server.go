package services

import (
	"GoResolver/internal/models"
	"strconv"
	"strings"
)

const (
	systemServerID   = 0
	systemServerName = "GoResolver"
)

func IsSystemServerID(serverID string) bool {
	return strings.TrimSpace(serverID) == strconv.Itoa(systemServerID)
}

func systemServer() models.Server {
	ip := resolveLocalFirewallDestinationIP(
		firewallFamilyIPv4,
		NewSettingsService().GetValue("app.base_url"),
		NewSettingsService().GetValue("openvpn.remote_host"),
	)
	if ip == "" {
		ip = resolveLocalFirewallDestinationIP(
			firewallFamilyIPv6,
			NewSettingsService().GetValue("app.base_url"),
			NewSettingsService().GetValue("openvpn.remote_host"),
		)
	}

	status := "Unknown"
	if ip != "" {
		status = DefaultStatusMonitor().GetPingStatus(ip)
	}

	return models.Server{
		ID:       systemServerID,
		Name:     systemServerName,
		IP:       ip,
		Status:   status,
		IsSystem: true,
	}
}
