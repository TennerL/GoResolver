package services

import (
	"GoResolver/internal/models"
	"strings"
)

type SystemService struct {}

func NewSystemService() *SystemService {
	return &SystemService{}
}

func (s *SystemService) GetDashboardData() []models.Dashboard {
	data := []models.Dashboard{}
	settings := NewSettingsService()
	monitor := DefaultStatusMonitor()

	data = append(data, models.Dashboard{
		Name:   "DNS",
		Status: monitor.GetDNSStatus(settings.GetValue("system.dns_probe_addr")),
	})

	healthName := strings.TrimSpace(settings.GetValue("vpn.healthcheck_name"))
	healthIP := strings.TrimSpace(settings.GetValue("vpn.healthcheck_ip"))
	if healthName != "" && healthIP != "" {
		data = append(data, models.Dashboard{
			Name:   healthName,
			Status: monitor.GetPingStatus(healthIP),
		})
	}
	return data
}
