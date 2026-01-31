package services

import (
	"net"
	"os/exec"
	"time"
	"GoResolver/internal/models"
)

type SystemService struct {}

func NewSystemService() *SystemService {
	return &SystemService{}
}

func (s *SystemService) GetDashboardData() []models.Dashboard {
	data := []models.Dashboard{}
	settings := NewSettingsService()

	dnsStatus := "Offline"
	conn, err := net.DialTimeout("udp", settings.GetValue("system.dns_probe_addr"), 2*time.Second)
	if err == nil {
		dnsStatus = "Online"
		conn.Close()
	}
	data = append(data, models.Dashboard{Name: "DNS", Status: dnsStatus})

	healthName := settings.GetValue("vpn.healthcheck_name")
	healthIP := settings.GetValue("vpn.healthcheck_ip")
	if healthName != "" && healthIP != "" {
		vpnStatus := "Offline"
		err = exec.Command("ping", "-c", "1", "-W", "1", healthIP).Run()
		if err == nil {
			vpnStatus = "Online"
		}

		data = append(data, models.Dashboard{Name: healthName, Status: vpnStatus})
	}
	return data
}
