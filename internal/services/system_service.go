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

	vpnStatus := "Offline"
	err = exec.Command("ping", "-c", "1", "-W", "1", settings.GetValue("vpn.healthcheck_ip")).Run()
	if err == nil {
		vpnStatus = "Online"
	}

	data = append(data, models.Dashboard{Name: settings.GetValue("vpn.healthcheck_name"), Status: vpnStatus})
	return data
}
