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

	dnsStatus := "Offline"
	conn, err := net.DialTimeout("udp", "127.0.0.1:53", 2*time.Second)
	if err == nil {
		dnsStatus = "Online"
		conn.Close()
	}
	data = append(data, models.Dashboard{Name: "DNS", Status: dnsStatus})

	vpnStatus := "Offline"
	err = exec.Command("ping", "-c", "1", "-W", "1", "10.8.0.6").Run()
	if err == nil {
		vpnStatus = "Online"
	}

	data = append(data, models.Dashboard{Name: "web.nihonsaba.intern", Status: vpnStatus})
	return data
}
