package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"log"
	"os/exec"
)

type ServerService struct{}

func NewServerService() *ServerService {
	return &ServerService{}
}

func (s *ServerService) GetServers() []models.Server {
	rows, err := db.DB.Query("SELECT id, domain_id, name, ip, vpn_file FROM servers ORDER BY id")
	if err != nil {
		log.Println("DB query error:", err)
		return nil
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.Domain_ID, &srv.Name, &srv.IP, &srv.VPN_File); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		srv.Status = checkStatus(srv.IP) 
		servers = append(servers, srv)
	}

	if err := rows.Err(); err != nil {
		log.Println("Rows iteration error:", err)
	}

	return servers
}

func checkStatus(ip string) string {
	serverStatus := "Offline"
	err := exec.Command("ping", "-c", "1", "-W", "1", ip).Run()
	if err == nil {
		serverStatus = "Online"
	}
	return serverStatus
}
