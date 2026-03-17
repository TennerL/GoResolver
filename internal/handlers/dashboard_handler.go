package handlers

import "GoResolver/internal/services"

type DashboardHandler struct {
	Service       *services.SystemService
	ServerService *services.ServerService
}

func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{
		Service:       services.NewSystemService(),
		ServerService: services.NewServerService(),
	}
}
