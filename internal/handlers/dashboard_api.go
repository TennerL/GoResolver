package handlers

import (
	"net/http"

	"GoResolver/internal/models"
)

func (h *DashboardHandler) BuildPage() models.PageData {
	return models.PageData{
		Active:  "dashboard",
		View:    "dashboard",
		Data:    h.Service.GetDashboardData(),
		Servers: h.ServerService.GetServers(),
	}
}

func (h *DashboardHandler) API(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.BuildPage())
}
