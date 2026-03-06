package handlers

import (
	"net/http"

	"GoResolver/internal/models"
)

func (h *ServerHandler) BuildPage() models.PageData {
	suggestedIP, _ := h.Service.SuggestNextVPNIP()
	return models.PageData{
		Active:      "servers",
		View:        "servers",
		Data:        h.Service.GetServers(),
		SuggestedIP: suggestedIP,
	}
}

func (h *ServerHandler) API(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.BuildPage())
}
