package handlers

import (
	"net/http"

	"GoResolver/internal/models"
)

func (h *DomainsHandler) BuildPage() models.PageData {
	return models.PageData{
		Active: "domains",
		View:   "domains",
		Data:   h.Service.GetDomains(),
	}
}

func (h *DomainsHandler) API(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.BuildPage())
}
