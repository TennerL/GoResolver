package handlers

import (
	"net/http"

	"GoResolver/internal/models"
	"github.com/gorilla/mux"
)

func (h *RecordHandler) BuildPage(domainID string) models.PageData {
	return models.PageData{
		Active:   "domains",
		View:     "records",
		Data:     h.Service.GetRecords(domainID),
		DomainID: domainID,
	}
}

func (h *RecordHandler) API(w http.ResponseWriter, r *http.Request) {
	domainID := mux.Vars(r)["id"]
	if domainID == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, h.BuildPage(domainID))
}
