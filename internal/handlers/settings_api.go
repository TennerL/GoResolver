package handlers

import (
	"net/http"

	"GoResolver/internal/models"
)

func (h *SettingsHandler) BuildPage(r *http.Request) models.PageData {
	return models.PageData{
		Active: "settings",
		View:   "settings",
		Data: models.SettingsPageData{
			Items: h.Service.EditableSettings(),
			Saved: r.URL.Query().Get("saved") == "1",
		},
	}
}

func (h *SettingsHandler) API(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.BuildPage(r))
}
