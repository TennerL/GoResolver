package handlers

import (
	"net/http"
	"strings"

	"GoResolver/internal/services"
)

type SettingsHandler struct {
	Service *services.SettingsService
}

func NewSettingsHandler() *SettingsHandler {
	return &SettingsHandler{
		Service: services.NewSettingsService(),
	}
}

func (h *SettingsHandler) Index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	values := map[string]string{}
	for _, item := range h.Service.EditableSettings() {
		if item.ReadOnly {
			continue
		}
		values[item.Key] = strings.TrimSpace(r.FormValue(item.Key))
	}

	if err := h.Service.SetMany(values); err != nil {
		http.Error(w, "Failed to save settings", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}
