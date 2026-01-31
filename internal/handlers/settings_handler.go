package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"GoResolver/internal/models"
	"GoResolver/internal/services"
)

type SettingsHandler struct {
	Service *services.SettingsService
	Tmpl    *template.Template
}

func NewSettingsHandler() *SettingsHandler {
	return &SettingsHandler{
		Service: services.NewSettingsService(),
		Tmpl: parseTemplatesWithFuncMap(
			baseFuncMap(),
			"web/templates/layout.html",
			"web/templates/settings.html",
		),
	}
}

func (h *SettingsHandler) Index(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		values := map[string]string{}
		for _, item := range h.Service.EditableSettings() {
			values[item.Key] = strings.TrimSpace(r.FormValue(item.Key))
		}

		if err := h.Service.SetMany(values); err != nil {
			http.Error(w, "Failed to save settings", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
		return
	}

	items := h.Service.EditableSettings()
	saved := r.URL.Query().Get("saved") == "1"

	page := models.PageData{
		Active: "settings",
		Data: models.SettingsPageData{
			Items: items,
			Saved: saved,
		},
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}
