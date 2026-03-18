package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"GoResolver/internal/models"
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

	if err := parseRequestForm(r); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	values := submittedEditableSettings(r.Form, h.Service.EditableSettings())

	if err := h.Service.SetMany(values); err != nil {
		http.Error(w, "Failed to save settings", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (h *SettingsHandler) SendTestMail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	analytics := services.NewAnalyticsService()
	if err := analytics.SendTestMail(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Test mail sent.",
	})
}

func parseRequestForm(r *http.Request) error {
	if err := r.ParseMultipartForm(32 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return err
	}
	return r.ParseForm()
}

func submittedEditableSettings(form url.Values, items []models.SettingItem) map[string]string {
	values := map[string]string{}
	for _, item := range items {
		if item.ReadOnly {
			continue
		}
		if _, ok := form[item.Key]; !ok {
			continue
		}
		values[item.Key] = strings.TrimSpace(form.Get(item.Key))
	}
	return values
}
