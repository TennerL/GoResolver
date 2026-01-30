package handlers

import (
	"html/template"
	"net/http"

	"GoResolver/internal/models"
	"GoResolver/internal/services"
)

type DashboardHandler struct {
	Service *services.SystemService
	Tmpl    *template.Template
}

func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{
		Service: services.NewSystemService(),
		Tmpl: parseTemplatesWithFuncMap(
			baseFuncMap(),
			"web/templates/layout.html",
			"web/templates/dashboard.html",
		),
	}
}

func (h *DashboardHandler) Index(w http.ResponseWriter, r *http.Request) {
	page := models.PageData{
		Active: "dashboard",
		Data:   h.Service.GetDashboardData(),
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}
