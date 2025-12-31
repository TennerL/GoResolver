package handlers 

import (
	"html/template"
	"net/http"
	"GoResolver/internal/models"
	"GoResolver/internal/services"
)

type ServerHandler struct {
	Tmpl *template.Template
	Service *services.ServerService
}

func NewServerHandler() *ServerHandler {
	return &ServerHandler{
		Service: services.NewServerService(),
		Tmpl: template.Must(template.ParseFiles(
			"web/templates/layout.html",
			"web/templates/servers.html",
		)),
	}
}

func (h *ServerHandler) Index(w http.ResponseWriter, r *http.Request) {
	page := models.PageData{
		Active: "servers",
		Data: h.Service.GetServers(),
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}