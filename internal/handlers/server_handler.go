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

func (h *ServerHandler) AddServer(w http.ResponseWriter, r *http.Request) {
	
	name := r.FormValue("friendlyName")
	ip := r.FormValue("desiredIP")
	
	server := models.Server{
		Name: name,
		IP: ip,
	}

	err := h.Service.AddServer(server)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w,r, "/servers", http.StatusSeeOther)
}