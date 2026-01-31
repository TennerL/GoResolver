package handlers 

import (
	"html/template"
	"net/http"
	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type ServerHandler struct {
	Tmpl *template.Template
	Service *services.ServerService
}

func NewServerHandler() *ServerHandler {
	return &ServerHandler{
		Service: services.NewServerService(),
		Tmpl: parseTemplatesWithFuncMap(
			baseFuncMap(),
			"web/templates/layout.html",
			"web/templates/servers.html",
		),
	}
}

func (h *ServerHandler) Index(w http.ResponseWriter, r *http.Request) {
	suggestedIP, _ := h.Service.SuggestNextVPNIP()
	page := models.PageData{
		Active: "servers",
		Data: h.Service.GetServers(),
		SuggestedIP: suggestedIP,
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

func (h *ServerHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := mux.Vars(r)["id"]
	if serverID == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}

	if err := h.Service.DeleteServer(serverID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}
