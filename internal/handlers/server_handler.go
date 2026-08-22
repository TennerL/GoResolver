package handlers

import (
	"net/http"

	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type ServerHandler struct {
	Service       *services.ServerService
	ConfigService *services.ServerConfigurationService
}

func NewServerHandler() *ServerHandler {
	return &ServerHandler{
		Service:       services.NewServerService(),
		ConfigService: services.NewServerConfigurationService(),
	}
}

func (h *ServerHandler) RedeployAll(w http.ResponseWriter, r *http.Request) {
	result, err := h.ConfigService.RedeployAllNginxConfigs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       len(result.Failed) == 0,
		"deployed": result.Deployed,
		"failed":   result.Failed,
	})
}

func (h *ServerHandler) AddServer(w http.ResponseWriter, r *http.Request) {
	server := models.Server{
		Name: r.FormValue("friendlyName"),
		IP:   r.FormValue("desiredIP"),
	}

	if err := h.Service.AddServer(server); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/servers", http.StatusSeeOther)
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
	if serverID == "0" {
		http.Error(w, "System server cannot be deleted", http.StatusBadRequest)
		return
	}

	if err := h.Service.DeleteServer(serverID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}
