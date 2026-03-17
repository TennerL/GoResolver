package handlers

import (
	"net/http"

	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type DomainsHandler struct {
	Service *services.DomainService
}

func NewDomainsHandler() *DomainsHandler {
	return &DomainsHandler{
		Service: services.NewDomainService(),
	}
}

func (h *DomainsHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "Domain name required", http.StatusBadRequest)
		return
	}

	if err := h.Service.CreateDomain(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}

func (h *DomainsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}
	if err := h.Service.DeleteDomain(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}
