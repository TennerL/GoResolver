package handlers

import (
	"html/template"
	"net/http"
	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type DomainsHandler struct {
	Tmpl    *template.Template
	Service *services.DomainService
}

func NewDomainsHandler() *DomainsHandler {
	return &DomainsHandler{
		Service: services.NewDomainService(),
		Tmpl: parseTemplatesWithFuncMap(
			baseFuncMap(),
			"web/templates/layout.html",
			"web/templates/domains.html",
		),
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

	err := h.Service.CreateDomain(name)
	if err != nil {
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
	err := h.Service.DeleteDomain(id)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w,r, "/domains", http.StatusSeeOther)
}


func (h *DomainsHandler) Index(w http.ResponseWriter, r *http.Request) {

	page := models.PageData{
		Active: "domains",
		Data:   h.Service.GetDomains(),
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}
