package handlers

import (
	"net/http"

	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type RecordHandler struct {
	Service *services.RecordService
}

func NewRecordHandler() *RecordHandler {
	return &RecordHandler{
		Service: services.NewRecordService(),
	}
}

func (h *RecordHandler) Edit(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing record ID", http.StatusBadRequest)
		return
	}
	if err := h.Service.UpdateRecord(id, r.FormValue("name"), r.FormValue("type"), r.FormValue("content"), r.FormValue("ttl")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func (h *RecordHandler) Create(w http.ResponseWriter, r *http.Request) {
	domainID := mux.Vars(r)["id"]
	if domainID == "" {
		http.Error(w, "Missing domain ID", http.StatusBadRequest)
		return
	}
	if err := h.Service.CreateRecord(domainID, r.FormValue("name"), r.FormValue("type"), r.FormValue("content"), r.FormValue("ttl")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func (h *RecordHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}
	if err := h.Service.DeleteRecord(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}
