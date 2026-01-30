package handlers 

import (
	"encoding/json"
	"html/template"
	"net/http"
	"GoResolver/internal/models"
	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type RecordHandler struct {
	Tmpl *template.Template
	Service *services.RecordService
}

func NewRecordHandler() *RecordHandler {
	funcs := mergeFuncMaps(baseFuncMap(), template.FuncMap{
		"json": func(v any) template.JS {
			b, err := json.Marshal(v)
			if err != nil {
				return template.JS("{}")
			}
			return template.JS(b)
		},
	})

	tmpl := template.Must(
		template.New("layout.html").
			Funcs(funcs).
			ParseFiles(
				"web/templates/layout.html",
				"web/templates/records.html",
			),
	)

	return &RecordHandler{
		Service: services.NewRecordService(),
		Tmpl:    tmpl,
	}
}



func (h *RecordHandler) Index(w http.ResponseWriter, r *http.Request) {
	domainID := mux.Vars(r)["id"]
	if domainID == "" {
		http.Error(w, "No id supplied", http.StatusBadRequest)
		return
	}

	page := models.PageData{
		Active:   "domains",
		Data:     h.Service.GetRecords(domainID),
		DomainID: domainID,
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}


func (h *RecordHandler) Edit(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing record ID", http.StatusBadRequest)
		return
	}
	err := h.Service.UpdateRecord(
		id,
		r.FormValue("name"),
		r.FormValue("type"),
		r.FormValue("content"),
		r.FormValue("ttl"),
	)

	if err != nil {
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

	err := h.Service.CreateRecord(
		domainID,
		r.FormValue("name"),
		r.FormValue("type"),
		r.FormValue("content"),
		r.FormValue("ttl"),
	)

	if err != nil {
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
	err := h.Service.DeleteRecord(id)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}
