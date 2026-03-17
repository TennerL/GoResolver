package handlers

import (
	"html/template"
	"net/http"

	"GoResolver/web"
)

type FrontendHandler struct {
	Tmpl *template.Template
}

func NewFrontendHandler() *FrontendHandler {
	return &FrontendHandler{
		Tmpl: template.Must(template.ParseFS(web.StaticFS, "templates/app.html")),
	}
}

func (h *FrontendHandler) Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	if err := h.Tmpl.ExecuteTemplate(w, "app", nil); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
