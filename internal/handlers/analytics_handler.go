package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"

	"GoResolver/internal/services"
	"GoResolver/internal/models"
)

type AnalyticsHandler struct {
	Tmpl    *template.Template
	Service *services.AnalyticsService
}

func NewAnalyticsHandler() *AnalyticsHandler {
	return &AnalyticsHandler{
		Service: services.NewAnalyticsService(),
		Tmpl: template.Must(template.ParseFiles(
			"web/templates/layout.html",
			"web/templates/analytics.html",
		)),
	}
}

func (h *AnalyticsHandler) Index(w http.ResponseWriter, r *http.Request) {
	page := models.PageData{
		Active: "analytics",
	}

	h.Tmpl.ExecuteTemplate(w, "layout", page)
}

func (h *AnalyticsHandler) API(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minutes := 60
	host := q.Get("host")
	if v := q.Get("range"); v != "" {
		if m, err := strconv.Atoi(v); err == nil && m > 0 {
			minutes = m
		}
	}

	reqLabels, reqValues, err := h.Service.RequestsOverTime(minutes, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	statusCodes, err := h.Service.StatusCodes(minutes, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	uriLabels, uriValues, err := h.Service.TopURIs(minutes, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	latLabels, latValues, err := h.Service.AvgRequestTime(minutes, host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"requests_over_time": map[string]any{
			"labels": reqLabels,
			"values": reqValues,
		},
		"status_codes": statusCodes,
		"top_uris": map[string]any{
			"labels": uriLabels,
			"values": uriValues,
		},
		"avg_request_time": map[string]any{
			"labels": latLabels,
			"values": latValues,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Hosts API endpoint
func (h *AnalyticsHandler) Hosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.Service.Hosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}