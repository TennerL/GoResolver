package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"GoResolver/internal/services"
)

type AnalyticsHandler struct {
	Service *services.AnalyticsService
}

func NewAnalyticsHandler() *AnalyticsHandler {
	return &AnalyticsHandler{
		Service: services.NewAnalyticsService(),
	}
}

func parseAnalyticsTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts, true
		}
		if ts, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func analyticsQueryUsesCacheOnly(qValues map[string][]string) bool {
	defaultRange := "60"
	for key, values := range qValues {
		value := ""
		if len(values) > 0 {
			value = strings.TrimSpace(values[0])
		}
		switch key {
		case "cache_only":
			if value == "1" || strings.EqualFold(value, "true") {
				return true
			}
		case "range":
			if value != "" && value != defaultRange {
				return true
			}
		case "host", "filter", "method", "status", "status_class", "uri_contains", "ip_contains", "from", "to":
			if value != "" {
				return true
			}
		}
	}
	return false
}

func parseAnalyticsFilters(r *http.Request) services.AnalyticsFilters {
	q := r.URL.Query()
	filters := services.AnalyticsFilters{
		RangeMinutes: 60,
		Host:         strings.TrimSpace(q.Get("host")),
		Method:       strings.TrimSpace(q.Get("method")),
		StatusClass:  strings.TrimSpace(q.Get("status_class")),
		URIContains:  strings.TrimSpace(q.Get("uri_contains")),
		IPContains:   strings.TrimSpace(q.Get("ip_contains")),
		Verdict:      strings.TrimSpace(q.Get("filter")),
		CacheOnly:    analyticsQueryUsesCacheOnly(q),
	}

	if v := strings.TrimSpace(q.Get("range")); v != "" {
		if minutes, err := strconv.Atoi(v); err == nil && minutes > 0 {
			filters.RangeMinutes = minutes
		}
	}
	if v := strings.TrimSpace(q.Get("status")); v != "" {
		if status, err := strconv.Atoi(v); err == nil && status > 0 {
			filters.Status = status
		}
	}
	if from, ok := parseAnalyticsTime(q.Get("from")); ok {
		filters.From = from
	}
	if to, ok := parseAnalyticsTime(q.Get("to")); ok {
		filters.To = to
	}

	return filters
}

func (h *AnalyticsHandler) API(w http.ResponseWriter, r *http.Request) {
	filters := parseAnalyticsFilters(r)

	reqLabels, reqValues, err := h.Service.RequestsOverTime(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	statusCodes, err := h.Service.StatusCodes(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uriLabels, uriStatusCounts, err := h.Service.TopURIs(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	latLabels, latValues, err := h.Service.AvgRequestTime(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	methods, err := h.Service.Methods(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := h.Service.Summary(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"requests_over_time": map[string]any{"labels": reqLabels, "values": reqValues},
		"status_codes":       statusCodes,
		"top_uris":           map[string]any{"labels": uriLabels, "status_codes": uriStatusCounts},
		"avg_request_time":   map[string]any{"labels": latLabels, "values": latValues},
		"methods":            methods,
		"summary":            summary,
		"cache_only":         filters.CacheOnly,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *AnalyticsHandler) Hosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.Service.Hosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (h *AnalyticsHandler) IPs(w http.ResponseWriter, r *http.Request) {
	filters := parseAnalyticsFilters(r)
	ips, err := h.Service.IPReputationList(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, ips)
}

func (h *AnalyticsHandler) IPGeo(w http.ResponseWriter, r *http.Request) {
	filters := parseAnalyticsFilters(r)
	points, err := h.Service.IPGeoPoints(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, points)
}
