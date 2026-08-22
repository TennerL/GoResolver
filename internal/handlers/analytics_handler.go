package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"GoResolver/internal/services"
	"github.com/gorilla/mux"
)

type AnalyticsHandler struct {
	Service       *services.AnalyticsService
	ServerService *services.ServerConfigurationService
}

func NewAnalyticsHandler() *AnalyticsHandler {
	return &AnalyticsHandler{
		Service:       services.NewAnalyticsService(),
		ServerService: services.NewServerConfigurationService(),
	}
}

func (h *AnalyticsHandler) Fail2BanBans(w http.ResponseWriter, r *http.Request) {
	bans, err := h.ServerService.ListAllActiveFail2BanBans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, bans)
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
		case "host", "filter", "method", "status", "status_class", "q", "uri_contains", "ip_contains", "from", "to":
			if value != "" {
				return true
			}
		case "isp_contains":
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
		RangeMinutes:       60,
		Host:               strings.TrimSpace(q.Get("host")),
		Method:             strings.TrimSpace(q.Get("method")),
		StatusClass:        strings.TrimSpace(q.Get("status_class")),
		QuickSearch:        strings.TrimSpace(q.Get("q")),
		URIContains:        strings.TrimSpace(q.Get("uri_contains")),
		IPContains:         strings.TrimSpace(q.Get("ip_contains")),
		ISPContains:        strings.TrimSpace(q.Get("isp_contains")),
		Verdict:            strings.TrimSpace(q.Get("filter")),
		CacheOnly:          analyticsQueryUsesCacheOnly(q),
		IncludeInternalAPI: strings.EqualFold(strings.TrimSpace(q.Get("include_internal_api")), "true") || strings.TrimSpace(q.Get("include_internal_api")) == "1",
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
	snapshot, err := h.Service.Snapshot(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
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

func (h *AnalyticsHandler) Alerts(w http.ResponseWriter, r *http.Request) {
	filters := parseAnalyticsFilters(r)
	observability, err := h.Service.Observability(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, observability)
}

func (h *AnalyticsHandler) Logs(w http.ResponseWriter, r *http.Request) {
	filters := parseAnalyticsFilters(r)
	q := r.URL.Query()
	limit := 100
	offset := 0
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	result, err := h.Service.LogSearch(filters, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *AnalyticsHandler) IPProfile(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	filters := parseAnalyticsFilters(r)
	profile, err := h.Service.IPProfile(ip, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (h *AnalyticsHandler) Incidents(w http.ResponseWriter, r *http.Request) {
	incidents, err := h.Service.Incidents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, incidents)
}

func (h *AnalyticsHandler) DismissIncident(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(mux.Vars(r)["id"])
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}
	if err := h.Service.DismissIncident(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (h *AnalyticsHandler) DeleteIncident(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(mux.Vars(r)["id"])
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}
	if err := h.Service.DeleteIncident(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}
