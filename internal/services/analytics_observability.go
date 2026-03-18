package services

import (
	"GoResolver/internal/db"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type AnalyticsCountItem struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

type AnalyticsLogEntry struct {
	Time          string  `json:"time"`
	IP            string  `json:"ip"`
	Host          string  `json:"host"`
	Method        string  `json:"method"`
	URI           string  `json:"uri"`
	Status        int     `json:"status"`
	Bytes         int64   `json:"bytes"`
	RequestTimeMs float64 `json:"request_time_ms"`
	Referer       string  `json:"referer"`
	UserAgent     string  `json:"user_agent"`
	City          string  `json:"city"`
	Region        string  `json:"region"`
	Country       string  `json:"country"`
	ISP           string  `json:"isp"`
	Verdict       string  `json:"verdict"`
	Score         int     `json:"score"`
	Reports       int     `json:"reports"`
}

type AnalyticsLogSearchResult struct {
	Items  []AnalyticsLogEntry `json:"items"`
	Total  int64               `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

type AnalyticsIncidentContext struct {
	Hosts        []string            `json:"hosts"`
	TopIPs       []string            `json:"top_ips"`
	TopURIs      []string            `json:"top_uris"`
	RecentEvents []AnalyticsLogEntry `json:"recent_events"`
}

type AnalyticsAlert struct {
	ID          string                   `json:"id"`
	Severity    string                   `json:"severity"`
	Title       string                   `json:"title"`
	Summary     string                   `json:"summary"`
	Value       string                   `json:"value"`
	Threshold   string                   `json:"threshold"`
	Context     AnalyticsIncidentContext `json:"context"`
	StartedFrom string                   `json:"started_from"`
	WindowTo    string                   `json:"window_to"`
}

type AnalyticsObservability struct {
	Alerts        []AnalyticsAlert `json:"alerts"`
	Incidents     []AnalyticsIncident `json:"incidents"`
	RetentionDays int              `json:"retention_days"`
}

type AnalyticsIPProfile struct {
	IP               string              `json:"ip"`
	Hostnames        []string            `json:"hostnames"`
	ISP              string              `json:"isp"`
	City             string              `json:"city"`
	Region           string              `json:"region"`
	Country          string              `json:"country"`
	Verdict          string              `json:"verdict"`
	Score            int                 `json:"score"`
	Reports          int                 `json:"reports"`
	CheckedAt        string              `json:"checked_at"`
	Summary          AnalyticsSummary    `json:"summary"`
	RequestsOverTime analyticsIntSeries  `json:"requests_over_time"`
	StatusCodes      []AnalyticsCountItem `json:"status_codes"`
	TopPaths         []AnalyticsCountItem `json:"top_paths"`
	TopHosts         []AnalyticsCountItem `json:"top_hosts"`
	RecentRequests   []AnalyticsLogEntry `json:"recent_requests"`
}

func analyticsRetentionDays() int {
	settings := NewSettingsService()
	return parseIntSetting(settings.GetValue("analytics.retention_days"), 30)
}

func analyticsAlertThresholds() (errorRate float64, latencyMs float64, spikeFactor float64, minRequests int, suspiciousIPs int) {
	settings := NewSettingsService()
	errorRate = parseFloatSetting(settings.GetValue("analytics.alert.error_rate_percent"), 20)
	latencyMs = parseFloatSetting(settings.GetValue("analytics.alert.avg_request_time_ms"), 800)
	spikeFactor = parseFloatSetting(settings.GetValue("analytics.alert.request_spike_factor"), 2)
	minRequests = parseIntSetting(settings.GetValue("analytics.alert.min_requests"), 100)
	suspiciousIPs = parseIntSetting(settings.GetValue("analytics.alert.suspicious_ip_count"), 3)
	if spikeFactor < 1.1 {
		spikeFactor = 1.1
	}
	if minRequests < 1 {
		minRequests = 1
	}
	if suspiciousIPs < 1 {
		suspiciousIPs = 1
	}
	return errorRate, latencyMs, spikeFactor, minRequests, suspiciousIPs
}

func parseFloatSetting(raw string, fallback float64) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var value float64
	if _, err := fmt.Sscanf(raw, "%f", &value); err == nil {
		return value
	}
	return fallback
}

func (s *AnalyticsService) Observability(filters AnalyticsFilters) (AnalyticsObservability, error) {
	filters = normalizeAnalyticsFilters(filters)
	current, err := s.Snapshot(filters)
	if err != nil {
		return AnalyticsObservability{}, err
	}

	window := filters.To.Sub(filters.From)
	if window <= 0 {
		window = time.Duration(filters.RangeMinutes) * time.Minute
	}

	previousFilters := filters
	previousFilters.To = filters.From
	previousFilters.From = filters.From.Add(-window)
	previous, _ := s.Snapshot(previousFilters)

	context, err := s.IncidentContext(filters, 8)
	if err != nil {
		return AnalyticsObservability{}, err
	}

	errorRateThreshold, latencyThresholdMs, spikeFactor, minRequests, suspiciousIPThreshold := analyticsAlertThresholds()
	alerts := make([]AnalyticsAlert, 0, 4)

	if current.Summary.TotalRequests >= int64(minRequests) && current.Summary.ErrorRate >= errorRateThreshold {
		alerts = append(alerts, AnalyticsAlert{
			ID:          "error-rate",
			Severity:    "high",
			Title:       "High error rate",
			Summary:     "4xx and 5xx responses are above the configured threshold in the selected window.",
			Value:       fmt.Sprintf("%.1f%%", current.Summary.ErrorRate),
			Threshold:   fmt.Sprintf("%.1f%%", errorRateThreshold),
			Context:     context,
			StartedFrom: filters.From.Format(time.RFC3339),
			WindowTo:    filters.To.Format(time.RFC3339),
		})
	}

	if current.Summary.TotalRequests >= int64(minRequests) && current.Summary.AvgRequestTimeMs >= latencyThresholdMs {
		alerts = append(alerts, AnalyticsAlert{
			ID:          "latency",
			Severity:    "medium",
			Title:       "Latency spike",
			Summary:     "Average request time is elevated for the selected traffic slice.",
			Value:       fmt.Sprintf("%.0f ms", current.Summary.AvgRequestTimeMs),
			Threshold:   fmt.Sprintf("%.0f ms", latencyThresholdMs),
			Context:     context,
			StartedFrom: filters.From.Format(time.RFC3339),
			WindowTo:    filters.To.Format(time.RFC3339),
		})
	}

	if previous.Summary.TotalRequests >= int64(minRequests) && float64(current.Summary.TotalRequests) >= float64(previous.Summary.TotalRequests)*spikeFactor {
		alerts = append(alerts, AnalyticsAlert{
			ID:          "request-spike",
			Severity:    "medium",
			Title:       "Traffic spike",
			Summary:     "Request volume is significantly above the previous matching window.",
			Value:       fmt.Sprintf("%d", current.Summary.TotalRequests),
			Threshold:   fmt.Sprintf("%.0fx previous window", spikeFactor),
			Context:     context,
			StartedFrom: filters.From.Format(time.RFC3339),
			WindowTo:    filters.To.Format(time.RFC3339),
		})
	}

	suspiciousFilters := filters
	suspiciousFilters.CacheOnly = true
	suspiciousFilters.Verdict = "suspicious"
	suspiciousIPs, err := s.IPReputationList(suspiciousFilters)
	if err == nil && len(suspiciousIPs) >= suspiciousIPThreshold {
		topIPs := make([]string, 0, minInt(len(suspiciousIPs), 5))
		for _, entry := range suspiciousIPs {
			topIPs = append(topIPs, entry.IP)
			if len(topIPs) >= 5 {
				break
			}
		}
		alertContext := context
		alertContext.TopIPs = topIPs
		alerts = append(alerts, AnalyticsAlert{
			ID:          "suspicious-ips",
			Severity:    "high",
			Title:       "Suspicious IP activity",
			Summary:     "Multiple IPs in the selected window are marked suspicious by the cached reputation model.",
			Value:       fmt.Sprintf("%d IPs", len(suspiciousIPs)),
			Threshold:   fmt.Sprintf("%d IPs", suspiciousIPThreshold),
			Context:     alertContext,
			StartedFrom: filters.From.Format(time.RFC3339),
			WindowTo:    filters.To.Format(time.RFC3339),
		})
	}

	incidents, err := s.syncIncidents(alerts)
	if err != nil {
		return AnalyticsObservability{}, err
	}

	return AnalyticsObservability{
		Alerts:        alerts,
		Incidents:     incidents,
		RetentionDays: analyticsRetentionDays(),
	}, nil
}

func (s *AnalyticsService) IncidentContext(filters AnalyticsFilters, limit int) (AnalyticsIncidentContext, error) {
	logs, err := s.LogSearch(filters, limit, 0)
	if err != nil {
		return AnalyticsIncidentContext{}, err
	}
	snapshot, err := s.Snapshot(filters)
	if err != nil {
		return AnalyticsIncidentContext{}, err
	}

	hosts, err := s.TopHosts(filters, 5)
	if err != nil {
		return AnalyticsIncidentContext{}, err
	}

	hostLabels := make([]string, 0, len(hosts))
	for _, item := range hosts {
		hostLabels = append(hostLabels, item.Label)
	}

	topIPs := append([]string(nil), snapshot.TopIPs.Labels...)
	if len(topIPs) > 5 {
		topIPs = topIPs[:5]
	}
	topURIs := append([]string(nil), snapshot.TopURIs.Labels...)
	if len(topURIs) > 5 {
		topURIs = topURIs[:5]
	}

	return AnalyticsIncidentContext{
		Hosts:        hostLabels,
		TopIPs:       topIPs,
		TopURIs:      topURIs,
		RecentEvents: logs.Items,
	}, nil
}

func (s *AnalyticsService) TopHosts(filters AnalyticsFilters, limit int) ([]AnalyticsCountItem, error) {
	if limit <= 0 {
		limit = 5
	}
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT host, COUNT(*) AS hits
		FROM nginx_logs
		%s
		GROUP BY host
		ORDER BY hits DESC, host ASC
		LIMIT ?`, whereClause)
	args = append(args, limit)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AnalyticsCountItem, 0, limit)
	for rows.Next() {
		var label string
		var value int
		if err := rows.Scan(&label, &value); err != nil {
			return nil, err
		}
		items = append(items, AnalyticsCountItem{Label: label, Value: value})
	}
	return items, rows.Err()
}

func (s *AnalyticsService) LogSearch(filters AnalyticsFilters, limit, offset int) (AnalyticsLogSearchResult, error) {
	filters = normalizeAnalyticsFilters(filters)
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	threshold := parseIntSetting(NewSettingsService().GetValue("abuseipdb.risk_threshold"), 50)
	innerWhere, innerArgs := analyticsWhereClause(filters)
	base := fmt.Sprintf(`
		FROM (
			SELECT
				%s AS client_ip,
				%s AS event_time,
				host,
				method,
				uri,
				status,
				bytes,
				referer,
				user_agent,
				request_time
			FROM nginx_logs
			%s
		) logs
		LEFT JOIN ip_geolocation geo ON geo.ip = logs.client_ip
		LEFT JOIN ip_reputation rep ON rep.ip = logs.client_ip
	`, analyticsClientIPExpr(), "`time`", innerWhere)

	outerConditions := make([]string, 0, 1)
	args := append([]any{}, innerArgs...)
	if filters.Verdict != "" {
		switch filters.Verdict {
		case "suspicious":
			outerConditions = append(outerConditions, "rep.score >= ?")
			args = append(args, threshold)
		case "genuine":
			outerConditions = append(outerConditions, "(rep.score IS NOT NULL AND rep.score < ?)")
			args = append(args, threshold)
		case "unknown":
			outerConditions = append(outerConditions, "rep.score IS NULL")
		}
	}
	outerWhere := ""
	if len(outerConditions) > 0 {
		outerWhere = "WHERE " + strings.Join(outerConditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) " + base + outerWhere
	var total int64
	if err := db.DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return AnalyticsLogSearchResult{}, err
	}

	query := `
		SELECT
			logs.event_time,
			logs.client_ip,
			logs.host,
			logs.method,
			logs.uri,
			logs.status,
			logs.bytes,
			logs.referer,
			logs.user_agent,
			logs.request_time,
			COALESCE(geo.city, ''),
			COALESCE(geo.region, ''),
			COALESCE(geo.country, ''),
			COALESCE(geo.isp, ''),
			COALESCE(rep.score, 0),
			COALESCE(rep.reports, 0),
			CASE WHEN rep.ip IS NULL THEN 0 ELSE 1 END
	` + base + outerWhere + `
		ORDER BY logs.event_time DESC
		LIMIT ? OFFSET ?`
	queryArgs := append(args, limit, offset)

	rows, err := db.DB.Query(query, queryArgs...)
	if err != nil {
		return AnalyticsLogSearchResult{}, err
	}
	defer rows.Close()

	items := make([]AnalyticsLogEntry, 0, limit)
	for rows.Next() {
		var (
			eventTime    time.Time
			entry        AnalyticsLogEntry
			requestTimeS sqlNullFloat64
			hasRep       int
		)
		if err := rows.Scan(
			&eventTime,
			&entry.IP,
			&entry.Host,
			&entry.Method,
			&entry.URI,
			&entry.Status,
			&entry.Bytes,
			&entry.Referer,
			&entry.UserAgent,
			&requestTimeS,
			&entry.City,
			&entry.Region,
			&entry.Country,
			&entry.ISP,
			&entry.Score,
			&entry.Reports,
			&hasRep,
		); err != nil {
			return AnalyticsLogSearchResult{}, err
		}
		entry.Time = eventTime.UTC().Format(time.RFC3339)
		if requestTimeS.Valid {
			entry.RequestTimeMs = requestTimeS.Float64 * 1000
		}
		entry.Verdict = verdictFromScore(entry.Score, threshold)
		if hasRep == 0 {
			entry.Verdict = "unknown"
		}
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		return AnalyticsLogSearchResult{}, err
	}

	return AnalyticsLogSearchResult{Items: items, Total: total, Limit: limit, Offset: offset}, nil
}

func (s *AnalyticsService) IPProfile(ip string, filters AnalyticsFilters) (AnalyticsIPProfile, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return AnalyticsIPProfile{}, fmt.Errorf("invalid ip")
	}
	filters = normalizeAnalyticsFilters(filters)

	summary, err := s.summaryForExactIP(ip, filters)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}
	requestsOverTime, err := s.requestsOverTimeForExactIP(ip, filters)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}
	statusCodes, err := s.statusCountsForExactIP(ip, filters)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}
	topPaths, err := s.topPathsForExactIP(ip, filters, 10)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}
	topHosts, err := s.topHostsForExactIP(ip, filters, 10)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}

	logs, err := s.recentRequestsForExactIP(ip, filters, 50)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}

	hostsMap, err := s.IPHosts(filters)
	if err != nil {
		return AnalyticsIPProfile{}, err
	}

	score, reports, checkedAt, verdict, _ := s.getIPReputation(ip, NewSettingsService().GetValue("abuseipdb.api_key"), parseIntSetting(NewSettingsService().GetValue("abuseipdb.max_age_days"), 90), parseIntSetting(NewSettingsService().GetValue("abuseipdb.risk_threshold"), 50), filters.CacheOnly)
	lat, lon, city, region, country, isp, ok := s.getCachedIPGeo(ip)
	if !ok && !filters.CacheOnly {
		lat, lon, city, region, country, isp, _ = fetchIPWhoIsGeo(ip)
		if lat != 0 || lon != 0 || city != "" || region != "" || country != "" || isp != "" {
			_ = s.saveIPGeo(ip, lat, lon, city, region, country, isp)
		}
	}

	return AnalyticsIPProfile{
		IP:               ip,
		Hostnames:        hostsMap[ip],
		ISP:              isp,
		City:             city,
		Region:           region,
		Country:          country,
		Verdict:          verdict,
		Score:            score,
		Reports:          reports,
		CheckedAt:        checkedAt,
		Summary:          summary,
		RequestsOverTime: requestsOverTime,
		StatusCodes:      statusCodes,
		TopPaths:         topPaths,
		TopHosts:         topHosts,
		RecentRequests:   logs,
	}, nil
}

func analyticsWhereClauseExactIP(filters AnalyticsFilters, ip string) (string, []any) {
	whereClause, args := analyticsWhereClause(filters)
	return whereClause + fmt.Sprintf(" AND %s = ?", analyticsClientIPExpr()), append(args, ip)
}

func (s *AnalyticsService) summaryForExactIP(ip string, filters AnalyticsFilters) (AnalyticsSummary, error) {
	whereClause, args := analyticsWhereClauseExactIP(filters, ip)
	query := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total_requests,
			COUNT(DISTINCT uri) AS unique_ips,
			SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS error_requests,
			AVG(request_time) AS avg_request_time,
			COALESCE(SUM(bytes), 0) AS transferred_bytes
		FROM nginx_logs
		%s`, whereClause)

	var summary AnalyticsSummary
	var uniquePaths int64
	var avgRequestTime sqlNullFloat64
	if err := db.DB.QueryRow(query, args...).Scan(
		&summary.TotalRequests,
		&uniquePaths,
		&summary.ErrorRequests,
		&avgRequestTime,
		&summary.TransferredBytes,
	); err != nil {
		return summary, err
	}
	summary.UniqueIPs = uniquePaths
	if summary.TotalRequests > 0 {
		summary.ErrorRate = (float64(summary.ErrorRequests) / float64(summary.TotalRequests)) * 100
	}
	if avgRequestTime.Valid {
		summary.AvgRequestTimeMs = avgRequestTime.Float64 * 1000
	}
	return summary, nil
}

func (s *AnalyticsService) requestsOverTimeForExactIP(ip string, filters AnalyticsFilters) (analyticsIntSeries, error) {
	filters = normalizeAnalyticsFilters(filters)
	labelFormat := analyticsTimeLabelFormat(filters)
	whereClause, args := analyticsWhereClauseExactIP(filters, ip)
	query := fmt.Sprintf(`
		SELECT DATE_FORMAT(time, '%s') AS label, COUNT(*)
		FROM nginx_logs
		%s
		GROUP BY label
		ORDER BY MIN(time)`, labelFormat, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return analyticsIntSeries{}, err
	}
	defer rows.Close()

	var labels []string
	var values []int
	for rows.Next() {
		var label string
		var value int
		if err := rows.Scan(&label, &value); err != nil {
			return analyticsIntSeries{}, err
		}
		labels = append(labels, label)
		values = append(values, value)
	}
	return analyticsIntSeries{Labels: labels, Values: values}, rows.Err()
}

func (s *AnalyticsService) statusCountsForExactIP(ip string, filters AnalyticsFilters) ([]AnalyticsCountItem, error) {
	whereClause, args := analyticsWhereClauseExactIP(filters, ip)
	query := fmt.Sprintf(`
		SELECT status, COUNT(*) AS hits
		FROM nginx_logs
		%s
		GROUP BY status
		ORDER BY hits DESC, status ASC`, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []AnalyticsCountItem{}
	for rows.Next() {
		var status int
		var value int
		if err := rows.Scan(&status, &value); err != nil {
			return nil, err
		}
		items = append(items, AnalyticsCountItem{Label: fmt.Sprintf("%d", status), Value: value})
	}
	return items, rows.Err()
}

func (s *AnalyticsService) topPathsForExactIP(ip string, filters AnalyticsFilters, limit int) ([]AnalyticsCountItem, error) {
	return s.countItemsForExactIP(ip, filters, "uri", limit)
}

func (s *AnalyticsService) topHostsForExactIP(ip string, filters AnalyticsFilters, limit int) ([]AnalyticsCountItem, error) {
	return s.countItemsForExactIP(ip, filters, "host", limit)
}

func (s *AnalyticsService) countItemsForExactIP(ip string, filters AnalyticsFilters, column string, limit int) ([]AnalyticsCountItem, error) {
	if limit <= 0 {
		limit = 10
	}
	whereClause, args := analyticsWhereClauseExactIP(filters, ip)
	query := fmt.Sprintf(`
		SELECT %s, COUNT(*) AS hits
		FROM nginx_logs
		%s
		GROUP BY %s
		ORDER BY hits DESC, %s ASC
		LIMIT ?`, column, whereClause, column, column)
	args = append(args, limit)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AnalyticsCountItem, 0, limit)
	for rows.Next() {
		var label string
		var value int
		if err := rows.Scan(&label, &value); err != nil {
			return nil, err
		}
		if strings.TrimSpace(label) == "" {
			label = "(empty)"
		}
		items = append(items, AnalyticsCountItem{Label: label, Value: value})
	}
	return items, rows.Err()
}

func (s *AnalyticsService) recentRequestsForExactIP(ip string, filters AnalyticsFilters, limit int) ([]AnalyticsLogEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	threshold := parseIntSetting(NewSettingsService().GetValue("abuseipdb.risk_threshold"), 50)
	whereClause, args := analyticsWhereClauseExactIP(filters, ip)
	query := fmt.Sprintf(`
		SELECT
			`+"`time`"+`,
			host,
			method,
			uri,
			status,
			bytes,
			referer,
			user_agent,
			request_time,
			COALESCE(geo.city, ''),
			COALESCE(geo.region, ''),
			COALESCE(geo.country, ''),
			COALESCE(geo.isp, ''),
			COALESCE(rep.score, 0),
			COALESCE(rep.reports, 0),
			CASE WHEN rep.ip IS NULL THEN 0 ELSE 1 END
		FROM nginx_logs logs
		LEFT JOIN ip_geolocation geo ON geo.ip = %s
		LEFT JOIN ip_reputation rep ON rep.ip = %s
		%s
		ORDER BY `+"`time`"+` DESC
		LIMIT ?`, analyticsClientIPExpr(), analyticsClientIPExpr(), whereClause)
	args = append(args, limit)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AnalyticsLogEntry, 0, limit)
	for rows.Next() {
		var (
			eventTime    time.Time
			entry        AnalyticsLogEntry
			requestTimeS sqlNullFloat64
			hasRep       int
		)
		if err := rows.Scan(
			&eventTime,
			&entry.Host,
			&entry.Method,
			&entry.URI,
			&entry.Status,
			&entry.Bytes,
			&entry.Referer,
			&entry.UserAgent,
			&requestTimeS,
			&entry.City,
			&entry.Region,
			&entry.Country,
			&entry.ISP,
			&entry.Score,
			&entry.Reports,
			&hasRep,
		); err != nil {
			return nil, err
		}
		entry.IP = ip
		entry.Time = eventTime.UTC().Format(time.RFC3339)
		if requestTimeS.Valid {
			entry.RequestTimeMs = requestTimeS.Float64 * 1000
		}
		entry.Verdict = verdictFromScore(entry.Score, threshold)
		if hasRep == 0 {
			entry.Verdict = "unknown"
		}
		items = append(items, entry)
	}
	return items, rows.Err()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sortCountItems(items []AnalyticsCountItem) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		return items[i].Label < items[j].Label
	})
}
