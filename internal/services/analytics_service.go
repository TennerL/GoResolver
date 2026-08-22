package services

import (
	"GoResolver/internal/db"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	analyticsSnapshotTTL      = 5 * time.Second
	analyticsSnapshotCacheMax = 128
)

type AnalyticsService struct {
	cacheMu        sync.RWMutex
	snapshotCache  map[string]analyticsSnapshotCacheEntry
	snapshotLoader singleflight.Group
}

type AnalyticsFilters struct {
	RangeMinutes       int
	Host               string
	Method             string
	Status             int
	StatusClass        string
	QuickSearch        string
	URIContains        string
	IPContains         string
	ISPContains        string
	Verdict            string
	From               time.Time
	To                 time.Time
	CacheOnly          bool
	IncludeInternalAPI bool
}

type AnalyticsSummary struct {
	TotalRequests    int64   `json:"total_requests"`
	UniqueIPs        int64   `json:"unique_ips"`
	ErrorRequests    int64   `json:"error_requests"`
	ErrorRate        float64 `json:"error_rate"`
	AvgRequestTimeMs float64 `json:"avg_request_time_ms"`
	TransferredBytes int64   `json:"transferred_bytes"`
}

type analyticsIntSeries struct {
	Labels []string `json:"labels"`
	Values []int    `json:"values"`
}

type analyticsFloatSeries struct {
	Labels []string  `json:"labels"`
	Values []float64 `json:"values"`
}

type analyticsTopURIs struct {
	Labels      []string         `json:"labels"`
	StatusCodes map[string][]int `json:"status_codes"`
}

type analyticsTopIPs struct {
	Labels []string   `json:"labels"`
	Values []int      `json:"values"`
	URLs   [][]string `json:"urls"`
}

type AnalyticsSnapshot struct {
	RequestsOverTime analyticsIntSeries   `json:"requests_over_time"`
	StatusCodes      map[int]int          `json:"status_codes"`
	TopURIs          analyticsTopURIs     `json:"top_uris"`
	AvgRequestTime   analyticsFloatSeries `json:"avg_request_time"`
	Methods          map[string]int       `json:"methods"`
	TopIPs           analyticsTopIPs      `json:"top_ips"`
	Summary          AnalyticsSummary     `json:"summary"`
	CacheOnly        bool                 `json:"cache_only"`
	RetentionDays    int                  `json:"retention_days"`
}

type analyticsSnapshotCacheEntry struct {
	snapshot  AnalyticsSnapshot
	expiresAt time.Time
}

func NewAnalyticsService() *AnalyticsService {
	return &AnalyticsService{
		snapshotCache: make(map[string]analyticsSnapshotCacheEntry),
	}
}

func normalizeAnalyticsFilters(filters AnalyticsFilters) AnalyticsFilters {
	filters.Host = strings.TrimSpace(filters.Host)
	filters.Method = strings.ToUpper(strings.TrimSpace(filters.Method))
	filters.StatusClass = normalizeStatusClass(filters.StatusClass)
	filters.QuickSearch = strings.TrimSpace(filters.QuickSearch)
	filters.URIContains = strings.TrimSpace(filters.URIContains)
	filters.IPContains = strings.TrimSpace(filters.IPContains)
	filters.ISPContains = strings.TrimSpace(filters.ISPContains)
	filters.Verdict = strings.ToLower(strings.TrimSpace(filters.Verdict))

	if filters.RangeMinutes <= 0 {
		filters.RangeMinutes = 60
	}

	now := time.Now().UTC()
	from := filters.From
	to := filters.To
	switch {
	case from.IsZero() && to.IsZero():
		to = now
		from = to.Add(-time.Duration(filters.RangeMinutes) * time.Minute)
	case from.IsZero():
		to = to.UTC()
		from = to.Add(-time.Duration(filters.RangeMinutes) * time.Minute)
	case to.IsZero():
		from = from.UTC()
		to = now
	default:
		from = from.UTC()
		to = to.UTC()
	}
	if to.Before(from) {
		from, to = to, from
	}
	filters.From = from
	filters.To = to
	return filters
}

func normalizeStatusClass(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1xx", "2xx", "3xx", "4xx", "5xx":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func analyticsTimeLabelFormat(filters AnalyticsFilters) string {
	span := filters.To.Sub(filters.From)
	switch {
	case span > 7*24*time.Hour:
		return "%Y-%m-%d"
	case span > 24*time.Hour:
		return "%Y-%m-%d %H:00"
	default:
		return "%Y-%m-%d %H:%i"
	}
}

func analyticsWhereClause(filters AnalyticsFilters) (string, []any) {
	filters = normalizeAnalyticsFilters(filters)

	conditions := []string{
		"`time` >= ?",
		"`time` <= ?",
	}
	args := []any{filters.From, filters.To}

	if filters.Host != "" {
		conditions = append(conditions, "host = ?")
		args = append(args, filters.Host)
	}
	if filters.Method != "" {
		conditions = append(conditions, "method = ?")
		args = append(args, filters.Method)
	}
	if filters.Status > 0 {
		conditions = append(conditions, "status = ?")
		args = append(args, filters.Status)
	}
	if filters.StatusClass != "" {
		base := int(filters.StatusClass[0]-'0') * 100
		conditions = append(conditions, "status BETWEEN ? AND ?")
		args = append(args, base, base+99)
	}
	if filters.QuickSearch != "" {
		like := "%" + filters.QuickSearch + "%"
		conditions = append(conditions, fmt.Sprintf("(host LIKE ? OR uri LIKE ? OR method LIKE ? OR %s LIKE ? OR EXISTS (SELECT 1 FROM ip_geolocation geo WHERE geo.ip = %s AND geo.isp LIKE ?))", analyticsClientIPExpr(), analyticsClientIPExpr()))
		args = append(args, like, like, like, like, like)
	}
	if filters.URIContains != "" {
		conditions = append(conditions, "uri LIKE ?")
		args = append(args, "%"+filters.URIContains+"%")
	}
	if filters.IPContains != "" {
		like := "%" + filters.IPContains + "%"
		conditions = append(conditions, "remote_addr LIKE ?")
		args = append(args, like)
	}
	if filters.ISPContains != "" {
		conditions = append(conditions, fmt.Sprintf("EXISTS (SELECT 1 FROM ip_geolocation geo WHERE geo.ip = %s AND geo.isp LIKE ?)", analyticsClientIPExpr()))
		args = append(args, "%"+filters.ISPContains+"%")
	}
	if !filters.IncludeInternalAPI {
		conditions = append(conditions, "uri NOT LIKE ?")
		args = append(args, "/api/%")
	}

	return "WHERE " + strings.Join(conditions, " AND "), args
}

func analyticsClientIPExpr() string {
	return "TRIM(remote_addr)"
}

func analyticsSnapshotCacheKey(filters AnalyticsFilters) string {
	filters = normalizeAnalyticsFilters(filters)
	return strings.Join([]string{
		strconv.Itoa(filters.RangeMinutes),
		filters.Host,
		filters.Method,
		strconv.Itoa(filters.Status),
		filters.StatusClass,
		filters.QuickSearch,
		filters.URIContains,
		filters.IPContains,
		filters.ISPContains,
		filters.Verdict,
		filters.From.Format(time.RFC3339Nano),
		filters.To.Format(time.RFC3339Nano),
		strconv.FormatBool(filters.IncludeInternalAPI),
	}, "\x1f")
}

func (s *AnalyticsService) getCachedSnapshot(key string) (AnalyticsSnapshot, bool) {
	s.cacheMu.RLock()
	entry, ok := s.snapshotCache[key]
	s.cacheMu.RUnlock()
	if !ok {
		return AnalyticsSnapshot{}, false
	}
	if time.Now().After(entry.expiresAt) {
		s.cacheMu.Lock()
		delete(s.snapshotCache, key)
		s.cacheMu.Unlock()
		return AnalyticsSnapshot{}, false
	}
	return entry.snapshot, true
}

func (s *AnalyticsService) setCachedSnapshot(key string, snapshot AnalyticsSnapshot) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if s.snapshotCache == nil {
		s.snapshotCache = make(map[string]analyticsSnapshotCacheEntry)
	}

	if len(s.snapshotCache) >= analyticsSnapshotCacheMax {
		now := time.Now()
		for cacheKey, entry := range s.snapshotCache {
			if now.After(entry.expiresAt) {
				delete(s.snapshotCache, cacheKey)
			}
		}
		if len(s.snapshotCache) >= analyticsSnapshotCacheMax {
			for cacheKey := range s.snapshotCache {
				delete(s.snapshotCache, cacheKey)
				break
			}
		}
	}

	s.snapshotCache[key] = analyticsSnapshotCacheEntry{
		snapshot:  snapshot,
		expiresAt: time.Now().Add(analyticsSnapshotTTL),
	}
}

func (s *AnalyticsService) Snapshot(filters AnalyticsFilters) (AnalyticsSnapshot, error) {
	normalized := normalizeAnalyticsFilters(filters)
	cacheKey := analyticsSnapshotCacheKey(normalized)

	if snapshot, ok := s.getCachedSnapshot(cacheKey); ok {
		snapshot.CacheOnly = normalized.CacheOnly
		return snapshot, nil
	}

	value, err, _ := s.snapshotLoader.Do(cacheKey, func() (any, error) {
		if snapshot, ok := s.getCachedSnapshot(cacheKey); ok {
			return snapshot, nil
		}

		snapshot, err := s.buildSnapshot(normalized)
		if err != nil {
			return AnalyticsSnapshot{}, err
		}
		s.setCachedSnapshot(cacheKey, snapshot)
		return snapshot, nil
	})
	if err != nil {
		return AnalyticsSnapshot{}, err
	}

	snapshot := value.(AnalyticsSnapshot)
	snapshot.CacheOnly = normalized.CacheOnly
	snapshot.RetentionDays = analyticsRetentionDays()
	return snapshot, nil
}

func (s *AnalyticsService) buildSnapshot(filters AnalyticsFilters) (AnalyticsSnapshot, error) {
	var (
		snapshot        AnalyticsSnapshot
		reqLabels       []string
		reqValues       []int
		statusCodes     map[int]int
		uriLabels       []string
		uriStatusCounts map[string][]int
		latLabels       []string
		latValues       []float64
		methods         map[string]int
		ipLabels        []string
		ipValues        []int
		ipURLs          [][]string
		summary         AnalyticsSummary
	)

	var group errgroup.Group
	group.Go(func() error {
		var err error
		reqLabels, reqValues, err = s.RequestsOverTime(filters)
		return err
	})
	group.Go(func() error {
		var err error
		statusCodes, err = s.StatusCodes(filters)
		return err
	})
	group.Go(func() error {
		var err error
		uriLabels, uriStatusCounts, err = s.TopURIs(filters)
		return err
	})
	group.Go(func() error {
		var err error
		latLabels, latValues, err = s.AvgRequestTime(filters)
		return err
	})
	group.Go(func() error {
		var err error
		methods, err = s.Methods(filters)
		return err
	})
	group.Go(func() error {
		var err error
		ipLabels, ipValues, ipURLs, err = s.TopIPs(filters)
		return err
	})
	group.Go(func() error {
		var err error
		summary, err = s.Summary(filters)
		return err
	})
	if err := group.Wait(); err != nil {
		return AnalyticsSnapshot{}, err
	}

	snapshot = AnalyticsSnapshot{
		RequestsOverTime: analyticsIntSeries{Labels: reqLabels, Values: reqValues},
		StatusCodes:      statusCodes,
		TopURIs:          analyticsTopURIs{Labels: uriLabels, StatusCodes: uriStatusCounts},
		AvgRequestTime:   analyticsFloatSeries{Labels: latLabels, Values: latValues},
		Methods:          methods,
		TopIPs:           analyticsTopIPs{Labels: ipLabels, Values: ipValues, URLs: ipURLs},
		Summary:          summary,
	}
	return snapshot, nil
}

func (s *AnalyticsService) RequestsOverTime(filters AnalyticsFilters) ([]string, []int, error) {
	filters = normalizeAnalyticsFilters(filters)
	labelFormat := analyticsTimeLabelFormat(filters)
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT DATE_FORMAT(time, '%s') AS label, COUNT(*)
		FROM nginx_logs
		%s
		GROUP BY label
		ORDER BY MIN(time)`, labelFormat, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var labels []string
	var values []int

	for rows.Next() {
		var l string
		var v int
		if err := rows.Scan(&l, &v); err != nil {
			return nil, nil, err
		}
		labels = append(labels, l)
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return labels, values, nil
}

func (s *AnalyticsService) StatusCodes(filters AnalyticsFilters) (map[int]int, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT status, COUNT(*)
		FROM nginx_logs
		%s
		GROUP BY status`, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int]int)
	for rows.Next() {
		var status, count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		result[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *AnalyticsService) Methods(filters AnalyticsFilters) (map[string]int, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT method, COUNT(*)
		FROM nginx_logs
		%s
		GROUP BY method
		ORDER BY COUNT(*) DESC, method ASC`, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var method string
		var count int
		if err := rows.Scan(&method, &count); err != nil {
			return nil, err
		}
		method = strings.TrimSpace(method)
		if method == "" {
			method = "UNKNOWN"
		}
		result[method] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *AnalyticsService) TopIPs(filters AnalyticsFilters) ([]string, []int, [][]string, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT %s AS client_ip, COUNT(*) AS hits
		FROM nginx_logs
		%s
		GROUP BY client_ip
		ORDER BY hits DESC, client_ip ASC
		LIMIT 50`, analyticsClientIPExpr(), whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()

	labels := []string{}
	values := []int{}
	urls := [][]string{}
	for rows.Next() {
		var ip string
		var hits int
		if err := rows.Scan(&ip, &hits); err != nil {
			return nil, nil, nil, err
		}
		ip = strings.TrimSpace(ip)
		if !isValidIP(ip) {
			continue
		}
		labels = append(labels, ip)
		values = append(values, hits)
		if len(labels) >= 10 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	topURIsByIP, err := s.topURIsForIPs(filters, labels)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ip := range labels {
		urls = append(urls, topURIsByIP[ip])
	}
	return labels, values, urls, nil
}

func (s *AnalyticsService) topURIsForIPs(filters AnalyticsFilters, ips []string) (map[string][]string, error) {
	if len(ips) == 0 {
		return map[string][]string{}, nil
	}

	whereClause, args := analyticsWhereClause(filters)
	ipExpr := analyticsClientIPExpr()
	placeholders := analyticsSQLPlaceholders(len(ips))
	query := fmt.Sprintf(`
		SELECT client_ip, uri, hits
		FROM (
			SELECT %s AS client_ip, uri, COUNT(*) AS hits
			FROM nginx_logs
			%s
			GROUP BY %s, uri
		) ip_uris
		WHERE client_ip IN (%s)
		ORDER BY client_ip ASC, hits DESC, uri ASC`, ipExpr, whereClause, ipExpr, placeholders)

	queryArgs := make([]any, 0, len(args)+len(ips))
	queryArgs = append(queryArgs, args...)
	for _, ip := range ips {
		queryArgs = append(queryArgs, ip)
	}
	rows, err := db.DB.Query(query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	urlsByIP := make(map[string][]string, len(ips))
	for rows.Next() {
		var ip string
		var uri string
		var hits int
		if err := rows.Scan(&ip, &uri, &hits); err != nil {
			return nil, err
		}
		if len(urlsByIP[ip]) >= 5 {
			continue
		}
		uri = strings.TrimSpace(uri)
		if uri == "" {
			uri = "(empty URI)"
		}
		urlsByIP[ip] = append(urlsByIP[ip], fmt.Sprintf("%s (%d)", uri, hits))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return urlsByIP, nil
}

func analyticsSQLPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = "?"
	}
	return strings.Join(placeholders, ", ")
}

func (s *AnalyticsService) Summary(filters AnalyticsFilters) (AnalyticsSummary, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total_requests,
			COUNT(DISTINCT %s) AS unique_ips,
			SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS error_requests,
			AVG(request_time) AS avg_request_time,
			COALESCE(SUM(bytes), 0) AS transferred_bytes
		FROM nginx_logs
		%s`, analyticsClientIPExpr(), whereClause)

	var summary AnalyticsSummary
	var avgRequestTime sqlNullFloat64
	if err := db.DB.QueryRow(query, args...).Scan(
		&summary.TotalRequests,
		&summary.UniqueIPs,
		&summary.ErrorRequests,
		&avgRequestTime,
		&summary.TransferredBytes,
	); err != nil {
		return summary, err
	}

	if summary.TotalRequests > 0 {
		summary.ErrorRate = (float64(summary.ErrorRequests) / float64(summary.TotalRequests)) * 100
	}
	if avgRequestTime.Valid {
		summary.AvgRequestTimeMs = avgRequestTime.Float64 * 1000
	}

	return summary, nil
}

func (s *AnalyticsService) TopURIs(filters AnalyticsFilters) ([]string, map[string][]int, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT uri, status, COUNT(*) as hits
		FROM nginx_logs
		%s
		GROUP BY uri, status
		ORDER BY hits DESC
		LIMIT 20
	`, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type entry struct {
		URI    string
		Status int
		Count  int
	}
	entries := []entry{}
	statusSet := map[int]struct{}{}

	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.URI, &e.Status, &e.Count); err != nil {
			return nil, nil, err
		}
		entries = append(entries, e)
		statusSet[e.Status] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	labels := []string{}
	seen := map[string]struct{}{}
	for _, e := range entries {
		if _, ok := seen[e.URI]; !ok {
			labels = append(labels, e.URI)
			seen[e.URI] = struct{}{}
			if len(labels) >= 10 {
				break
			}
		}
	}

	values := map[string][]int{}
	for status := range statusSet {
		values[fmt.Sprintf("%d", status)] = make([]int, len(labels))
	}

	for _, e := range entries {
		idx := -1
		for i, uri := range labels {
			if uri == e.URI {
				idx = i
				break
			}
		}
		if idx == -1 {
			continue
		}
		values[fmt.Sprintf("%d", e.Status)][idx] = e.Count
	}

	return labels, values, nil
}

func (s *AnalyticsService) AvgRequestTime(filters AnalyticsFilters) ([]string, []float64, error) {
	filters = normalizeAnalyticsFilters(filters)
	labelFormat := analyticsTimeLabelFormat(filters)
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT DATE_FORMAT(time, '%s') AS label, AVG(request_time)
		FROM nginx_logs
		%s
		  AND request_time IS NOT NULL
		GROUP BY label
		ORDER BY MIN(time)`, labelFormat, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var labels []string
	var values []float64
	for rows.Next() {
		var l string
		var v float64
		if err := rows.Scan(&l, &v); err != nil {
			return nil, nil, err
		}
		labels = append(labels, l)
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return labels, values, nil
}

func (s *AnalyticsService) Hosts() ([]string, error) {
	rows, err := db.DB.Query("SELECT DISTINCT host FROM nginx_logs ORDER BY host")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

type IPReputation struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	ISP       string   `json:"isp"`
	Score     int      `json:"score"`
	Reports   int      `json:"reports"`
	CheckedAt string   `json:"checked_at"`
	Verdict   string   `json:"verdict"`
}

type IPGeoPoint struct {
	IP      string  `json:"ip"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city"`
	Region  string  `json:"region"`
	Country string  `json:"country"`
	ISP     string  `json:"isp"`
}

func (s *AnalyticsService) EnsureIPReputationTable() error {
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS ip_reputation (
			ip VARCHAR(45) PRIMARY KEY,
			score INT NOT NULL,
			reports INT NOT NULL,
			checked_at DATETIME NOT NULL,
			source VARCHAR(32) NOT NULL
		)
	`)
	return err
}

func (s *AnalyticsService) EnsureIPGeoTable() error {
	_, err := db.DB.Exec(`
		CREATE TABLE IF NOT EXISTS ip_geolocation (
			ip VARCHAR(45) PRIMARY KEY,
			lat DOUBLE NOT NULL,
			lon DOUBLE NOT NULL,
			city VARCHAR(128) NOT NULL,
			region VARCHAR(128) NOT NULL,
			country VARCHAR(128) NOT NULL,
			isp VARCHAR(255) NOT NULL,
			checked_at DATETIME NOT NULL,
			source VARCHAR(32) NOT NULL
		)
	`)
	_, _ = db.DB.Exec(`ALTER TABLE ip_geolocation ADD COLUMN isp VARCHAR(255) NOT NULL DEFAULT ''`)
	return err
}

func (s *AnalyticsService) UniqueIPs(filters AnalyticsFilters) ([]string, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT remote_addr
		FROM nginx_logs
		%s
	`, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ipSet := map[string]struct{}{}
	for rows.Next() {
		var remoteAddr string
		if err := rows.Scan(&remoteAddr); err != nil {
			return nil, err
		}
		candidate := strings.TrimSpace(remoteAddr)
		if !isValidIP(candidate) {
			continue
		}
		ipSet[candidate] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}

func (s *AnalyticsService) IPReputationList(filters AnalyticsFilters) ([]IPReputation, error) {
	if err := s.EnsureIPReputationTable(); err != nil {
		return nil, err
	}

	filters = normalizeAnalyticsFilters(filters)

	ipHosts, err := s.IPHosts(filters)
	if err != nil {
		return nil, err
	}

	ips, err := s.UniqueIPs(filters)
	if err != nil {
		return nil, err
	}

	settings := NewSettingsService()
	key := strings.TrimSpace(settings.GetValue("abuseipdb.api_key"))
	threshold := parseIntSetting(settings.GetValue("abuseipdb.risk_threshold"), 50)
	maxAgeDays := parseIntSetting(settings.GetValue("abuseipdb.max_age_days"), 90)
	_ = parseIntSetting(settings.GetValue("abuseipdb.cache_ttl_hours"), 24)

	reputations := make([]IPReputation, 0, len(ips))
	for _, ip := range ips {
		score, reports, checkedAt, verdict, err := s.getIPReputation(ip, key, maxAgeDays, threshold, filters.CacheOnly)
		if err != nil {
			verdict = "unknown"
		}
		isp := ""
		if _, _, _, _, _, cachedISP, ok := s.getCachedIPGeo(ip); ok {
			isp = cachedISP
		} else if !filters.CacheOnly {
			lat, lon, city, region, country, fetchedISP, geoErr := fetchIPWhoIsGeo(ip)
			if geoErr == nil {
				_ = s.saveIPGeo(ip, lat, lon, city, region, country, fetchedISP)
				isp = fetchedISP
			}
		}
		if filters.Verdict != "" && verdict != filters.Verdict {
			continue
		}
		reputations = append(reputations, IPReputation{
			IP:        ip,
			Hostnames: ipHosts[ip],
			ISP:       isp,
			Score:     score,
			Reports:   reports,
			CheckedAt: checkedAt,
			Verdict:   verdict,
		})
	}
	sort.SliceStable(reputations, func(i, j int) bool {
		left := reputations[i]
		right := reputations[j]
		if verdictRank(left.Verdict) != verdictRank(right.Verdict) {
			return verdictRank(left.Verdict) < verdictRank(right.Verdict)
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.Reports != right.Reports {
			return left.Reports > right.Reports
		}
		return left.IP < right.IP
	})
	return reputations, nil
}

func (s *AnalyticsService) IPGeoPoints(filters AnalyticsFilters) ([]IPGeoPoint, error) {
	if err := s.EnsureIPGeoTable(); err != nil {
		return nil, err
	}

	filters = normalizeAnalyticsFilters(filters)
	if filters.CacheOnly {
		return s.cachedIPGeoPoints(filters)
	}

	ips, err := s.UniqueIPs(filters)
	if err != nil {
		return nil, err
	}

	points := make([]IPGeoPoint, 0, len(ips))
	for _, ip := range ips {
		lat, lon, city, region, country, isp, ok := s.getCachedIPGeo(ip)
		if !ok {
			if filters.CacheOnly {
				continue
			}
			lat, lon, city, region, country, isp, err = fetchIPWhoIsGeo(ip)
			if err != nil {
				continue
			}
			_ = s.saveIPGeo(ip, lat, lon, city, region, country, isp)
		}
		if lat == 0 && lon == 0 {
			continue
		}
		points = append(points, IPGeoPoint{
			IP:      ip,
			Lat:     lat,
			Lon:     lon,
			City:    city,
			Region:  region,
			Country: country,
			ISP:     isp,
		})
	}
	return points, nil
}

func (s *AnalyticsService) cachedIPGeoPoints(filters AnalyticsFilters) ([]IPGeoPoint, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT DISTINCT geo.ip, geo.lat, geo.lon, geo.city, geo.region, geo.country, geo.isp
		FROM nginx_logs logs
		JOIN ip_geolocation geo ON geo.ip = TRIM(logs.remote_addr)
		%s
		ORDER BY geo.ip
	`, whereClause)
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	points := make([]IPGeoPoint, 0)
	for rows.Next() {
		var point IPGeoPoint
		if err := rows.Scan(&point.IP, &point.Lat, &point.Lon, &point.City, &point.Region, &point.Country, &point.ISP); err != nil {
			return nil, err
		}
		if point.Lat != 0 || point.Lon != 0 {
			points = append(points, point)
		}
	}
	return points, rows.Err()
}

func abuseIPDBCacheTTL() time.Duration {
	ttlHours := parseIntSetting(NewSettingsService().GetValue("abuseipdb.cache_ttl_hours"), 24)
	if ttlHours <= 0 {
		ttlHours = 24
	}
	return time.Duration(ttlHours) * time.Hour
}

func (s *AnalyticsService) getIPReputation(ip, apiKey string, maxAgeDays, threshold int, cacheOnly bool) (int, int, string, string, error) {
	cachedScore, cachedReports, cachedAtTime, ok := s.getCachedIPReputationTime(ip)
	if ok {
		cachedAt := cachedAtTime.UTC().Format(time.RFC3339)
		if cacheOnly || !isPublicRoutableIP(ip) || time.Since(cachedAtTime) < abuseIPDBCacheTTL() {
			return cachedScore, cachedReports, cachedAt, verdictFromScore(cachedScore, threshold), nil
		}
	}
	if cacheOnly {
		return 0, 0, "", "unknown", fmt.Errorf("cache-only reputation lookup")
	}
	if !isPublicRoutableIP(ip) {
		return 0, 0, "", "unknown", fmt.Errorf("non-public ip")
	}

	if apiKey == "" {
		return 0, 0, "", "unknown", fmt.Errorf("missing AbuseIPDB api key")
	}

	score, reports, err := fetchAbuseIPDBScore(ip, apiKey, maxAgeDays)
	if err != nil {
		return 0, 0, "", "unknown", err
	}

	checkedAt := time.Now().UTC().Format(time.RFC3339)
	if err := s.saveIPReputation(ip, score, reports); err != nil {
		return score, reports, checkedAt, verdictFromScore(score, threshold), nil
	}

	return score, reports, checkedAt, verdictFromScore(score, threshold), nil
}

func (s *AnalyticsService) getCachedIPReputation(ip string) (int, int, string, bool) {
	score, reports, checkedAt, ok := s.getCachedIPReputationTime(ip)
	if !ok {
		return 0, 0, "", false
	}
	return score, reports, checkedAt.UTC().Format(time.RFC3339), true
}

func (s *AnalyticsService) getCachedIPReputationTime(ip string) (int, int, time.Time, bool) {
	var score, reports int
	var checkedAt time.Time
	row := db.DB.QueryRow(`
		SELECT score, reports, checked_at
		FROM ip_reputation
		WHERE ip = ?
	`, ip)
	if err := row.Scan(&score, &reports, &checkedAt); err != nil {
		return 0, 0, time.Time{}, false
	}
	return score, reports, checkedAt.UTC(), true
}

func (s *AnalyticsService) saveIPReputation(ip string, score, reports int) error {
	_, err := db.DB.Exec(`
		INSERT INTO ip_reputation (ip, score, reports, checked_at, source)
		VALUES (?, ?, ?, ?, 'abuseipdb')
		ON DUPLICATE KEY UPDATE
			score = VALUES(score),
			reports = VALUES(reports),
			checked_at = VALUES(checked_at),
			source = VALUES(source)
	`, ip, score, reports, time.Now().UTC())
	return err
}

func (s *AnalyticsService) getCachedIPGeo(ip string) (float64, float64, string, string, string, string, bool) {
	var lat, lon float64
	var city, region, country, isp string
	row := db.DB.QueryRow(`
		SELECT lat, lon, city, region, country, isp
		FROM ip_geolocation
		WHERE ip = ?
	`, ip)
	if err := row.Scan(&lat, &lon, &city, &region, &country, &isp); err != nil {
		return 0, 0, "", "", "", "", false
	}
	return lat, lon, city, region, country, isp, true
}

func (s *AnalyticsService) saveIPGeo(ip string, lat, lon float64, city, region, country, isp string) error {
	_, err := db.DB.Exec(`
		INSERT INTO ip_geolocation (ip, lat, lon, city, region, country, isp, checked_at, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ipwho.is')
		ON DUPLICATE KEY UPDATE
			lat = VALUES(lat),
			lon = VALUES(lon),
			city = VALUES(city),
			region = VALUES(region),
			country = VALUES(country),
			isp = VALUES(isp),
			checked_at = VALUES(checked_at),
			source = VALUES(source)
	`, ip, lat, lon, city, region, country, isp, time.Now().UTC())
	return err
}

func fetchAbuseIPDBScore(ip, apiKey string, maxAgeDays int) (int, int, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		"https://api.abuseipdb.com/api/v2/check",
		nil,
	)
	if err != nil {
		return 0, 0, err
	}

	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", strconv.Itoa(maxAgeDays))
	q.Set("verbose", "true")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return 0, 0, fmt.Errorf("abuseipdb error: %s", string(body))
	}

	var payload struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			TotalReports         int `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, 0, err
	}
	return payload.Data.AbuseConfidenceScore, payload.Data.TotalReports, nil
}

func fetchIPWhoIsGeo(ip string) (float64, float64, string, string, string, string, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		"https://ipwho.is/"+ip,
		nil,
	)
	if err != nil {
		return 0, 0, "", "", "", "", err
	}

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", "", "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return 0, 0, "", "", "", "", fmt.Errorf("ipwho.is error: %s", string(body))
	}

	var payload struct {
		Success    bool    `json:"success"`
		Message    string  `json:"message"`
		Latitude   float64 `json:"latitude"`
		Longitude  float64 `json:"longitude"`
		City       string  `json:"city"`
		Region     string  `json:"region"`
		Country    string  `json:"country"`
		Connection struct {
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, 0, "", "", "", "", err
	}
	if !payload.Success {
		if payload.Message == "" {
			payload.Message = "unknown error"
		}
		return 0, 0, "", "", "", "", fmt.Errorf("ipwho.is: %s", payload.Message)
	}
	return payload.Latitude, payload.Longitude, payload.City, payload.Region, payload.Country, payload.Connection.ISP, nil
}

func verdictFromScore(score, threshold int) string {
	if threshold <= 0 {
		threshold = 50
	}
	if score >= threshold {
		return "suspicious"
	}
	return "genuine"
}

func verdictRank(verdict string) int {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "suspicious":
		return 0
	case "unknown":
		return 1
	case "genuine":
		return 2
	default:
		return 3
	}
}

func parseIntSetting(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return v
	}
	return fallback
}

func isValidIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil
}

func isPublicRoutableIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsMulticast() || parsed.IsUnspecified() {
		return false
	}
	return parsed.IsGlobalUnicast()
}

func (s *AnalyticsService) IPHosts(filters AnalyticsFilters) (map[string][]string, error) {
	whereClause, args := analyticsWhereClause(filters)
	query := fmt.Sprintf(`
		SELECT remote_addr, host
		FROM nginx_logs
		%s
	`, whereClause)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hostMap := map[string]map[string]struct{}{}
	for rows.Next() {
		var remoteAddr, hostName string
		if err := rows.Scan(&remoteAddr, &hostName); err != nil {
			return nil, err
		}
		candidate := strings.TrimSpace(remoteAddr)
		if !isValidIP(candidate) {
			continue
		}
		if hostName == "" {
			continue
		}
		if _, ok := hostMap[candidate]; !ok {
			hostMap[candidate] = map[string]struct{}{}
		}
		hostMap[candidate][hostName] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := map[string][]string{}
	for ip, names := range hostMap {
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		out[ip] = list
	}
	return out, nil
}

type sqlNullFloat64 struct {
	Float64 float64
	Valid   bool
}

func (n *sqlNullFloat64) Scan(value any) error {
	if value == nil {
		n.Float64 = 0
		n.Valid = false
		return nil
	}
	switch v := value.(type) {
	case float64:
		n.Float64 = v
	case float32:
		n.Float64 = float64(v)
	case int64:
		n.Float64 = float64(v)
	case []byte:
		parsed, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return err
		}
		n.Float64 = parsed
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return err
		}
		n.Float64 = parsed
	default:
		return fmt.Errorf("unsupported float scan type %T", value)
	}
	n.Valid = true
	return nil
}
