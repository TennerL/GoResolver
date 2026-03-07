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
	"time"
)

type AnalyticsService struct{}

func NewAnalyticsService() *AnalyticsService {
	return &AnalyticsService{}
}

func (s *AnalyticsService) RequestsOverTime(minutes int, host string) ([]string, []int, error) {
	rows, err := db.DB.Query(`
		SELECT DATE_FORMAT(time, '%H:%i') AS label, COUNT(*)
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND (? = '' OR host = ?)
		GROUP BY label
		ORDER BY label`,
		minutes, host, host,
	)
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

func (s *AnalyticsService) StatusCodes(minutes int, host string) (map[int]int, error) {
	rows, err := db.DB.Query(`
		SELECT status, COUNT(*)
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND (? = '' OR host = ?)
		GROUP BY status`,
		minutes, host, host,
	)
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

func (s *AnalyticsService) TopURIs(minutes int, host string) ([]string, map[string][]int, error) {
	query := `
		SELECT uri, status, COUNT(*) as hits
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND (? = '' OR host = ?)
		GROUP BY uri, status
		ORDER BY hits DESC
		LIMIT 20
	`

	rows, err := db.DB.Query(query, minutes, host, host)
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

func (s *AnalyticsService) AvgRequestTime(minutes int, host string) ([]string, []float64, error) {
	rows, err := db.DB.Query(`
		SELECT DATE_FORMAT(time, '%H:%i') AS label, AVG(request_time)
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND request_time IS NOT NULL
		  AND (? = '' OR host = ?)
		GROUP BY label
		ORDER BY label`,
		minutes, host, host,
	)
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

func (s *AnalyticsService) UniqueIPs(minutes int, host string) ([]string, error) {
	rows, err := db.DB.Query(`
		SELECT remote_addr, x_forwarded_for
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND (? = '' OR host = ?)
	`, minutes, host, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ipSet := map[string]struct{}{}
	for rows.Next() {
		var remoteAddr, xff string
		if err := rows.Scan(&remoteAddr, &xff); err != nil {
			return nil, err
		}
		candidate := firstIPFromXFF(xff)
		if candidate == "" {
			candidate = strings.TrimSpace(remoteAddr)
		}
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

func (s *AnalyticsService) IPReputationList(minutes int, host, filter string) ([]IPReputation, error) {
	if err := s.EnsureIPReputationTable(); err != nil {
		return nil, err
	}

	ipHosts, err := s.IPHosts(minutes, host)
	if err != nil {
		return nil, err
	}

	ips, err := s.UniqueIPs(minutes, host)
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
		score, reports, checkedAt, verdict, err := s.getIPReputation(ip, key, maxAgeDays, threshold)
		if err != nil {
			verdict = "unknown"
		}
		isp := ""
		if _, _, _, _, _, cachedISP, ok := s.getCachedIPGeo(ip); ok {
			isp = cachedISP
		} else if lat, lon, city, region, country, fetchedISP, geoErr := fetchIPWhoIsGeo(ip); geoErr == nil {
			_ = s.saveIPGeo(ip, lat, lon, city, region, country, fetchedISP)
			isp = fetchedISP
		}
		if filter != "" && verdict != filter {
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
	return reputations, nil
}

func (s *AnalyticsService) IPGeoPoints(minutes int, host string) ([]IPGeoPoint, error) {
	if err := s.EnsureIPGeoTable(); err != nil {
		return nil, err
	}

	ips, err := s.UniqueIPs(minutes, host)
	if err != nil {
		return nil, err
	}

	points := make([]IPGeoPoint, 0, len(ips))
	for _, ip := range ips {
		lat, lon, city, region, country, isp, ok := s.getCachedIPGeo(ip)
		if !ok {
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

func (s *AnalyticsService) getIPReputation(ip, apiKey string, maxAgeDays, threshold int) (int, int, string, string, error) {
	cachedScore, cachedReports, cachedAt, ok := s.getCachedIPReputation(ip)
	if ok {
		return cachedScore, cachedReports, cachedAt, verdictFromScore(cachedScore, threshold), nil
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
	var score, reports int
	var checkedAt time.Time
	row := db.DB.QueryRow(`
		SELECT score, reports, checked_at
		FROM ip_reputation
		WHERE ip = ?
	`, ip)
	if err := row.Scan(&score, &reports, &checkedAt); err != nil {
		return 0, 0, "", false
	}
	return score, reports, checkedAt.UTC().Format(time.RFC3339), true
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

func parseIntSetting(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return v
	}
	return fallback
}

func firstIPFromXFF(xff string) string {
	if xff == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func isValidIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil
}

func (s *AnalyticsService) IPHosts(minutes int, host string) (map[string][]string, error) {
	rows, err := db.DB.Query(`
		SELECT remote_addr, x_forwarded_for, host
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND (? = '' OR host = ?)
	`, minutes, host, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hostMap := map[string]map[string]struct{}{}
	for rows.Next() {
		var remoteAddr, xff, hostName string
		if err := rows.Scan(&remoteAddr, &xff, &hostName); err != nil {
			return nil, err
		}
		candidate := firstIPFromXFF(xff)
		if candidate == "" {
			candidate = strings.TrimSpace(remoteAddr)
		}
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
