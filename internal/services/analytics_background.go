package services

import (
	"GoResolver/internal/db"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	analyticsBackgroundRefreshEvery       = 15 * time.Minute
	analyticsBackgroundReputationBatchMax = 10
	analyticsBackgroundCandidateFactor    = 4
)

type AnalyticsBackgroundMonitor struct {
	startOnce sync.Once
	service   *AnalyticsService
}

var defaultAnalyticsBackgroundMonitor = &AnalyticsBackgroundMonitor{
	service: NewAnalyticsService(),
}

func StartAnalyticsBackgroundMonitor() {
	defaultAnalyticsBackgroundMonitor.Start()
}

func (m *AnalyticsBackgroundMonitor) Start() {
	m.startOnce.Do(func() {
		go m.loop()
	})
}

func (m *AnalyticsBackgroundMonitor) loop() {
	m.runOnce()

	ticker := time.NewTicker(analyticsBackgroundRefreshEvery)
	defer ticker.Stop()

	for range ticker.C {
		m.runOnce()
	}
}

func (m *AnalyticsBackgroundMonitor) runOnce() {
	if err := m.service.RefreshBackgroundIPReputation(); err != nil {
		log.Println("analytics background reputation refresh failed:", err)
	}
	if _, err := m.service.SyncIncidents(); err != nil {
		log.Println("analytics background incident sync failed:", err)
	}
}

func (s *AnalyticsService) RefreshBackgroundIPReputation() error {
	if err := s.EnsureIPReputationTable(); err != nil {
		return err
	}

	settings := NewSettingsService()
	apiKey := settings.GetValue("abuseipdb.api_key")
	if apiKey == "" {
		return nil
	}

	threshold := parseIntSetting(settings.GetValue("abuseipdb.risk_threshold"), 50)
	maxAgeDays := parseIntSetting(settings.GetValue("abuseipdb.max_age_days"), 90)
	cacheTTL := abuseIPDBCacheTTL()

	ips, err := s.backgroundReputationCandidateIPs(analyticsIncidentFilters(), analyticsBackgroundReputationBatchMax)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, ip := range ips {
		if _, _, checkedAt, ok := s.getCachedIPReputationTime(ip); ok && now.Sub(checkedAt) < cacheTTL {
			continue
		}
		if _, _, _, _, err := s.getIPReputation(ip, apiKey, maxAgeDays, threshold, false); err != nil {
			log.Printf("analytics background abuseipdb refresh skipped for %s: %v", ip, err)
		}
	}
	return nil
}

func (s *AnalyticsService) backgroundReputationCandidateIPs(filters AnalyticsFilters, limit int) ([]string, error) {
	if limit <= 0 {
		limit = analyticsBackgroundReputationBatchMax
	}
	queryLimit := limit * analyticsBackgroundCandidateFactor
	if queryLimit < limit {
		queryLimit = limit
	}

	whereClause, args := analyticsWhereClause(filters)
	ipExpr := analyticsClientIPExpr()
	query := fmt.Sprintf(`
		SELECT %s AS client_ip
		FROM nginx_logs
		%s
		GROUP BY %s
		ORDER BY COUNT(*) DESC, MAX(time) DESC, client_ip ASC
		LIMIT ?
	`, ipExpr, whereClause, ipExpr)
	args = append(args, queryLimit)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ips := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ip = strings.TrimSpace(ip)
		if !isPublicRoutableIP(ip) {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
		if len(ips) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}
