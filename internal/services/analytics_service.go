package services

import (
	"GoResolver/internal/db"
	"fmt"
)

type AnalyticsService struct {}

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
		rows.Scan(&l, &v)
		labels = append(labels, l)
		values = append(values, v)
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
		rows.Scan(&status, &count)
		result[status] = count
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
    uriSet := map[string]struct{}{}

    for rows.Next() {
        var e entry
        if err := rows.Scan(&e.URI, &e.Status, &e.Count); err != nil {
            return nil, nil, err
        }
        entries = append(entries, e)
        statusSet[e.Status] = struct{}{}
        uriSet[e.URI] = struct{}{}
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
    statusList := []string{}
    for s := range statusSet {
        statusStr := fmt.Sprintf("%d", s)
        statusList = append(statusList, statusStr)
        values[statusStr] = make([]int, len(labels)) 
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
		rows.Scan(&l, &v)
		labels = append(labels, l)
		values = append(values, v)
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
	return hosts, nil
}