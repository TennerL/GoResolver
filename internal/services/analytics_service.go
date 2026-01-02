package services

import (
	"GoResolver/internal/db"
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

func (s *AnalyticsService) TopURIs(minutes int, host string) ([]string, []int, error) {
	rows, err := db.DB.Query(`
		SELECT uri, COUNT(*) AS hits
		FROM nginx_logs
		WHERE time >= NOW() - INTERVAL ? MINUTE
		  AND (? = '' OR host = ?)
		GROUP BY uri
		ORDER BY hits DESC
		LIMIT 10`,
		minutes, host, host,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var labels []string
	var values []int
	for rows.Next() {
		var uri string
		var hits int
		rows.Scan(&uri, &hits)
		labels = append(labels, uri)
		values = append(values, hits)
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