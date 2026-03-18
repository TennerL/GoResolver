package logging

import (
	"GoResolver/internal/services"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NginxLog struct {
	Time          string  `json:"time"`
	RemoteAddr    string  `json:"remote_addr"`
	XForwardedFor string  `json:"x_forwarded_for"`
	Method        string  `json:"method"`
	URI           string  `json:"uri"`
	Status        int     `json:"status"`
	Bytes         int64   `json:"bytes"`
	Referer       string  `json:"referer"`
	UserAgent     string  `json:"user_agent"`
	RequestTime   float64 `json:"request_time"`
	UpstreamTime  string  `json:"upstream_time"`
	Host          string  `json:"host"`
	RayID         string  `json:"ray_id"`
}

var (
	retentionMu      sync.Mutex
	lastRetentionRun time.Time
	alertEvalMu      sync.Mutex
	lastAlertEvalRun time.Time
)

func StartNginxLogIngester(db *sql.DB, path string) {
	ensureNginxLogsSchema(db)
	if path == "" {
		log.Println("nginx log ingester disabled: log path is empty")
		return
	}

	file, err := os.Open(path)
	if err != nil {
		log.Printf("nginx log ingester disabled: cannot open %q: %v", path, err)
		return
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		log.Printf("nginx log ingester disabled: cannot seek %q: %v", path, err)
		return
	}

	reader := bufio.NewReader(file)
	batch := make([]NginxLog, 0, 100)

	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case <-flushTicker.C:
			if len(batch) > 0 {
				insertBatch(db, batch)
				batch = batch[:0]
			}

		default:
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				log.Println("read error:", err)
				continue
			}

			line = bytes.TrimSpace(line)
			start := bytes.IndexByte(line, '[')
			if start == -1 {
				log.Printf("no JSON array found, skipping: %s\n", line)
				continue
			}

			jsonPart := line[start:]
			var arr []json.RawMessage
			if err := json.Unmarshal(jsonPart, &arr); err != nil {
				repaired := repairLegacyLogFormat(jsonPart)
				if repaired == nil || json.Unmarshal(repaired, &arr) != nil {
					log.Printf("json array error: %v | %s\n", err, jsonPart)
					continue
				}
			}

			if len(arr) != 2 {
				log.Printf("unexpected array length: %d | %s\n", len(arr), jsonPart)
				continue
			}

			var entry NginxLog
			if err := json.Unmarshal(arr[1], &entry); err != nil {
				log.Printf("json object error: %v | %s\n", err, arr[1])
				continue
			}

			batch = append(batch, entry)

			if len(batch) >= 100 {
				insertBatch(db, batch)
				batch = batch[:0]
			}
		}
	}
}

func repairLegacyLogFormat(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 3 || trimmed[0] != '[' {
		return nil
	}
	comma := bytes.IndexByte(trimmed, ',')
	if comma == -1 {
		return nil
	}
	first := bytes.TrimSpace(trimmed[1:comma])
	if len(first) == 0 || first[0] == '"' {
		return nil
	}
	rest := bytes.TrimSpace(trimmed[comma+1:])
	buf := bytes.NewBuffer(nil)
	buf.WriteByte('[')
	buf.WriteByte('"')
	buf.Write(first)
	buf.WriteString(`", `)
	buf.Write(rest)
	return buf.Bytes()
}

func ensureNginxLogsSchema(db *sql.DB) {
	_, _ = db.Exec(`ALTER TABLE nginx_logs ADD COLUMN ray_id VARCHAR(64) NULL`)
}

func insertBatch(db *sql.DB, batch []NginxLog) {
	if len(batch) == 0 {
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Println("tx begin error:", err)
		return
	}

	stmt, err := tx.Prepare(
		"INSERT INTO nginx_logs " +
			"(`time`, remote_addr, x_forwarded_for, method, uri, status, bytes, " +
			"referer, user_agent, request_time, upstream_time, host, ray_id) " +
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	)
	if err != nil {
		log.Println("prepare error:", err)
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		t, err := parseNginxTime(e.Time)
		if err != nil {
			log.Printf("invalid time format, skipping entry: %s | %+v\n", err, e)
			continue
		}

		var upstream float64
		if e.UpstreamTime != "" {
			upstream, err = parseUpstreamTime(e.UpstreamTime)
			if err != nil {
				log.Printf("invalid upstream_time, defaulting to 0: %s | %+v\n", err, e)
				upstream = 0
			}
		}

		_, err = stmt.Exec(
			t,
			e.RemoteAddr,
			e.XForwardedFor,
			e.Method,
			e.URI,
			e.Status,
			e.Bytes,
			e.Referer,
			e.UserAgent,
			e.RequestTime,
			upstream,
			e.Host,
			e.RayID,
		)
		if err != nil {
			log.Printf("insert error: %v | entry: %+v\n", err, e)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Println("commit error:", err)
	}

	maybePruneOldLogs(db)
	maybeEvaluateAnalyticsAlerts()
}

func parseNginxTime(ts string) (time.Time, error) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05-07:00",
		"02/Jan/2006:15:04:05 -0700",
	}

	for _, l := range layouts {
		if t, err := time.Parse(l, ts); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time: %s", ts)
}

func parseUpstreamTime(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	if err != nil {
		return 0, err
	}
	return f, nil
}

func maybePruneOldLogs(db *sql.DB) {
	retentionMu.Lock()
	defer retentionMu.Unlock()

	now := time.Now().UTC()
	if !lastRetentionRun.IsZero() && now.Sub(lastRetentionRun) < 15*time.Minute {
		return
	}
	lastRetentionRun = now

	retentionDays := getAnalyticsRetentionDays(db)
	if retentionDays <= 0 {
		return
	}

	cutoff := now.AddDate(0, 0, -retentionDays)
	if _, err := db.Exec("DELETE FROM nginx_logs WHERE `time` < ?", cutoff); err != nil {
		log.Printf("analytics retention cleanup failed: %v", err)
	}
}

func getAnalyticsRetentionDays(db *sql.DB) int {
	var raw string
	err := db.QueryRow("SELECT setting_value FROM app_settings WHERE setting_key = 'analytics.retention_days'").Scan(&raw)
	if err != nil || strings.TrimSpace(raw) == "" {
		return 30
	}
	value, convErr := strconv.Atoi(strings.TrimSpace(raw))
	if convErr != nil {
		return 30
	}
	if value < 0 {
		return 0
	}
	return value
}

func maybeEvaluateAnalyticsAlerts() {
	alertEvalMu.Lock()
	defer alertEvalMu.Unlock()

	now := time.Now().UTC()
	if !lastAlertEvalRun.IsZero() && now.Sub(lastAlertEvalRun) < 5*time.Minute {
		return
	}
	lastAlertEvalRun = now

	service := services.NewAnalyticsService()
	_, _ = service.Observability(services.AnalyticsFilters{RangeMinutes: 60})
}
