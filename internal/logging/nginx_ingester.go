package logging

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"io"
	"fmt"
	"bytes"
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
}

func StartNginxLogIngester(db *sql.DB, path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("cannot open nginx log file: %v", err)
	}
	defer file.Close()

	//file.Seek(0, io.SeekStart)
	file.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(file)
	batch := make([]NginxLog, 0, 100)

	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case <-flushTicker.C:
			if len(batch) > 0 {
				//log.Printf("flushing %d logs\n", len(batch))
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
				log.Printf("json array error: %v | %s\n", err, jsonPart)
				continue
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
				//log.Printf("batch size reached: %d\n", len(batch))
				insertBatch(db, batch)
				batch = batch[:0]
			}

		}
	}
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
    "referer, user_agent, request_time, upstream_time, host) " +
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Println("prepare error:", err)
		tx.Rollback()
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
		)
		if err != nil {
			log.Printf("insert error: %v | entry: %+v\n", err, e)
		} 
	}

	if err := tx.Commit(); err != nil {
		log.Println("commit error:", err)
	}
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
