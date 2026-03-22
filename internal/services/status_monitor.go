package services

import (
	"GoResolver/internal/db"
	"context"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	statusChecking      = "Checking"
	statusOnline        = "Online"
	statusOffline       = "Offline"
	statusRefreshEvery  = 15 * time.Second
	statusStaleAfter    = 20 * time.Second
	statusProbeTimeout  = 1500 * time.Millisecond
	statusProbeParallel = 8
)

type statusEntry struct {
	Status      string
	CheckedAt   time.Time
	OnlineSince time.Time
	Refreshing  bool
}

type StatusMonitor struct {
	mu           sync.RWMutex
	startOnce    sync.Once
	entries      map[string]statusEntry
	probeLimiter chan struct{}
}

var defaultStatusMonitor = &StatusMonitor{
	entries:      map[string]statusEntry{},
	probeLimiter: make(chan struct{}, statusProbeParallel),
}

func DefaultStatusMonitor() *StatusMonitor {
	return defaultStatusMonitor
}

func StartStatusMonitor() {
	defaultStatusMonitor.Start()
}

func (m *StatusMonitor) Start() {
	m.startOnce.Do(func() {
		go m.loop()
	})
}

func (m *StatusMonitor) loop() {
	m.refreshAll()

	ticker := time.NewTicker(statusRefreshEvery)
	defer ticker.Stop()

	for range ticker.C {
		m.refreshAll()
	}
}

func (m *StatusMonitor) GetPingStatus(ip string) string {
	trimmedIP := strings.TrimSpace(ip)
	if trimmedIP == "" {
		return statusOffline
	}

	m.Start()
	key := "ping:" + trimmedIP
	return m.getStatus(key, func() string {
		return probePing(trimmedIP)
	})
}

func (m *StatusMonitor) GetPingObservedUptime(ip string) string {
	trimmedIP := strings.TrimSpace(ip)
	if trimmedIP == "" {
		return ""
	}

	m.Start()
	key := "ping:" + trimmedIP
	_ = m.getStatus(key, func() string {
		return probePing(trimmedIP)
	})

	m.mu.RLock()
	entry, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok || entry.Status != statusOnline || entry.OnlineSince.IsZero() {
		return ""
	}
	return formatObservedUptime(time.Since(entry.OnlineSince))
}

func (m *StatusMonitor) GetDNSStatus(addr string) string {
	trimmedAddr := strings.TrimSpace(addr)
	if trimmedAddr == "" {
		return statusOffline
	}

	m.Start()
	key := "dns:" + trimmedAddr
	return m.getStatus(key, func() string {
		return probeDNS(trimmedAddr)
	})
}

func (m *StatusMonitor) getStatus(key string, probe func() string) string {
	now := time.Now()

	m.mu.RLock()
	entry, ok := m.entries[key]
	m.mu.RUnlock()

	if !ok {
		m.scheduleRefresh(key, probe)
		return statusChecking
	}

	if entry.Status == "" {
		entry.Status = statusChecking
	}

	if now.Sub(entry.CheckedAt) > statusStaleAfter {
		m.scheduleRefresh(key, probe)
	}

	return entry.Status
}

func (m *StatusMonitor) scheduleRefresh(key string, probe func() string) {
	m.mu.Lock()
	entry := m.entries[key]
	if entry.Refreshing {
		m.mu.Unlock()
		return
	}
	entry.Refreshing = true
	if entry.Status == "" {
		entry.Status = statusChecking
	}
	m.entries[key] = entry
	m.mu.Unlock()

	go func() {
		m.probeLimiter <- struct{}{}
		status := probe()
		<-m.probeLimiter

		m.mu.Lock()
		next := m.entries[key]
		previousStatus := next.Status
		next.Status = status
		next.CheckedAt = time.Now()
		switch status {
		case statusOnline:
			if previousStatus != statusOnline || next.OnlineSince.IsZero() {
				next.OnlineSince = next.CheckedAt
			}
		default:
			next.OnlineSince = time.Time{}
		}
		next.Refreshing = false
		m.entries[key] = next
		m.mu.Unlock()
	}()
}

func (m *StatusMonitor) refreshAll() {
	settings := NewSettingsService()

	dnsAddr := strings.TrimSpace(settings.GetValue("system.dns_probe_addr"))
	if dnsAddr != "" {
		addr := dnsAddr
		m.scheduleRefresh("dns:"+addr, func() string {
			return probeDNS(addr)
		})
	}

	healthIP := strings.TrimSpace(settings.GetValue("vpn.healthcheck_ip"))
	if healthIP != "" {
		ip := healthIP
		m.scheduleRefresh("ping:"+ip, func() string {
			return probePing(ip)
		})
	}

	for _, ip := range m.loadServerIPs() {
		ip := ip
		m.scheduleRefresh("ping:"+ip, func() string {
			return probePing(ip)
		})
	}
}

func (m *StatusMonitor) loadServerIPs() []string {
	rows, err := db.DB.Query("SELECT ip FROM servers WHERE ip <> ''")
	if err != nil {
		log.Println("status monitor server query failed:", err)
		return nil
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	ips := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			log.Println("status monitor server scan failed:", err)
			continue
		}
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}

	if err := rows.Err(); err != nil {
		log.Println("status monitor server rows failed:", err)
	}

	return ips
}

func probePing(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), statusProbeTimeout)
	defer cancel()

	if err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip).Run(); err == nil {
		return statusOnline
	}
	return statusOffline
}

func probeDNS(addr string) string {
	conn, err := net.DialTimeout("udp", addr, statusProbeTimeout)
	if err != nil {
		return statusOffline
	}
	_ = conn.Close()
	return statusOnline
}

func formatObservedUptime(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	minutes := int(duration.Round(time.Minute) / time.Minute)
	if minutes < 1 {
		return "<1m"
	}
	days := minutes / (60 * 24)
	hours := (minutes % (60 * 24)) / 60
	mins := minutes % 60

	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, strconv.Itoa(days)+"d")
	}
	if hours > 0 {
		parts = append(parts, strconv.Itoa(hours)+"h")
	}
	if mins > 0 && days == 0 {
		parts = append(parts, strconv.Itoa(mins)+"m")
	}
	if len(parts) == 0 {
		return "<1m"
	}
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, " ")
}
