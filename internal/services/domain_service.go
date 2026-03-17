package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
	"time"
)

type DomainService struct{}

func NewDomainService() *DomainService {
	return &DomainService{}
}

func (s *DomainService) CreateDomain(name string) error {
	name = normalizeDomainName(name)
	_, err := db.DB.Exec(
		"INSERT INTO domains (name) VALUES (?)",
		name,
	)
	if err != nil {
		log.Println("INSERT domain failed:", err)
	}
	return err
}

func (s *DomainService) DeleteDomain(id string) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec("DELETE FROM records WHERE domain_id = ?", id); err != nil {
		log.Println("DELETE records for domain failed:", err)
		return err
	}
	if _, err = tx.Exec("DELETE FROM domains WHERE id = ?", id); err != nil {
		log.Println("DELETE domain failed:", err)
		return err
	}
	err = tx.Commit()
	return err
}

func (s *DomainService) GetDomains() []models.Domain {
	rows, err := db.DB.Query("SELECT id, name FROM domains ORDER BY name")
	if err != nil {
		log.Println("DB query error:", err)
		return nil
	}
	defer rows.Close()

	var domains []models.Domain
	for rows.Next() {
		var d models.Domain
		if err := rows.Scan(&d.ID, &d.Name); err != nil {
			log.Println("Row scan error:", err)
			continue
		}

		d.Status = checkNS(d.Name)
		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		log.Println("Rows iteration error:", err)
	}

	return domains
}

func checkNS(domain string) string {
	settings := NewSettingsService()
	expectedHosts := configuredAuthoritativeNSHosts(settings)
	if len(expectedHosts) == 0 {
		return "Offline"
	}

	resolverHosts, rcode, err := queryNSHosts(settings.GetValue("dns.resolver_addr"), domain, true)
	if err == nil {
		if containsAllNSHosts(resolverHosts, expectedHosts) {
			return "Online"
		}
		if len(resolverHosts) > 0 {
			return "Delegation mismatch"
		}
	} else {
		log.Println("DNS query error for", domain, ":", err)
	}

	authoritativeHosts, authErr := queryAuthoritativeNSHosts(domain, expectedHosts)
	if authErr == nil && containsAllNSHosts(authoritativeHosts, expectedHosts) {
		if rcode == dns.RcodeServerFailure {
			return "DNSSEC Error"
		}
		if len(resolverHosts) == 0 {
			return "Online"
		}
		return "Delegation mismatch"
	}

	return "Offline"
}

func configuredAuthoritativeNSHosts(settings *SettingsService) []string {
	hosts := normalizeNSHosts(splitCSVHosts(settings.GetValue("dns.ns_hosts")))
	if len(hosts) > 0 {
		return hosts
	}

	primary := normalizeNSHost(settings.GetValue("dns.primary_ns"))
	if primary == "" {
		return nil
	}
	return []string{primary}
}

func queryNSHosts(serverAddr, domain string, recurse bool) ([]string, int, error) {
	serverAddr = strings.TrimSpace(serverAddr)
	if serverAddr == "" {
		return nil, 0, fmt.Errorf("empty DNS server address")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	msg.RecursionDesired = recurse

	client := &dns.Client{Timeout: 2 * time.Second}
	response, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		return nil, 0, err
	}

	hosts := extractNSHosts(response.Answer)
	if response.Rcode != dns.RcodeSuccess {
		return hosts, response.Rcode, fmt.Errorf("rcode=%s", dns.RcodeToString[response.Rcode])
	}

	return hosts, response.Rcode, nil
}

func queryAuthoritativeNSHosts(domain string, hosts []string) ([]string, error) {
	var lastErr error
	for _, host := range hosts {
		addr := net.JoinHostPort(host, "53")
		actualHosts, _, err := queryNSHosts(addr, domain, false)
		if err != nil {
			lastErr = err
			continue
		}
		if len(actualHosts) > 0 {
			return actualHosts, nil
		}
		lastErr = fmt.Errorf("empty NS answer from %s", host)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no authoritative hosts configured")
	}
	return nil, lastErr
}

func extractNSHosts(rrs []dns.RR) []string {
	seen := map[string]struct{}{}
	hosts := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		host := normalizeNSHost(ns.Ns)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

func containsAllNSHosts(actual, expected []string) bool {
	if len(expected) == 0 {
		return len(actual) > 0
	}

	actualSet := map[string]struct{}{}
	for _, host := range normalizeNSHosts(actual) {
		actualSet[host] = struct{}{}
	}
	for _, host := range normalizeNSHosts(expected) {
		if _, ok := actualSet[host]; !ok {
			return false
		}
	}
	return true
}

func normalizeNSHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = normalizeNSHost(host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func normalizeNSHost(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), "."))
	if host == "" {
		return ""
	}
	return host
}

func splitCSVHosts(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeDomainName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
