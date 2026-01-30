package services

import (
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"github.com/miekg/dns"
	"log"
	"time"
	"strings"
)

type DomainService struct{}

func NewDomainService() *DomainService {
	return &DomainService{}
}

func (s *DomainService) CreateDomain(name string) error {
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
	_, err := db.DB.Exec(
		"DELETE FROM domains WHERE id=?",
		id,
	)
	if err != nil {
		log.Println("DELETE domain failed:", err)
	}
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

	return domains
}

func checkNS(domain string) string {
	nsStatus := "Offline"
	settings := NewSettingsService()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	c := &dns.Client{Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, settings.GetValue("dns.resolver_addr"))
	if err != nil {
		log.Println("DNS query error for", domain, ":", err)
		return nsStatus
	}

	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			host := strings.TrimSuffix(strings.ToLower(ns.Ns), ".")
			if host == strings.ToLower(settings.GetValue("dns.primary_ns")) {
				nsStatus = "Online"
				break
			}
		}
	}

	return nsStatus
}
