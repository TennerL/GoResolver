package services

import (
	"log"
	"sync"
	"time"
)

const (
	certificateRenewalCheckEvery = 12 * time.Hour
	certificateRenewalBatchLimit = 25
)

type CertificateRenewalMonitor struct {
	startOnce sync.Once
	service   *ServerConfigurationService
}

var defaultCertificateRenewalMonitor = &CertificateRenewalMonitor{
	service: NewServerConfigurationService(),
}

func StartCertificateRenewalMonitor() {
	defaultCertificateRenewalMonitor.Start()
}

func (m *CertificateRenewalMonitor) Start() {
	m.startOnce.Do(func() {
		go m.loop()
	})
}

func (m *CertificateRenewalMonitor) loop() {
	m.runOnce()

	ticker := time.NewTicker(certificateRenewalCheckEvery)
	defer ticker.Stop()

	for range ticker.C {
		m.runOnce()
	}
}

func (m *CertificateRenewalMonitor) runOnce() {
	siteIDs, err := m.service.DueCertificateSiteIDs(time.Now().UTC(), certificateRenewalBatchLimit)
	if err != nil {
		log.Println("certificate renewal scan failed:", err)
		return
	}
	for _, siteID := range siteIDs {
		if siteID == "" {
			continue
		}
		if err := m.service.RenewCert(siteID); err != nil {
			log.Printf("certificate auto-renew failed for site %s: %v", siteID, err)
		}
	}
}
