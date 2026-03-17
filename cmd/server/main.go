package main

import (
	"GoResolver/internal/app"
	"GoResolver/internal/db"
	"GoResolver/internal/logging"
	"GoResolver/internal/services"
	"GoResolver/internal/session"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type RecordWithTTL struct {
	Content string
	TTL     uint32
}

type dnssecKeyMaterial struct {
	Key    *dns.DNSKEY
	Signer ed25519.PrivateKey
	Source string
}

var dnssecCache struct {
	mu       sync.Mutex
	material *dnssecKeyMaterial
}

var schemaColumnCache struct {
	mu     sync.RWMutex
	values map[string]bool
}

func main() {
	db.Init()
	if err := session.Init(); err != nil {
		log.Fatal(err)
	}

	if settingEnabled(appSettings.GetValue("dns.enabled"), true) {
		go func() {
			if err := startDNSServer(); err != nil {
				log.Printf("DNS server stopped: %v", err)
			}
		}()
	} else {
		log.Println("Built-in DNS server is disabled (dns.enabled=0)")
	}

	go logging.StartNginxLogIngester(
		db.DB,
		strings.TrimSpace(appSettings.GetValue("logging.nginx_access_json")),
	)
	go services.NewServerConfigurationService().StartFail2BanEnforcer()

	application := app.New()
	if err := application.Run(); err != nil {
		log.Fatal(err)
	}
}

/* ================= DNS SERVER ================= */

func startDNSServer() error {
	listeners := []struct {
		network string
		addr    *net.UDPAddr
	}{
		{
			network: "udp4",
			addr: &net.UDPAddr{
				Port: 53,
				IP:   net.IPv4zero,
			},
		},
		{
			network: "udp6",
			addr: &net.UDPAddr{
				Port: 53,
				IP:   net.ParseIP("::"),
			},
		},
	}

	started := 0
	for _, listener := range listeners {
		conn, err := net.ListenUDP(listener.network, listener.addr)
		if err != nil {
			log.Printf("DNS server %s listener could not start on %s: %v", listener.network, listener.addr.String(), err)
			continue
		}
		started++
		log.Printf("DNS server running on %s...", conn.LocalAddr())
		go serveDNS(conn)
	}

	if started == 0 {
		return fmt.Errorf("dns server could not start on IPv4 or IPv6")
	}

	return nil
}

func serveDNS(conn *net.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 1232)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("DNS read failed on %s: %v", conn.LocalAddr(), err)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		go handleDNSQuery(conn, clientAddr, packet)
	}
}

func handleDNSQuery(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	req := new(dns.Msg)
	if err := req.Unpack(data); err != nil {
		return
	}

	if len(req.Question) == 0 {
		return
	}

	q := req.Question[0]
	qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	fqdn := dns.Fqdn(qname)
	zone := findAuthoritativeZone(qname)
	zoneFQDN := dns.Fqdn(zone)

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = false

	doBit := false
	if opt := req.IsEdns0(); opt != nil {
		doBit = opt.Do()
		msg.SetEdns0(1232, doBit)
	}

	switch q.Qtype {

	case dns.TypeA:
		ip, ttl := querySingleRecord(zone, qname, "A")
		if ip == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		addRR(msg, fmt.Sprintf("%s %d IN A %s", fqdn, ttl, ip))

	case dns.TypeAAAA:
		ip, ttl := querySingleRecord(zone, qname, "AAAA")
		if ip == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		addRR(msg, fmt.Sprintf("%s %d IN AAAA %s", fqdn, ttl, ip))

	case dns.TypeCNAME:
		target, ttl := querySingleRecord(zone, qname, "CNAME")
		if target == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		addRR(msg, fmt.Sprintf(
			"%s %d IN CNAME %s",
			fqdn,
			ttl,
			dns.Fqdn(target),
		))

	case dns.TypeTXT:
		txts := queryMultiRecords(zone, qname, "TXT")
		if len(txts) == 0 {
			msg.Rcode = dns.RcodeNameError
			break
		}
		for _, t := range txts {
			addRR(msg, fmt.Sprintf(
				`%s %d IN TXT "%s"`,
				fqdn,
				t.TTL,
				t.Content,
			))
		}

	case dns.TypeMX:
		mxs := queryMultiRecords(zone, qname, "MX")
		if len(mxs) == 0 {
			msg.Rcode = dns.RcodeNameError
			break
		}
		for _, mx := range mxs {
			parts := strings.SplitN(mx.Content, ":", 2)
			if len(parts) != 2 {
				log.Println("Invalid MX record:", mx.Content)
				continue
			}
			addRR(msg, fmt.Sprintf(
				"%s %d IN MX %s %s",
				fqdn,
				mx.TTL,
				parts[0],
				dns.Fqdn(parts[1]),
			))
		}

	case dns.TypeTLSA:
		tlsaRecords := queryMultiRecords(zone, qname, "TLSA")
		if len(tlsaRecords) == 0 {
			msg.Rcode = dns.RcodeNameError
			break
		}
		for _, rec := range tlsaRecords {
			addRR(msg, fmt.Sprintf(
				"%s %d IN TLSA %s",
				fqdn,
				rec.TTL,
				rec.Content,
			))
		}

	case dns.TypeNS:
		if zone == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		nsHosts := parseCSV(appSettings.GetValue("dns.ns_hosts"))
		if len(nsHosts) == 0 {
			msg.Rcode = dns.RcodeNameError
			break
		}
		for _, ns := range nsHosts {
			addRR(msg, fmt.Sprintf(
				"%s 3600 IN NS %s",
				zoneFQDN,
				ns,
			))
		}

	case dns.TypeCAA:
		if zone == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		addRR(msg, fmt.Sprintf(
			`%s 3600 IN CAA 0 issue "%s"`,
			zoneFQDN,
			appSettings.GetValue("dns.caa_issuer"),
		))

	case dns.TypeSOA:
		if zone == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		rname := appSettings.GetValue("dns.soa_rname_template")
		if rname == "" {
			rname = "hostmaster.{domain}"
		}
		rname = strings.ReplaceAll(rname, "{domain}", zoneFQDN)
		addRR(msg, fmt.Sprintf(
			"%s 3600 IN SOA %s %s %d 3600 900 604800 86400",
			zoneFQDN,
			appSettings.GetValue("dns.soa_mname"),
			rname,
			zoneSOASerial(zone),
		))

	case dns.TypeDNSKEY:
		if !settingEnabled(appSettings.GetValue("dns.dnssec_enabled"), false) {
			msg.Rcode = dns.RcodeNotImplemented
			break
		}
		if zone == "" || fqdn != zoneFQDN {
			msg.Rcode = dns.RcodeNameError
			break
		}
		material, err := getOrCreateDNSSECKey()
		if err != nil {
			log.Println("DNSSEC key load failed:", err)
			msg.Rcode = dns.RcodeServerFailure
			break
		}
		keyCopy := *material.Key
		keyCopy.Hdr = dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
		msg.Answer = append(msg.Answer, &keyCopy)
		if sig := signRRSet(msg.Answer, material.Key, material.Signer, dns.Fqdn(zone)); sig != nil {
			msg.Answer = append(msg.Answer, sig)
		}

	case dns.TypeDS:
		if !settingEnabled(appSettings.GetValue("dns.dnssec_enabled"), false) {
			msg.Rcode = dns.RcodeNotImplemented
			break
		}
		if zone == "" || fqdn != zoneFQDN {
			msg.Rcode = dns.RcodeNameError
			break
		}
		material, err := getOrCreateDNSSECKey()
		if err != nil {
			log.Println("DNSSEC key load failed:", err)
			msg.Rcode = dns.RcodeServerFailure
			break
		}
		keyCopy := *material.Key
		keyCopy.Hdr = dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
		ds := keyCopy.ToDS(dns.SHA256)
		if ds == nil {
			msg.Rcode = dns.RcodeServerFailure
			break
		}
		ds.Hdr = dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
		msg.Answer = append(msg.Answer, ds)
		if sig := signRRSet(msg.Answer, material.Key, material.Signer, dns.Fqdn(zone)); sig != nil {
			msg.Answer = append(msg.Answer, sig)
		}

	default:
		msg.Rcode = dns.RcodeNotImplemented
	}

	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0 &&
		doBit && settingEnabled(appSettings.GetValue("dns.dnssec_enabled"), false) &&
		q.Qtype != dns.TypeDNSKEY && q.Qtype != dns.TypeDS && q.Qtype != dns.TypeRRSIG {
		if zone != "" {
			material, err := getOrCreateDNSSECKey()
			if err != nil {
				log.Println("DNSSEC key load failed:", err)
			} else if sig := signRRSet(msg.Answer, material.Key, material.Signer, dns.Fqdn(zone)); sig != nil {
				msg.Answer = append(msg.Answer, sig)
			}
		}
	}

	buf, err := msg.Pack()
	if err != nil {
		log.Println("Failed to pack DNS response:", err)
		return
	}

	_, _ = conn.WriteToUDP(buf, clientAddr)
}

/* ================= HELPERS ================= */

func addRR(msg *dns.Msg, rrStr string) {
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		log.Println("Invalid RR:", err, rrStr)
		return
	}
	msg.Answer = append(msg.Answer, rr)
}

func querySingleRecord(zone, domain, rtype string) (string, uint32) {
	if zone == "" {
		return "", 0
	}

	var content string
	var ttl uint32

	err := db.DB.QueryRow(
		`SELECT r.content, r.ttl
		FROM records r
		INNER JOIN domains d ON d.id = r.domain_id
		WHERE TRIM(TRAILING '.' FROM LOWER(d.name)) = ?
		  AND TRIM(TRAILING '.' FROM LOWER(r.name)) = ?
		  AND UPPER(r.type) = ?
		LIMIT 1`,
		zone, domain, rtype,
	).Scan(&content, &ttl)

	if err != nil {
		return "", 0
	}
	return content, ttl
}

func queryMultiRecords(zone, domain, rtype string) []RecordWithTTL {
	if zone == "" {
		return nil
	}

	rows, err := db.DB.Query(
		`SELECT r.content, r.ttl
		FROM records r
		INNER JOIN domains d ON d.id = r.domain_id
		WHERE TRIM(TRAILING '.' FROM LOWER(d.name)) = ?
		  AND TRIM(TRAILING '.' FROM LOWER(r.name)) = ?
		  AND UPPER(r.type) = ?`,
		zone, domain, rtype,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []RecordWithTTL
	for rows.Next() {
		var r RecordWithTTL
		if err := rows.Scan(&r.Content, &r.TTL); err == nil {
			result = append(result, r)
		}
	}
	if err := rows.Err(); err != nil {
		log.Println("Record query failed:", err)
		return nil
	}
	return result
}

var appSettings = services.NewSettingsService()

func findAuthoritativeZone(qname string) string {
	var zone string
	err := db.DB.QueryRow(`
		SELECT TRIM(TRAILING '.' FROM LOWER(name))
		FROM domains
		WHERE ? = TRIM(TRAILING '.' FROM LOWER(name))
		   OR ? LIKE CONCAT('%.', TRIM(TRAILING '.' FROM LOWER(name)))
		ORDER BY LENGTH(TRIM(TRAILING '.' FROM LOWER(name))) DESC
		LIMIT 1
	`, qname, qname).Scan(&zone)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

func getOrCreateDNSSECKey() (*dnssecKeyMaterial, error) {
	dnssecCache.mu.Lock()
	defer dnssecCache.mu.Unlock()

	pemValue := appSettings.GetValue("dns.dnssec_private_key_pem")
	normalizedSource := normalizeDNSSECPrivateKeyValue(pemValue)

	if dnssecCache.material != nil && dnssecCache.material.Source == normalizedSource {
		return dnssecCache.material, nil
	}

	if strings.TrimSpace(normalizedSource) == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemValue = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}))
		if err := appSettings.SetMany(map[string]string{
			"dns.dnssec_private_key_pem": pemValue,
		}); err != nil {
			return nil, err
		}
		normalizedSource = normalizeDNSSECPrivateKeyValue(pemValue)
	}

	priv, err := parseDNSSECPrivateKey(normalizedSource)
	if err != nil {
		return nil, err
	}

	pub := priv.Public().(ed25519.PublicKey)
	key := &dns.DNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	key.Hdr = dns.RR_Header{
		Name:   ".",
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}

	dnssecCache.material = &dnssecKeyMaterial{
		Key:    key,
		Signer: priv,
		Source: normalizedSource,
	}
	return dnssecCache.material, nil
}

func parseDNSSECPrivateKey(raw string) (ed25519.PrivateKey, error) {
	// Allow pasted values wrapped in quotes and with escaped newlines.
	value := normalizeDNSSECPrivateKeyValue(raw)

	// Preferred format: PKCS#8 PEM Ed25519 private key.
	if block, _ := pem.Decode([]byte(value)); block != nil {
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if priv, ok := pk.(ed25519.PrivateKey); ok {
				return priv, nil
			}
			return nil, errors.New("dnssec private key must be Ed25519")
		}
	}

	// Compatibility format: BIND dnssec-keygen .private file content.
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PrivateKey:") {
			continue
		}
		b64 := strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		rawKey, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		switch len(rawKey) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(rawKey), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(rawKey), nil
		}
	}

	return nil, errors.New("invalid dns.dnssec_private_key_pem")
}

func normalizeDNSSECPrivateKeyValue(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"'`)
	if strings.Contains(value, `\n`) {
		value = strings.ReplaceAll(value, `\n`, "\n")
	}
	return normalizeCompactPrivateKeyPEM(value)
}

func normalizeCompactPrivateKeyPEM(value string) string {
	const begin = "-----BEGIN PRIVATE KEY-----"
	const end = "-----END PRIVATE KEY-----"
	if !strings.Contains(value, begin) || !strings.Contains(value, end) {
		return value
	}
	bi := strings.Index(value, begin)
	ei := strings.Index(value, end)
	if bi < 0 || ei < 0 || ei <= bi {
		return value
	}
	body := strings.TrimSpace(value[bi+len(begin) : ei])
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	body = strings.ReplaceAll(body, "\t", "")
	body = strings.ReplaceAll(body, " ", "")
	if body == "" {
		return value
	}
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString("\n")
	for i := 0; i < len(body); i += 64 {
		j := i + 64
		if j > len(body) {
			j = len(body)
		}
		b.WriteString(body[i:j])
		b.WriteString("\n")
	}
	b.WriteString(end)
	b.WriteString("\n")
	return b.String()
}

func signRRSet(rrset []dns.RR, key *dns.DNSKEY, signer ed25519.PrivateKey, signerName string) *dns.RRSIG {
	if len(rrset) == 0 {
		return nil
	}
	h := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   h.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  h.Class,
			Ttl:    h.Ttl,
		},
		TypeCovered: h.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(h.Name)),
		OrigTtl:     h.Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-5 * time.Minute).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(signerName),
	}
	if err := sig.Sign(signer, rrset); err != nil {
		log.Println("DNSSEC sign failed:", err)
		return nil
	}
	return sig
}

func zoneSOASerial(zone string) uint32 {
	latest := time.Time{}

	if dbHasColumn("domains", "created_at") {
		var domainCreated sql.NullTime
		err := db.DB.QueryRow(`
			SELECT created_at
			FROM domains
			WHERE TRIM(TRAILING '.' FROM LOWER(name)) = ?
			LIMIT 1
		`, zone).Scan(&domainCreated)
		if err != nil && err != sql.ErrNoRows {
			log.Println("SOA serial domain lookup failed:", err)
		}
		if domainCreated.Valid {
			latest = domainCreated.Time.UTC()
		}
	}

	recordColumn := ""
	switch {
	case dbHasColumn("records", "updated_at"):
		recordColumn = "updated_at"
	case dbHasColumn("records", "created_at"):
		recordColumn = "created_at"
	}

	if recordColumn != "" {
		var recordUpdated sql.NullTime
		query := fmt.Sprintf(`
			SELECT MAX(r.%s)
			FROM records r
			INNER JOIN domains d ON d.id = r.domain_id
			WHERE TRIM(TRAILING '.' FROM LOWER(d.name)) = ?
		`, recordColumn)
		err := db.DB.QueryRow(query, zone).Scan(&recordUpdated)
		if err != nil {
			log.Println("SOA serial record lookup failed:", err)
		}
		if recordUpdated.Valid && (latest.IsZero() || recordUpdated.Time.After(latest)) {
			latest = recordUpdated.Time.UTC()
		}
	}

	if latest.IsZero() {
		return 1
	}

	return soaSerialFromUnix(latest.Unix())
}

func dbHasColumn(table, column string) bool {
	key := table + "." + column

	schemaColumnCache.mu.RLock()
	if schemaColumnCache.values != nil {
		if exists, ok := schemaColumnCache.values[key]; ok {
			schemaColumnCache.mu.RUnlock()
			return exists
		}
	}
	schemaColumnCache.mu.RUnlock()

	var count int
	err := db.DB.QueryRow(`
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = ?
		  AND column_name = ?
	`, table, column).Scan(&count)
	if err != nil {
		log.Printf("SOA serial schema lookup failed for %s.%s: %v", table, column, err)
		return false
	}

	exists := count > 0
	schemaColumnCache.mu.Lock()
	if schemaColumnCache.values == nil {
		schemaColumnCache.values = map[string]bool{}
	}
	schemaColumnCache.values[key] = exists
	schemaColumnCache.mu.Unlock()
	return exists
}

func soaSerialFromUnix(serial int64) uint32 {
	if serial < 1 {
		serial = 1
	}
	if serial > int64(^uint32(0)) {
		serial = int64(^uint32(0))
	}
	return uint32(serial)
}

func settingEnabled(raw string, defaultValue bool) bool {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return defaultValue
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func parseCSV(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{}
	}
	return out
}
