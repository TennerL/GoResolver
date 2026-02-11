package main

import (
	"GoResolver/internal/app"
	"GoResolver/internal/db"
	"GoResolver/internal/logging"
	"GoResolver/internal/services"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"sync"
	"strings"
	"time"
)

type RecordWithTTL struct {
	Content string
	TTL     uint32
}

type dnssecKeyMaterial struct {
	Key    *dns.DNSKEY
	Signer ed25519.PrivateKey
}

var dnssecCache struct {
	mu       sync.Mutex
	material *dnssecKeyMaterial
}


func main() {
	db.Init()

	if settingEnabled(appSettings.GetValue("dns.enabled"), true) {
		go startDNSServer()
	} else {
		log.Println("Built-in DNS server is disabled (dns.enabled=0)")
	}
	go logging.StartNginxLogIngester(
		db.DB,
		appSettings.GetValue("logging.nginx_access_json"),
	)
	go services.NewServerConfigurationService().StartFail2BanEnforcer()

	application := app.New()
	application.Run()
}

/* ================= DNS SERVER ================= */

func startDNSServer() {
	addr := net.UDPAddr{
		Port: 53,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("DNS Server could not start: %v", err)
	}
	defer conn.Close()

	log.Println("DNS server running on port 53...")

	buf := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go handleDNSQuery(conn, clientAddr, buf[:n])
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
		ip, ttl := querySingleRecord(qname, "A")
		if ip == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		addRR(msg, fmt.Sprintf("%s %d IN A %s", fqdn, ttl, ip))

	case dns.TypeAAAA:
		ip, ttl := querySingleRecord(qname, "AAAA")
		if ip == "" {
			msg.Rcode = dns.RcodeNameError
			break
		}
		addRR(msg, fmt.Sprintf("%s %d IN AAAA %s", fqdn, ttl, ip))

	case dns.TypeCNAME:
		target, ttl := querySingleRecord(qname, "CNAME")
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
		txts := queryMultiRecords(qname, "TXT")
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
		mxs := queryMultiRecords(qname, "MX")
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

	case dns.TypeNS:
		nsHosts := parseCSV(appSettings.GetValue("dns.ns_hosts"))
		if len(nsHosts) == 0 {
			msg.Rcode = dns.RcodeNameError
			break
		}
		for _, ns := range nsHosts {
			addRR(msg, fmt.Sprintf(
				"%s 3600 IN NS %s",
				fqdn,
				ns,
			))
		}

	case dns.TypeCAA:
		addRR(msg, fmt.Sprintf(
			`%s 3600 IN CAA 0 issue "%s"`,
			fqdn,
			appSettings.GetValue("dns.caa_issuer"),
		))

	case dns.TypeSOA:
		rname := appSettings.GetValue("dns.soa_rname_template")
		if rname == "" {
			rname = "hostmaster.{domain}"
		}
		rname = strings.ReplaceAll(rname, "{domain}", fqdn)
		addRR(msg, fmt.Sprintf(
			"%s 3600 IN SOA %s %s 1 3600 900 604800 86400",
			fqdn,
			appSettings.GetValue("dns.soa_mname"),
			rname,
		))

	case dns.TypeDNSKEY:
		if !settingEnabled(appSettings.GetValue("dns.dnssec_enabled"), false) {
			msg.Rcode = dns.RcodeNotImplemented
			break
		}
		zone := findAuthoritativeZone(qname)
		if zone == "" || fqdn != dns.Fqdn(zone) {
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
		zone := findAuthoritativeZone(qname)
		if zone == "" || fqdn != dns.Fqdn(zone) {
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
		zone := findAuthoritativeZone(qname)
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

func querySingleRecord(domain, rtype string) (string, uint32) {
	var content string
	var ttl uint32

	err := db.DB.QueryRow(
		"SELECT content, ttl FROM records WHERE name=? AND type=? LIMIT 1",
		domain, rtype,
	).Scan(&content, &ttl)

	if err != nil {
		return "", 0
	}
	return content, ttl
}

func queryMultiRecords(domain, rtype string) []RecordWithTTL {
	rows, err := db.DB.Query(
		"SELECT content, ttl FROM records WHERE name=? AND type=?",
		domain, rtype,
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
	return result
}

var appSettings = services.NewSettingsService()

func findAuthoritativeZone(qname string) string {
	var zone string
	err := db.DB.QueryRow(`
		SELECT name
		FROM domains
		WHERE ? = name OR ? LIKE CONCAT('%.', name)
		ORDER BY LENGTH(name) DESC
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

	if dnssecCache.material != nil {
		return dnssecCache.material, nil
	}

	pemValue := appSettings.GetValue("dns.dnssec_private_key_pem")
	if strings.TrimSpace(pemValue) == "" {
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
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("invalid dns.dnssec_private_key_pem")
	}

	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := pk.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("dnssec private key must be Ed25519")
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
	}
	return dnssecCache.material, nil
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
