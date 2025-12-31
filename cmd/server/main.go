package main

import (
	"GoResolver/internal/app"
	"GoResolver/internal/db"
	"GoResolver/internal/logging"
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
)

type RecordWithTTL struct {
	Content string
	TTL     uint32
}

func main() {
	db.Init()

	//go startDNSServer()
	go logging.StartNginxLogIngester(
		db.DB,
		"/var/log/nginx/access.db.json",
	)

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
	if len(data) < 12 {
		return
	}

	transactionID := binary.BigEndian.Uint16(data[:2])
	rdBit := uint16(data[2] & 0x01)

	idx := 12
	qname, idx := parseQName(data, idx)
	if idx+4 > len(data) {
		return
	}

	qtype := binary.BigEndian.Uint16(data[idx : idx+2])
	fqdn := dns.Fqdn(qname)

	msg := new(dns.Msg)
	msg.Id = transactionID
	msg.Response = true
	msg.Authoritative = true
	msg.RecursionDesired = (rdBit != 0)
	msg.Question = []dns.Question{
		{Name: fqdn, Qtype: qtype, Qclass: dns.ClassINET},
	}

	switch qtype {

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
		nsHosts := []string{"ns1.nsstatic.org.", "ns2.nsstatic.org."}
		for _, ns := range nsHosts {
			addRR(msg, fmt.Sprintf(
				"%s 3600 IN NS %s",
				fqdn,
				ns,
			))
		}

	case dns.TypeCAA:
		addRR(msg, fmt.Sprintf(
			`%s 3600 IN CAA 0 issue "letsencrypt.org"`,
			fqdn,
		))

	case dns.TypeSOA:
		addRR(msg, fmt.Sprintf(
			"%s 3600 IN SOA ns1.nsstatic.org. hostmaster.%s 1 3600 900 604800 86400",
			fqdn,
			fqdn,
		))

	default:
		msg.Rcode = dns.RcodeNotImplemented
	}

	buf, err := msg.Pack()
	if err != nil {
		log.Println("Failed to pack DNS response:", err)
		return
	}

	_, _ = conn.WriteToUDP(buf, clientAddr)
}

/* ================= HELPERS ================= */

func parseQName(msg []byte, offset int) (string, int) {
	var labels []string
	for {
		if offset >= len(msg) {
			return "", len(msg)
		}
		l := int(msg[offset])
		offset++
		if l == 0 {
			break
		}
		if offset+l > len(msg) {
			return "", len(msg)
		}
		labels = append(labels, string(msg[offset:offset+l]))
		offset += l
	}
	return strings.Join(labels, "."), offset
}

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
