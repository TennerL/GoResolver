package main

import (
	"github.com/miekg/dns"
	"math"
	"testing"
)

func TestSOASerialFromUnixZeroFallsBackToOne(t *testing.T) {
	if got := soaSerialFromUnix(0); got != 1 {
		t.Fatalf("expected serial 1, got %d", got)
	}
}

func TestSOASerialFromUnixClampsUint32(t *testing.T) {
	if got := soaSerialFromUnix(math.MaxInt64); got != math.MaxUint32 {
		t.Fatalf("expected serial %d, got %d", uint32(math.MaxUint32), got)
	}
}

func TestNSECTypeBitMapForApexIncludesAuthoritativeTypes(t *testing.T) {
	got := nsecTypeBitMap([]string{"A", "AAAA"}, true, true, true)
	wantTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeDNSKEY, dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG, dns.TypeSOA}
	for _, want := range wantTypes {
		if !containsDNSType(got, want) {
			t.Fatalf("expected bitmap to contain type %d, got %v", want, got)
		}
	}
	if containsDNSType(got, dns.TypeDS) {
		t.Fatalf("expected bitmap to omit DS, got %v", got)
	}
}

func TestNSECTypeBitMapForSubdomainOmitsApexOnlyTypes(t *testing.T) {
	got := nsecTypeBitMap([]string{"A"}, false, true, true)
	if !containsDNSType(got, dns.TypeA) || !containsDNSType(got, dns.TypeCAA) {
		t.Fatalf("expected bitmap to contain A and CAA, got %v", got)
	}
	if containsDNSType(got, dns.TypeSOA) || containsDNSType(got, dns.TypeNS) || containsDNSType(got, dns.TypeDNSKEY) || containsDNSType(got, dns.TypeDS) {
		t.Fatalf("expected bitmap to omit apex-only types and DS, got %v", got)
	}
}

func TestFindNSECSpanReturnsExistingOwnerForKnownName(t *testing.T) {
	owner, next, exists := findNSECSpan([]string{"nihonsaba.net", "dns.nihonsaba.net", "vt.nihonsaba.net"}, "dns.nihonsaba.net")
	if !exists {
		t.Fatal("expected existing name to be reported as existing")
	}
	if owner != "dns.nihonsaba.net" {
		t.Fatalf("owner = %q, want %q", owner, "dns.nihonsaba.net")
	}
	if next == "" {
		t.Fatal("expected next name to be set")
	}
}

func containsDNSType(types []uint16, want uint16) bool {
	for _, got := range types {
		if got == want {
			return true
		}
	}
	return false
}
