package services

import "testing"

func TestContainsAllNSHostsNormalizesCaseAndDots(t *testing.T) {
	actual := []string{"NS1.NSSTATIC.ORG.", "ns2.nsstatic.org"}
	expected := []string{"ns1.nsstatic.org", "ns2.nsstatic.org."}

	if !containsAllNSHosts(actual, expected) {
		t.Fatal("containsAllNSHosts() should match normalized host lists")
	}
}

func TestContainsAllNSHostsDetectsMissingHosts(t *testing.T) {
	actual := []string{"ns1.nsstatic.org"}
	expected := []string{"ns1.nsstatic.org", "ns2.nsstatic.org"}

	if containsAllNSHosts(actual, expected) {
		t.Fatal("containsAllNSHosts() should fail when a configured NS host is missing")
	}
}
