package services

import (
	"GoResolver/internal/models"
	"slices"
	"testing"
)

func TestFirewallFamilyForValue(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "62.214.0.0/16", want: firewallFamilyIPv4},
		{value: "2001:db8::1", want: firewallFamilyIPv6},
		{value: "2001:db8::/64", want: firewallFamilyIPv6},
		{value: "not-an-ip", want: ""},
	}

	for _, tt := range tests {
		if got := firewallFamilyForValue(tt.value); got != tt.want {
			t.Fatalf("firewallFamilyForValue(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestInferFirewallFamilyRejectsMixedValues(t *testing.T) {
	_, err := inferFirewallFamily(models.IPTablesRuleSpec{
		SourceIP: "62.214.0.1",
		DestIP:   "2001:db8::1",
	})
	if err == nil {
		t.Fatal("expected mixed-family rule to fail")
	}
}

func TestBuildFirewallRuleArgsUsesIPv6ConnlimitMask(t *testing.T) {
	connLimit := 12
	args := buildFirewallRuleArgs(models.IPTablesRuleSpec{
		Chain:     "INPUT",
		Action:    "append",
		Protocol:  "tcp",
		DestPort:  443,
		ConnLimit: &connLimit,
		Target:    "DROP",
	}, firewallFamilyIPv6)

	maskIndex := slices.Index(args, "--connlimit-mask")
	if maskIndex == -1 || maskIndex+1 >= len(args) {
		t.Fatalf("connlimit mask missing from args: %v", args)
	}
	if args[maskIndex+1] != "128" {
		t.Fatalf("expected IPv6 connlimit mask 128, got %q", args[maskIndex+1])
	}
}
