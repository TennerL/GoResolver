package services

import (
	"GoResolver/internal/models"
	"testing"
)

func TestFail2BanClientIPExprUsesRemoteAddrByDefault(t *testing.T) {
	got := fail2BanClientIPExpr(models.Fail2BanPolicy{})
	if got != "TRIM(remote_addr)" {
		t.Fatalf("fail2BanClientIPExpr() = %q, want %q", got, "TRIM(remote_addr)")
	}
}

func TestFail2BanClientIPExprUsesXForwardedForWhenEnabled(t *testing.T) {
	got := fail2BanClientIPExpr(models.Fail2BanPolicy{UseXForwardedFor: true})
	if got != analyticsClientIPExpr() {
		t.Fatalf("fail2BanClientIPExpr() = %q, want analyticsClientIPExpr()", got)
	}
}

func TestFail2BanEffectiveHostsIgnoresHostFilterForGlobalBans(t *testing.T) {
	got := fail2BanEffectiveHosts(models.Fail2BanPolicy{BanGlobally: true}, []string{"example.com"})
	if got != nil {
		t.Fatalf("fail2BanEffectiveHosts() = %v, want nil", got)
	}
}

func TestFail2BanEffectiveHostsIgnoresHostFilterForSystemServer(t *testing.T) {
	got := fail2BanEffectiveHosts(models.Fail2BanPolicy{ServerID: "0"}, []string{"example.com"})
	if got != nil {
		t.Fatalf("fail2BanEffectiveHosts() = %v, want nil", got)
	}
}

func TestResolveManagedRuleDestinationIPUsesServerIPForManagedServer(t *testing.T) {
	svc := NewServerConfigurationService()
	got := svc.resolveManagedRuleDestinationIP("12", "10.8.0.15", firewallFamilyIPv4)
	if got != "10.8.0.15" {
		t.Fatalf("resolveManagedRuleDestinationIP() = %q, want %q", got, "10.8.0.15")
	}
}
