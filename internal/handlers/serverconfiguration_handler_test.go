package handlers

import (
	"testing"

	"GoResolver/internal/models"
)

func TestFilterRulesForServerDoesNotLeakGeneralRulesToManagedServers(t *testing.T) {
	rules := []models.IPTablesRule{
		{Extra: "GoResolver:Allow:admin"},
		{Extra: "GoResolver:DDoS:12:limit"},
		{Extra: "GoResolver:DDoS:13:limit"},
		{Destination: "10.8.0.12"},
	}

	got := FilterRulesForServer(rules, "12", "10.8.0.12")
	if len(got) != 2 || got[0].Extra != "GoResolver:DDoS:12:limit" || got[1].Destination != "10.8.0.12" {
		t.Fatalf("unexpected rules for server 12: %#v", got)
	}
}

func TestFilterRulesForSystemServerIncludesGeneralRules(t *testing.T) {
	rules := []models.IPTablesRule{{Extra: "GoResolver:Allow:admin"}}
	if got := FilterRulesForServer(rules, "0", "127.0.0.1"); len(got) != 1 {
		t.Fatalf("expected general rule on system server, got %#v", got)
	}
}
