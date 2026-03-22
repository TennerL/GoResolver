package services

import "testing"

func TestNormalizeAnalyticsIncidentWindowMinutesUsesDefault(t *testing.T) {
	if got := normalizeAnalyticsIncidentWindowMinutes(0, 30); got != 60 {
		t.Fatalf("normalizeAnalyticsIncidentWindowMinutes(0, 30) = %d, want 60", got)
	}
}

func TestNormalizeAnalyticsIncidentWindowMinutesCapsToRetention(t *testing.T) {
	if got := normalizeAnalyticsIncidentWindowMinutes(60*24*40, 30); got != 60*24*30 {
		t.Fatalf("normalizeAnalyticsIncidentWindowMinutes(...) = %d, want %d", got, 60*24*30)
	}
}
