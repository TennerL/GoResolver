package logging

import (
	"testing"
	"time"
)

func TestMaybeSyncAnalyticsIncidentsRateLimitsExecution(t *testing.T) {
	originalLastRun := lastIncidentSyncRun
	originalSyncFn := analyticsIncidentSyncFn
	t.Cleanup(func() {
		lastIncidentSyncRun = originalLastRun
		analyticsIncidentSyncFn = originalSyncFn
	})

	callCount := 0
	lastIncidentSyncRun = time.Time{}
	analyticsIncidentSyncFn = func() {
		callCount++
	}

	maybeSyncAnalyticsIncidents()
	maybeSyncAnalyticsIncidents()

	if callCount != 1 {
		t.Fatalf("expected sync to run once within the rate limit window, got %d", callCount)
	}

	lastIncidentSyncRun = time.Now().UTC().Add(-analyticsIncidentSyncEvery)
	maybeSyncAnalyticsIncidents()

	if callCount != 2 {
		t.Fatalf("expected sync to run again after the rate limit window, got %d", callCount)
	}
}
