package services

import (
	"testing"
	"time"
)

func TestCertificateRenewSchedule(t *testing.T) {
	expiresAt := time.Date(2026, time.April, 30, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, time.March, 31, 12, 0, 0, 0, time.UTC)

	if got := certificateRenewSchedule(expiresAt); !got.Equal(want) {
		t.Fatalf("certificateRenewSchedule(%s) = %s, want %s", expiresAt, got, want)
	}
}

func TestCertificateRenewScheduleZero(t *testing.T) {
	if got := certificateRenewSchedule(time.Time{}); !got.IsZero() {
		t.Fatalf("certificateRenewSchedule(zero) = %s, want zero", got)
	}
}
