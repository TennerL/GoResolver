package services

import (
	"testing"
	"time"
)

func TestFormatObservedUptime(t *testing.T) {
	testCases := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{name: "negative", duration: -time.Minute, want: "<1m"},
		{name: "sub minute", duration: 20 * time.Second, want: "<1m"},
		{name: "rounded minute", duration: 89 * time.Second, want: "1m"},
		{name: "hours and minutes", duration: 2*time.Hour + 15*time.Minute, want: "2h 15m"},
		{name: "days and hours", duration: 49*time.Hour + 10*time.Minute, want: "2d 1h"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatObservedUptime(tc.duration); got != tc.want {
				t.Fatalf("formatObservedUptime(%s) = %q, want %q", tc.duration, got, tc.want)
			}
		})
	}
}
