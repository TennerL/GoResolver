package services

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeAnalyticsFiltersDefaultsWindow(t *testing.T) {
	before := time.Now().UTC()
	filters := normalizeAnalyticsFilters(AnalyticsFilters{})
	after := time.Now().UTC()

	if filters.RangeMinutes != 60 {
		t.Fatalf("expected default range 60, got %d", filters.RangeMinutes)
	}
	if filters.From.IsZero() || filters.To.IsZero() {
		t.Fatal("expected default time window to be populated")
	}
	if filters.To.Before(filters.From) {
		t.Fatalf("expected non-negative window, got from=%v to=%v", filters.From, filters.To)
	}

	expectedLower := before.Add(-61 * time.Minute)
	expectedUpper := after.Add(-59 * time.Minute)
	if filters.From.Before(expectedLower) || filters.From.After(expectedUpper) {
		t.Fatalf("expected from near now-60m, got %v", filters.From)
	}
}

func TestNormalizeAnalyticsFiltersSwapsReversedWindow(t *testing.T) {
	from := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)

	filters := normalizeAnalyticsFilters(AnalyticsFilters{From: from, To: to})

	if !filters.From.Equal(to) || !filters.To.Equal(from) {
		t.Fatalf("expected reversed window to be swapped, got from=%v to=%v", filters.From, filters.To)
	}
}

func TestAnalyticsWhereClauseIncludesCustomFilters(t *testing.T) {
	filters := AnalyticsFilters{
		RangeMinutes: 15,
		Host:         "nihonsaba.net",
		Method:       "get",
		Status:       404,
		StatusClass:  "4xx",
		URIContains:  "/wp-login",
		IPContains:   "87.106.",
	}

	whereClause, args := analyticsWhereClause(filters)

	for _, snippet := range []string{
		"host = ?",
		"method = ?",
		"status = ?",
		"status BETWEEN ? AND ?",
		"uri LIKE ?",
		"(remote_addr LIKE ? OR x_forwarded_for LIKE ?)",
	} {
		if !strings.Contains(whereClause, snippet) {
			t.Fatalf("expected where clause to contain %q, got %q", snippet, whereClause)
		}
	}
	if len(args) != 10 {
		t.Fatalf("expected 10 query args, got %d", len(args))
	}
	if method, ok := args[3].(string); !ok || method != "GET" {
		t.Fatalf("expected uppercase method arg GET, got %#v", args[3])
	}
	if like, ok := args[7].(string); !ok || like != "%/wp-login%" {
		t.Fatalf("expected URI like arg, got %#v", args[7])
	}
}

func TestAnalyticsTimeLabelFormatScalesWithWindow(t *testing.T) {
	shortWindow := AnalyticsFilters{
		From: time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 7, 11, 0, 0, 0, time.UTC),
	}
	longWindow := AnalyticsFilters{
		From: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
	}

	if got := analyticsTimeLabelFormat(shortWindow); got != "%Y-%m-%d %H:%i" {
		t.Fatalf("expected minute granularity for short window, got %q", got)
	}
	if got := analyticsTimeLabelFormat(longWindow); got != "%Y-%m-%d" {
		t.Fatalf("expected daily granularity for long window, got %q", got)
	}
}
