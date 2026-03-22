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
		ISPContains:  "hetzner",
	}

	whereClause, args := analyticsWhereClause(filters)

	for _, snippet := range []string{
		"host = ?",
		"method = ?",
		"status = ?",
		"status BETWEEN ? AND ?",
		"uri LIKE ?",
		"remote_addr LIKE ?",
		"geo.isp LIKE ?",
		"uri NOT LIKE ?",
	} {
		if !strings.Contains(whereClause, snippet) {
			t.Fatalf("expected where clause to contain %q, got %q", snippet, whereClause)
		}
	}
	if len(args) != 11 {
		t.Fatalf("expected 11 query args, got %d", len(args))
	}
	if method, ok := args[3].(string); !ok || method != "GET" {
		t.Fatalf("expected uppercase method arg GET, got %#v", args[3])
	}
	if like, ok := args[7].(string); !ok || like != "%/wp-login%" {
		t.Fatalf("expected URI like arg, got %#v", args[7])
	}
	if ipLike, ok := args[8].(string); !ok || ipLike != "%87.106.%" {
		t.Fatalf("expected IP like arg, got %#v", args[8])
	}
	if ispLike, ok := args[9].(string); !ok || ispLike != "%hetzner%" {
		t.Fatalf("expected ISP like arg, got %#v", args[9])
	}
	if internalAPIPattern, ok := args[10].(string); !ok || internalAPIPattern != "/api/%" {
		t.Fatalf("expected internal API exclusion arg, got %#v", args[10])
	}
}

func TestAnalyticsWhereClauseCanIncludeInternalAPI(t *testing.T) {
	whereClause, _ := analyticsWhereClause(AnalyticsFilters{IncludeInternalAPI: true})

	if strings.Contains(whereClause, "uri NOT LIKE ?") {
		t.Fatalf("expected internal API exclusion to be disabled, got %q", whereClause)
	}
}

func TestAnalyticsSQLPlaceholders(t *testing.T) {
	if got := analyticsSQLPlaceholders(0); got != "" {
		t.Fatalf("expected empty placeholder list, got %q", got)
	}
	if got := analyticsSQLPlaceholders(3); got != "?, ?, ?" {
		t.Fatalf("expected three placeholders, got %q", got)
	}
}

func TestAnalyticsSnapshotCacheKeyIgnoresCacheOnlyFlag(t *testing.T) {
	from := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 7, 11, 0, 0, 0, time.UTC)

	withLiveLookup := AnalyticsFilters{
		RangeMinutes:       60,
		Host:               "nihonsaba.net",
		Method:             "GET",
		From:               from,
		To:                 to,
		CacheOnly:          false,
		IncludeInternalAPI: false,
	}
	withCacheOnly := withLiveLookup
	withCacheOnly.CacheOnly = true

	if analyticsSnapshotCacheKey(withLiveLookup) != analyticsSnapshotCacheKey(withCacheOnly) {
		t.Fatal("expected snapshot cache key to ignore cache_only state for identical log filters")
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

func TestIsPublicRoutableIP(t *testing.T) {
	if !isPublicRoutableIP("8.8.8.8") {
		t.Fatal("expected public IPv4 address to be routable")
	}
	if !isPublicRoutableIP("2606:4700:4700::1111") {
		t.Fatal("expected public IPv6 address to be routable")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.20", "169.254.0.1", "::1", "fc00::1", ""} {
		if isPublicRoutableIP(ip) {
			t.Fatalf("expected %q to be treated as non-public", ip)
		}
	}
}
