package handlers

import (
	"net/http/httptest"
	"testing"
)

func TestParseAnalyticsFiltersParsesCustomQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/analytics?range=1440&host=nihonsaba.net&method=post&status=404&status_class=4xx&uri_contains=wp-login&ip_contains=87.106.&isp_contains=hetzner&filter=suspicious&from=2026-03-07T08:00&to=2026-03-07T09:00&include_internal_api=1", nil)

	filters := parseAnalyticsFilters(req)

	if filters.RangeMinutes != 1440 {
		t.Fatalf("expected range 1440, got %d", filters.RangeMinutes)
	}
	if filters.Host != "nihonsaba.net" {
		t.Fatalf("expected host filter, got %q", filters.Host)
	}
	if filters.Method != "post" {
		t.Fatalf("expected raw method to be preserved before normalization, got %q", filters.Method)
	}
	if filters.Status != 404 {
		t.Fatalf("expected status 404, got %d", filters.Status)
	}
	if filters.StatusClass != "4xx" {
		t.Fatalf("expected status class 4xx, got %q", filters.StatusClass)
	}
	if filters.URIContains != "wp-login" {
		t.Fatalf("expected URI substring, got %q", filters.URIContains)
	}
	if filters.IPContains != "87.106." {
		t.Fatalf("expected IP contains filter, got %q", filters.IPContains)
	}
	if filters.ISPContains != "hetzner" {
		t.Fatalf("expected ISP contains filter, got %q", filters.ISPContains)
	}
	if filters.Verdict != "suspicious" {
		t.Fatalf("expected verdict suspicious, got %q", filters.Verdict)
	}
	if !filters.IncludeInternalAPI {
		t.Fatal("expected include_internal_api to be enabled")
	}
	if filters.From.IsZero() || filters.To.IsZero() {
		t.Fatal("expected explicit from/to timestamps to be parsed")
	}
	if !filters.CacheOnly {
		t.Fatal("expected custom query to enable cache-only mode")
	}
}

func TestAnalyticsQueryUsesCacheOnlyDefaults(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/analytics?range=60", nil)

	if analyticsQueryUsesCacheOnly(req.URL.Query()) {
		t.Fatal("expected default range query to keep live lookups enabled")
	}

	filters := parseAnalyticsFilters(req)
	if filters.IncludeInternalAPI {
		t.Fatal("expected internal API routes to stay excluded by default")
	}
}

func TestAnalyticsQueryUsesCacheOnlyIgnoresInternalAPIToggle(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/analytics?range=60&include_internal_api=1", nil)

	if analyticsQueryUsesCacheOnly(req.URL.Query()) {
		t.Fatal("expected internal API toggle alone to keep live lookups enabled")
	}
}

func TestAnalyticsQueryUsesCacheOnlyForQuickSearch(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/analytics?range=60&q=hetzner", nil)

	if !analyticsQueryUsesCacheOnly(req.URL.Query()) {
		t.Fatal("expected quick search to enable cache-only mode")
	}
}
