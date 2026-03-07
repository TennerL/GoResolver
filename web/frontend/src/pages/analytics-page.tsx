import { Badge, Button, Container, Grid, Group, Modal, NativeSelect, Paper, SimpleGrid, Stack, Text, TextInput, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconAdjustmentsHorizontal, IconMapPin, IconRefresh, IconSearch } from "@tabler/icons-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { ChartCard, MapCard, PageHeader, StatusBadge, buildLineOption, buildStatusOption, buildTopUrisOption, fetchJSON } from "../common";

const defaultFilters = {
  range: "60",
  from: "",
  to: "",
  host: "",
  filter: "",
  method: "",
  status: "",
  statusClass: "",
  uriContains: "",
  ipContains: ""
};

const emptyAnalytics = {
  requests_over_time: { labels: [], values: [] },
  status_codes: {},
  top_uris: { labels: [], status_codes: {} },
  avg_request_time: { labels: [], values: [] },
  methods: {},
  summary: { total_requests: 0, unique_ips: 0, error_requests: 0, error_rate: 0, avg_request_time_ms: 0, transferred_bytes: 0 },
  cache_only: false
};

const quickRangeOptions = [
  { value: "15", label: "Last 15 minutes" },
  { value: "60", label: "Last 60 minutes" },
  { value: "360", label: "Last 6 hours" },
  { value: "1440", label: "Last 24 hours" },
  { value: "10080", label: "Last 7 days" }
];

const refreshIntervalOptions = [
  { value: "0", label: "Off" },
  { value: "5000", label: "5 seconds" },
  { value: "15000", label: "15 seconds" },
  { value: "30000", label: "30 seconds" },
  { value: "60000", label: "60 seconds" }
];

const verdictOptions = [
  { value: "", label: "All" },
  { value: "genuine", label: "Genuine" },
  { value: "suspicious", label: "Suspicious" },
  { value: "unknown", label: "Unknown" }
];

const methodOptions = [
  { value: "", label: "All" },
  { value: "GET", label: "GET" },
  { value: "POST", label: "POST" },
  { value: "HEAD", label: "HEAD" },
  { value: "PUT", label: "PUT" },
  { value: "PATCH", label: "PATCH" },
  { value: "DELETE", label: "DELETE" },
  { value: "OPTIONS", label: "OPTIONS" }
];

const statusClassOptions = [
  { value: "", label: "All" },
  { value: "2xx", label: "2xx Success" },
  { value: "3xx", label: "3xx Redirect" },
  { value: "4xx", label: "4xx Client Error" },
  { value: "5xx", label: "5xx Server Error" }
];

function formatDateTime(value) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return value;
  return parsed.toLocaleString();
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;
  let size = value;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size >= 10 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`;
}

function formatLatency(ms) {
  const value = Number(ms || 0);
  if (!Number.isFinite(value) || value <= 0) return "0 ms";
  return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value.toFixed(0)} ms`;
}

function toAPIQueryDateTime(value) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return value;
  return parsed.toISOString();
}

function hasCustomFilters(filters) {
  return filters.range !== defaultFilters.range
    || filters.from !== ""
    || filters.to !== ""
    || filters.host !== ""
    || filters.filter !== ""
    || filters.method !== ""
    || filters.status !== ""
    || filters.statusClass !== ""
    || filters.uriContains.trim() !== ""
    || filters.ipContains.trim() !== "";
}

function buildAnalyticsQuery(filters) {
  const params = new URLSearchParams();
  if (filters.range) params.set("range", filters.range);
  if (filters.from) params.set("from", toAPIQueryDateTime(filters.from));
  if (filters.to) params.set("to", toAPIQueryDateTime(filters.to));
  if (filters.host) params.set("host", filters.host);
  if (filters.filter) params.set("filter", filters.filter);
  if (filters.method) params.set("method", filters.method);
  if (filters.status) params.set("status", filters.status);
  if (filters.statusClass) params.set("status_class", filters.statusClass);
  if (filters.uriContains.trim()) params.set("uri_contains", filters.uriContains.trim());
  if (filters.ipContains.trim()) params.set("ip_contains", filters.ipContains.trim());
  if (hasCustomFilters(filters)) params.set("cache_only", "1");
  return params.toString();
}

function buildAnalyticsUrl(filters) {
  return `/api/analytics?${buildAnalyticsQuery(filters)}`;
}

function buildIPsUrl(filters) {
  return `/api/analytics/ips?${buildAnalyticsQuery(filters)}`;
}

function buildGeoUrl(filters) {
  return `/api/analytics/ip-geo?${buildAnalyticsQuery(filters)}`;
}

function summarizeFilters(filters) {
  const summary = [];
  if (filters.from) summary.push(`From ${formatDateTime(filters.from)}`);
  if (filters.to) summary.push(`To ${formatDateTime(filters.to)}`);
  if (!filters.from && !filters.to && filters.range) {
    const rangeLabel = quickRangeOptions.find((option) => option.value === filters.range)?.label;
    if (rangeLabel) summary.push(rangeLabel);
  }
  if (filters.host) summary.push(`Host ${filters.host}`);
  if (filters.method) summary.push(`Method ${filters.method}`);
  if (filters.status) summary.push(`Status ${filters.status}`);
  if (filters.statusClass) summary.push(`Class ${filters.statusClass}`);
  if (filters.filter) summary.push(`Verdict ${filters.filter}`);
  if (filters.uriContains.trim()) summary.push(`URI contains "${filters.uriContains.trim()}"`);
  if (filters.ipContains.trim()) summary.push(`IP contains "${filters.ipContains.trim()}"`);
  return summary;
}

function SummaryCard({ label, value, hint }) {
  return (
    <Paper radius="xl" p="lg" className="soft-panel">
      <Stack gap={4}>
        <Text size="sm" c="dimmed">{label}</Text>
        <Title order={3}>{value}</Title>
        <Text size="sm" c="dimmed">{hint}</Text>
      </Stack>
    </Paper>
  );
}

export function AnalyticsPageView() {
  const [filterOpened, filterModal] = useDisclosure(false);
  const [draftFilters, setDraftFilters] = useState(defaultFilters);
  const [filters, setFilters] = useState(defaultFilters);
  const [refreshInterval, setRefreshInterval] = useState("15000");
  const [reloadToken, setReloadToken] = useState(0);
  const [hosts, setHosts] = useState([]);
  const [analytics, setAnalytics] = useState(emptyAnalytics);
  const [ips, setIps] = useState([]);
  const [points, setPoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastLoadedAt, setLastLoadedAt] = useState("");
  const inFlightRef = useRef(false);

  const filterBadges = useMemo(() => summarizeFilters(filters), [filters]);
  const cacheOnly = !!analytics?.cache_only;

  const updateDraft = (key, value) => {
    setDraftFilters((current) => ({ ...current, [key]: value }));
  };

  const applyFilters = () => {
    const nextFilters = {
      ...draftFilters,
      status: draftFilters.status.replace(/[^\d]/g, "").slice(0, 3)
    };
    const changed = JSON.stringify(filters) !== JSON.stringify(nextFilters);
    setFilters(nextFilters);
    filterModal.close();
    if (!changed) {
      setReloadToken((value) => value + 1);
    }
  };

  const resetFilters = () => {
    setDraftFilters(defaultFilters);
    setFilters(defaultFilters);
    setReloadToken((value) => value + 1);
    filterModal.close();
  };

  useEffect(() => {
    let cancelled = false;

    async function loadHosts() {
      try {
        const nextHosts = await fetchJSON("/api/analytics/hosts");
        if (!cancelled) {
          setHosts(Array.isArray(nextHosts) ? nextHosts : []);
        }
      } catch (error) {
        if (!cancelled) {
          window.alert(error instanceof Error ? error.message : "Failed to load hosts");
        }
      }
    }

    void loadHosts();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();

    async function loadEverything() {
      if (inFlightRef.current) return;
      inFlightRef.current = true;
      setLoading(true);
      try {
        const [nextAnalytics, nextIps, nextPoints] = await Promise.all([
          fetchJSON(buildAnalyticsUrl(filters), { signal: controller.signal }),
          fetchJSON(buildIPsUrl(filters), { signal: controller.signal }),
          fetchJSON(buildGeoUrl(filters), { signal: controller.signal })
        ]);

        if (cancelled) return;

        setAnalytics(nextAnalytics && typeof nextAnalytics === "object" ? { ...emptyAnalytics, ...nextAnalytics } : emptyAnalytics);
        setIps(Array.isArray(nextIps) ? nextIps : []);
        setPoints(Array.isArray(nextPoints) ? nextPoints : []);
        setLastLoadedAt(new Date().toISOString());
      } catch (error) {
        if (controller.signal.aborted || cancelled) return;
        window.alert(error instanceof Error ? error.message : "Failed to load analytics");
      } finally {
        inFlightRef.current = false;
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadEverything();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [filters, reloadToken]);

  useEffect(() => {
    const intervalMs = Number(refreshInterval);
    if (!intervalMs) return undefined;

    const timer = window.setInterval(() => {
      if (!inFlightRef.current) {
        setReloadToken((value) => value + 1);
      }
    }, intervalMs);

    return () => window.clearInterval(timer);
  }, [refreshInterval]);

  return (
    <Container fluid className="analytics-surface">
      <PageHeader
        title="Analytics"
        description="Inspect traffic with tighter filters, cached reputation lookups for drill-down views, and a clearer overview of request quality."
        actions={
          <Group gap="sm">
            <NativeSelect data={refreshIntervalOptions} value={refreshInterval} onChange={(event) => setRefreshInterval(event.currentTarget.value)} />
            <Button variant="light" leftSection={<IconRefresh size={16} />} onClick={() => setReloadToken((value) => value + 1)} loading={loading}>
              Refresh
            </Button>
            <Button leftSection={<IconAdjustmentsHorizontal size={16} />} onClick={filterModal.open}>
              Filters{filterBadges.length ? ` (${filterBadges.length})` : ""}
            </Button>
          </Group>
        }
      />

      <Paper radius="xl" p="lg" className="soft-panel" mb="lg">
        <Stack gap="sm">
          <Group gap="sm">
            {filterBadges.length === 0 ? <Badge variant="light" color="gray">Default slice</Badge> : filterBadges.map((item) => <Badge key={item} variant="light" color="gray">{item}</Badge>)}
            {cacheOnly ? <Badge variant="light" color="orange">Filtered view: cached reputation only</Badge> : <Badge variant="light" color="teal">Live reputation allowed</Badge>}
          </Group>
          <Text size="sm" c="dimmed">
            {lastLoadedAt ? `Last updated ${formatDateTime(lastLoadedAt)}.` : "Loading current analytics slice."} Filtered views skip live AbuseIPDB checks and reuse cached data only.
          </Text>
        </Stack>
      </Paper>

      <SimpleGrid cols={{ base: 1, sm: 2, xl: 5 }} spacing="lg" mb="lg">
        <SummaryCard label="Requests" value={analytics.summary.total_requests?.toLocaleString?.() || "0"} hint="Total matching log entries" />
        <SummaryCard label="Unique IPs" value={analytics.summary.unique_ips?.toLocaleString?.() || "0"} hint="Distinct client IPs after XFF extraction" />
        <SummaryCard label="Errors" value={`${Number(analytics.summary.error_rate || 0).toFixed(1)}%`} hint={`${analytics.summary.error_requests || 0} requests with 4xx/5xx`} />
        <SummaryCard label="Average Request Time" value={formatLatency(analytics.summary.avg_request_time_ms)} hint="Mean request duration across matching entries" />
        <SummaryCard label="Transferred" value={formatBytes(analytics.summary.transferred_bytes)} hint="Response bytes served for the current slice" />
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, xl: 2 }} spacing="lg">
        <ChartCard title="Requests over time" option={buildLineOption(analytics.requests_over_time, "#ff6d4d")} />
        <ChartCard title="Status codes" option={buildStatusOption(analytics.status_codes)} />
        <ChartCard title="Top URIs" option={buildTopUrisOption(analytics.top_uris)} />
        <ChartCard title="Average request time" option={buildLineOption(analytics.avg_request_time, "#52a8ff")} />
        <ChartCard title="Request methods" option={buildStatusOption(analytics.methods)} />
      </SimpleGrid>

      <Grid mt="lg" gutter="lg">
        <Grid.Col span={{ base: 12, xl: 5 }}>
          <Paper radius="xl" p="lg" className="soft-panel">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 16 }}>
              <div>
                <Title order={4}>IP Reputation</Title>
                <Text size="sm" c="dimmed">
                  Unique client IPs for the selected slice. Cached-only mode is used whenever filters are active.
                </Text>
              </div>
              <Badge variant="light">{ips.length}</Badge>
            </div>
            <Stack gap="sm">
              {ips.length === 0 ? (
                <Text c="dimmed">No IPs found for the current filter.</Text>
              ) : ips.map((entry) => (
                <Paper key={entry.ip} radius="lg" p="md" className="shell-panel">
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "start" }}>
                    <div>
                      <code className="code-chip">{entry.ip}</code>
                      <Text size="sm" c="dimmed">Score: {entry.score ?? 0} · Reports: {entry.reports ?? 0}</Text>
                      <Text size="sm" c="dimmed">Host: {entry.hostnames?.length ? entry.hostnames.join(", ") : "-"}</Text>
                      <Text size="sm" c="dimmed">ISP: {entry.isp || "-"}</Text>
                      <Text size="sm" c="dimmed">Checked: {entry.checked_at ? formatDateTime(entry.checked_at) : cacheOnly ? "Cache miss" : "-"}</Text>
                    </div>
                    <StatusBadge status={entry.verdict || "unknown"} />
                  </div>
                </Paper>
              ))}
            </Stack>
          </Paper>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 7 }}>
          <Paper radius="xl" p="lg" className="soft-panel">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 16 }}>
              <div>
                <Title order={4}>IP Locations</Title>
                <Text size="sm" c="dimmed">Map markers are built from cached geolocation for the current slice.</Text>
              </div>
              <Badge variant="light" leftSection={<IconMapPin size={12} />}>{points.length}</Badge>
            </div>
            <MapCard points={points} />
          </Paper>
        </Grid.Col>
      </Grid>

      <Modal opened={filterOpened} onClose={filterModal.close} title="Analytics Filters" size="lg" centered>
        <Stack gap="md">
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <NativeSelect
              label="Quick time range"
              description="Used directly, or as a fallback window when only one boundary is set."
              data={quickRangeOptions}
              value={draftFilters.range}
              onChange={(event) => updateDraft("range", event.currentTarget.value)}
            />
            <NativeSelect
              label="Host"
              data={[{ value: "", label: "All hosts" }, ...hosts.map((host) => ({ value: host, label: host }))]}
              value={draftFilters.host}
              onChange={(event) => updateDraft("host", event.currentTarget.value)}
            />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <TextInput
              label="From"
              description="Local time"
              type="datetime-local"
              value={draftFilters.from}
              onChange={(event) => updateDraft("from", event.currentTarget.value)}
            />
            <TextInput
              label="To"
              description="Local time"
              type="datetime-local"
              value={draftFilters.to}
              onChange={(event) => updateDraft("to", event.currentTarget.value)}
            />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 3 }}>
            <NativeSelect label="Reputation verdict" data={verdictOptions} value={draftFilters.filter} onChange={(event) => updateDraft("filter", event.currentTarget.value)} />
            <NativeSelect label="HTTP method" data={methodOptions} value={draftFilters.method} onChange={(event) => updateDraft("method", event.currentTarget.value)} />
            <NativeSelect label="Status class" data={statusClassOptions} value={draftFilters.statusClass} onChange={(event) => updateDraft("statusClass", event.currentTarget.value)} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 3 }}>
            <TextInput
              label="Exact status"
              placeholder="404"
              value={draftFilters.status}
              onChange={(event) => updateDraft("status", event.currentTarget.value)}
            />
            <TextInput
              label="URI contains"
              placeholder="/wp-login"
              value={draftFilters.uriContains}
              onChange={(event) => updateDraft("uriContains", event.currentTarget.value)}
              leftSection={<IconSearch size={16} />}
            />
            <TextInput
              label="IP contains"
              placeholder="87.106."
              value={draftFilters.ipContains}
              onChange={(event) => updateDraft("ipContains", event.currentTarget.value)}
            />
          </SimpleGrid>
          <Text size="sm" c="dimmed">
            Applying any custom filter switches IP reputation to cached-only mode to avoid repeated live AbuseIPDB checks while drilling down.
          </Text>
          <Group justify="space-between">
            <Button variant="subtle" color="gray" onClick={resetFilters}>Reset</Button>
            <Group gap="sm">
              <Button variant="light" color="gray" onClick={filterModal.close}>Cancel</Button>
              <Button leftSection={<IconAdjustmentsHorizontal size={16} />} onClick={applyFilters}>Apply Filters</Button>
            </Group>
          </Group>
        </Stack>
      </Modal>
    </Container>
  );
}
