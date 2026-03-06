import { Badge, Button, Container, Grid, NativeSelect, Paper, SimpleGrid, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconMapPin, IconRefresh } from "@tabler/icons-react";
import { useEffect, useRef, useState } from "react";
import { ChartCard, MapCard, PageHeader, StatusBadge, buildLineOption, buildStatusOption, buildTopUrisOption, fetchJSON } from "../common";

const emptyAnalytics = { requests_over_time: { labels: [], values: [] }, status_codes: {}, top_uris: { labels: [], status_codes: {} }, avg_request_time: { labels: [], values: [] } };
const refreshIntervalOptions = [
  { value: "0", label: "Off" },
  { value: "5000", label: "5 seconds" },
  { value: "15000", label: "15 seconds" },
  { value: "30000", label: "30 seconds" },
  { value: "60000", label: "60 seconds" }
];

function buildAnalyticsUrl(filters) {
  return `/api/analytics?range=${encodeURIComponent(filters.range)}&host=${encodeURIComponent(filters.host)}`;
}

function buildIPsUrl(filters) {
  return `/api/analytics/ips?range=${encodeURIComponent(filters.range)}&host=${encodeURIComponent(filters.host)}&filter=${encodeURIComponent(filters.filter)}`;
}

function buildGeoUrl(filters) {
  return `/api/analytics/ip-geo?range=${encodeURIComponent(filters.range)}&host=${encodeURIComponent(filters.host)}`;
}

export function AnalyticsPageView() {
  const [draftRange, setDraftRange] = useState("60");
  const [draftHost, setDraftHost] = useState("");
  const [draftFilter, setDraftFilter] = useState("");
  const [filters, setFilters] = useState({ range: "60", host: "", filter: "" });
  const [refreshInterval, setRefreshInterval] = useState("15000");
  const [reloadToken, setReloadToken] = useState(0);
  const [hosts, setHosts] = useState([]);
  const [analytics, setAnalytics] = useState(emptyAnalytics);
  const [ips, setIps] = useState([]);
  const [points, setPoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const inFlightRef = useRef(false);
  const applyFilters = () => {
    const nextFilters = { range: draftRange || "60", host: draftHost, filter: draftFilter };
    if (filters.range === nextFilters.range && filters.host === nextFilters.host && filters.filter === nextFilters.filter) {
      setReloadToken((value) => value + 1);
      return;
    }
    setFilters(nextFilters);
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

        setAnalytics(nextAnalytics && typeof nextAnalytics === "object" ? nextAnalytics : emptyAnalytics);
        setIps(Array.isArray(nextIps) ? nextIps : []);
        setPoints(Array.isArray(nextPoints) ? nextPoints : []);
      } catch (error) {
        if (controller.signal.aborted || cancelled) return;
        if (!cancelled) {
          window.alert(error instanceof Error ? error.message : "Failed to load analytics");
        }
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
      <PageHeader title="Analytics" description="Query the recent traffic window and inspect hosts, IP reputation, and geo spread." />
      <Paper radius="xl" p="lg" className="soft-panel" mb="lg">
        <SimpleGrid cols={{ base: 1, md: 2, xl: 5 }}>
          <TextInput label="Time range (minutes)" type="number" min="1" value={draftRange} onChange={(event) => setDraftRange(event.currentTarget.value)} />
          <NativeSelect label="Host" data={[{ value: "", label: "All" }, ...hosts.map((host) => ({ value: host, label: host }))]} value={draftHost} onChange={(event) => setDraftHost(event.currentTarget.value)} />
          <NativeSelect label="IP Filter" data={[{ value: "", label: "All" }, { value: "genuine", label: "Genuine" }, { value: "suspicious", label: "Suspicious" }, { value: "unknown", label: "Unknown" }]} value={draftFilter} onChange={(event) => setDraftFilter(event.currentTarget.value)} />
          <NativeSelect label="Auto refresh" data={refreshIntervalOptions} value={refreshInterval} onChange={(event) => setRefreshInterval(event.currentTarget.value)} />
          <div style={{ display: "flex", alignItems: "end" }}><Button leftSection={<IconRefresh size={16} />} onClick={applyFilters} loading={loading}>Apply</Button></div>
        </SimpleGrid>
      </Paper>
      <SimpleGrid cols={{ base: 1, xl: 2 }} spacing="lg">
        <ChartCard title="Requests over time" option={buildLineOption(analytics.requests_over_time, "#ff6d4d")} />
        <ChartCard title="Status codes" option={buildStatusOption(analytics.status_codes)} />
        <ChartCard title="Top URIs" option={buildTopUrisOption(analytics.top_uris)} />
        <ChartCard title="Average request time" option={buildLineOption(analytics.avg_request_time, "#52a8ff")} />
      </SimpleGrid>
      <Grid mt="lg" gutter="lg">
        <Grid.Col span={{ base: 12, xl: 5 }}>
          <Paper radius="xl" p="lg" className="soft-panel">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 16 }}><div><Title order={4}>IP Reputation</Title><Text size="sm" c="dimmed">Unique IPs extracted from recent traffic.</Text></div><Badge variant="light">{ips.length}</Badge></div>
            <Stack gap="sm">{ips.length === 0 ? <Text c="dimmed">No IPs found for the current filter.</Text> : ips.map((entry) => <Paper key={entry.ip} radius="lg" p="md" className="shell-panel"><div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "start" }}><div><code className="code-chip">{entry.ip}</code><Text size="sm" c="dimmed">Score: {entry.score ?? 0} · Reports: {entry.reports ?? 0}</Text><Text size="sm" c="dimmed">Host: {entry.hostnames?.length ? entry.hostnames.join(", ") : "-"}</Text><Text size="sm" c="dimmed">ISP: {entry.isp || "-"}</Text></div><StatusBadge status={entry.verdict || "unknown"} /></div></Paper>)}</Stack>
          </Paper>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 7 }}>
          <Paper radius="xl" p="lg" className="soft-panel">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 16 }}><div><Title order={4}>IP Locations</Title><Text size="sm" c="dimmed">Cached geolocation for recent traffic sources.</Text></div><Badge variant="light" leftSection={<IconMapPin size={12} />}>{points.length}</Badge></div>
            <MapCard points={points} />
          </Paper>
        </Grid.Col>
      </Grid>
    </Container>
  );
}
