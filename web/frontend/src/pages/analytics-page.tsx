import { Accordion, Badge, Button, Checkbox, Code, Container, Grid, Group, Modal, NativeSelect, Pagination, Paper, SimpleGrid, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconAdjustmentsHorizontal, IconBell, IconMapPin, IconRefresh, IconSearch, IconTrash } from "@tabler/icons-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { ChartCard, MapCard, PageHeader, StatusBadge, buildLineOption, buildRankingOption, buildStatusOption, buildTopUrisOption, fetchJSON } from "../common";

const defaultFilters = {
  range: "60",
  from: "",
  to: "",
  host: "",
  q: "",
  filter: "",
  method: "",
  status: "",
  statusClass: "",
  uriContains: "",
  ipContains: "",
  ispContains: "",
  excludeInternalAPI: true
};

const emptyAnalytics = {
  requests_over_time: { labels: [], values: [] },
  status_codes: {},
  top_uris: { labels: [], status_codes: {} },
  avg_request_time: { labels: [], values: [] },
  methods: {},
  top_ips: { labels: [], values: [], urls: [] },
  summary: { total_requests: 0, unique_ips: 0, error_requests: 0, error_rate: 0, avg_request_time_ms: 0, transferred_bytes: 0 },
  cache_only: false
};

const emptyObservability = {
  alerts: [],
  retention_days: 30
};

const emptyLogSearch = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0
};

const logPageSize = 50;

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
    || filters.q.trim() !== ""
    || filters.filter !== ""
    || filters.method !== ""
    || filters.status !== ""
    || filters.statusClass !== ""
    || filters.uriContains.trim() !== ""
    || filters.ipContains.trim() !== ""
    || filters.ispContains.trim() !== "";
}

function buildAnalyticsQuery(filters) {
  const params = new URLSearchParams();
  if (filters.range) params.set("range", filters.range);
  if (filters.from) params.set("from", toAPIQueryDateTime(filters.from));
  if (filters.to) params.set("to", toAPIQueryDateTime(filters.to));
  if (filters.host) params.set("host", filters.host);
  if (filters.q.trim()) params.set("q", filters.q.trim());
  if (filters.filter) params.set("filter", filters.filter);
  if (filters.method) params.set("method", filters.method);
  if (filters.status) params.set("status", filters.status);
  if (filters.statusClass) params.set("status_class", filters.statusClass);
  if (filters.uriContains.trim()) params.set("uri_contains", filters.uriContains.trim());
  if (filters.ipContains.trim()) params.set("ip_contains", filters.ipContains.trim());
  if (filters.ispContains.trim()) params.set("isp_contains", filters.ispContains.trim());
  if (!filters.excludeInternalAPI) params.set("include_internal_api", "1");
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

function buildAlertsUrl(filters) {
  return `/api/analytics/alerts?${buildAnalyticsQuery(filters)}`;
}

function buildIncidentsUrl() {
  return "/api/analytics/incidents";
}

function buildLogsUrl(filters, limit = 50, offset = 0) {
  const params = new URLSearchParams(buildAnalyticsQuery(filters));
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  return `/api/analytics/logs?${params.toString()}`;
}

function buildIPProfileUrl(ip, filters) {
  const params = new URLSearchParams(buildAnalyticsQuery(filters));
  params.set("ip", ip);
  return `/api/analytics/ip-profile?${params.toString()}`;
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
  if (filters.q.trim()) summary.push(`Search "${filters.q.trim()}"`);
  if (filters.method) summary.push(`Method ${filters.method}`);
  if (filters.status) summary.push(`Status ${filters.status}`);
  if (filters.statusClass) summary.push(`Class ${filters.statusClass}`);
  if (filters.filter) summary.push(`Verdict ${filters.filter}`);
  if (filters.uriContains.trim()) summary.push(`URI contains "${filters.uriContains.trim()}"`);
  if (filters.ipContains.trim()) summary.push(`IP contains "${filters.ipContains.trim()}"`);
  if (filters.ispContains.trim()) summary.push(`ISP contains "${filters.ispContains.trim()}"`);
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

function CountList({ title, items }) {
  return (
    <Paper radius="xl" p="lg" className="soft-panel">
      <Stack gap="sm">
        <Title order={4}>{title}</Title>
        {items?.length
          ? items.map((item) => (
            <Group key={`${title}-${item.label}`} justify="space-between">
              <Text size="sm">{item.label}</Text>
              <Badge variant="light">{item.value}</Badge>
            </Group>
          ))
          : <Text size="sm" c="dimmed">No data for this IP in the current slice.</Text>}
      </Stack>
    </Paper>
  );
}

export function AnalyticsPageView() {
  const [filterOpened, filterModal] = useDisclosure(false);
  const [profileOpened, profileModal] = useDisclosure(false);
  const [notificationsOpened, notificationsModal] = useDisclosure(false);
  const [draftFilters, setDraftFilters] = useState(defaultFilters);
  const [filters, setFilters] = useState(defaultFilters);
  const [quickSearch, setQuickSearch] = useState("");
  const [refreshInterval, setRefreshInterval] = useState("15000");
  const [reloadToken, setReloadToken] = useState(0);
  const [hosts, setHosts] = useState([]);
  const [analytics, setAnalytics] = useState(emptyAnalytics);
  const [observability, setObservability] = useState(emptyObservability);
  const [incidents, setIncidents] = useState([]);
  const [ips, setIps] = useState([]);
  const [points, setPoints] = useState([]);
  const [logs, setLogs] = useState(emptyLogSearch);
  const [logPage, setLogPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [lastLoadedAt, setLastLoadedAt] = useState("");
  const [profileLoading, setProfileLoading] = useState(false);
  const [activeProfile, setActiveProfile] = useState(null);
  const inFlightRef = useRef(false);

  const filterBadges = useMemo(() => summarizeFilters(filters), [filters]);
  const cacheOnly = !!analytics?.cache_only;
  const activeIncidents = useMemo(
    () => (incidents || []).filter((incident) => incident.status === "open"),
    [incidents]
  );
  const incidentHistory = useMemo(
    () => (incidents || []).filter((incident) => incident.status !== "open"),
    [incidents]
  );

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
    setQuickSearch("");
    setReloadToken((value) => value + 1);
    filterModal.close();
  };

  const openIPProfile = async (ip) => {
    setProfileLoading(true);
    profileModal.open();
    try {
      const profile = await fetchJSON(buildIPProfileUrl(ip, filters));
      setActiveProfile(profile);
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Failed to load IP profile");
      profileModal.close();
    } finally {
      setProfileLoading(false);
    }
  };

  const dismissIncident = async (incident) => {
    if (!incident?.id) return;
    if (!window.confirm(`Dismiss incident "${incident.title}" and move it to history?`)) return;
    try {
      await fetchJSON(`/api/analytics/incidents/${incident.id}/dismiss`, { method: "POST" });
      setReloadToken((value) => value + 1);
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Failed to dismiss incident");
    }
  };

  const deleteHistoryIncident = async (incident) => {
    if (!incident?.id) return;
    if (!window.confirm(`Delete incident history entry "${incident.title}"?`)) return;
    try {
      await fetchJSON(`/api/analytics/incidents/${incident.id}`, { method: "DELETE" });
      setReloadToken((value) => value + 1);
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Failed to delete incident history entry");
    }
  };

  useEffect(() => {
    setQuickSearch(filters.q);
    setLogPage(1);
  }, [filters]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setFilters((current) => current.q === quickSearch ? current : { ...current, q: quickSearch });
      setDraftFilters((current) => current.q === quickSearch ? current : { ...current, q: quickSearch });
    }, 250);
    return () => window.clearTimeout(timer);
  }, [quickSearch]);

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
      inFlightRef.current = true;
      setLoading(true);
      try {
        const [nextAnalytics, nextIps, nextPoints, nextObservability, nextIncidents, nextLogs] = await Promise.all([
          fetchJSON(buildAnalyticsUrl(filters), { signal: controller.signal }),
          fetchJSON(buildIPsUrl(filters), { signal: controller.signal }),
          fetchJSON(buildGeoUrl(filters), { signal: controller.signal }),
          fetchJSON(buildAlertsUrl(filters), { signal: controller.signal }),
          fetchJSON(buildIncidentsUrl(), { signal: controller.signal }),
          fetchJSON(buildLogsUrl(filters, logPageSize, (logPage - 1) * logPageSize), { signal: controller.signal })
        ]);

        if (cancelled) return;

        setAnalytics(nextAnalytics && typeof nextAnalytics === "object" ? { ...emptyAnalytics, ...nextAnalytics } : emptyAnalytics);
        setIps(Array.isArray(nextIps) ? nextIps : []);
        setPoints(Array.isArray(nextPoints) ? nextPoints : []);
        setObservability(nextObservability && typeof nextObservability === "object" ? { ...emptyObservability, ...nextObservability } : emptyObservability);
        setIncidents(Array.isArray(nextIncidents) ? nextIncidents : []);
        setLogs(nextLogs && typeof nextLogs === "object" ? { ...emptyLogSearch, ...nextLogs } : emptyLogSearch);
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
  }, [filters, logPage, reloadToken]);

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
        description="Alerts, searchable logs, longer retention controls, and IP drill-downs for incident handling."
        actions={
          <Group gap="sm">
            <Button variant="subtle" color="gray" px="sm" onClick={notificationsModal.open} aria-label={`Open notification center (${activeIncidents.length} open)`}>
              <Group gap={6} wrap="nowrap">
                <IconBell size={18} />
                {activeIncidents.length ? <Badge color="red" variant="filled" size="sm" circle>{activeIncidents.length}</Badge> : null}
              </Group>
            </Button>
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
            {filters.excludeInternalAPI ? <Badge variant="light" color="teal">Internal API excluded</Badge> : <Badge variant="light" color="orange">Internal API included</Badge>}
            {cacheOnly ? <Badge variant="light" color="orange">Filtered view: cached reputation only</Badge> : <Badge variant="light" color="teal">Live reputation allowed</Badge>}
            <Badge variant="light" color="blue">Retention {observability.retention_days} days</Badge>
          </Group>
          <Text size="sm" c="dimmed">
            {lastLoadedAt ? `Last updated ${formatDateTime(lastLoadedAt)}.` : "Loading current analytics slice."} Use the quick search for IPs, ISPs, hosts, or paths, then open any IP directly from the log table.
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
        <ChartCard title="Top IP addresses" option={buildRankingOption(analytics.top_ips, "#ffd43b")} />
        <ChartCard title="Average request time" option={buildLineOption(analytics.avg_request_time, "#52a8ff")} />
        <ChartCard title="Request methods" option={buildStatusOption(analytics.methods)} />
      </SimpleGrid>

      <Grid mt="lg" gutter="lg">
        <Grid.Col span={12}>
          <Paper radius="xl" p="lg" className="soft-panel">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 16 }}>
              <div>
                <Title order={4}>IP locations</Title>
                <Text size="sm" c="dimmed">Map markers are built from cached geolocation for the current slice.</Text>
              </div>
              <Badge variant="light" leftSection={<IconMapPin size={12} />}>{points.length}</Badge>
            </div>
            <MapCard points={points} />
          </Paper>
        </Grid.Col>
      </Grid>

      <Paper radius="xl" p="lg" className="soft-panel" mt="lg">
        <Group justify="space-between" align="end" mb="md">
          <div>
            <Title order={4}>Log search</Title>
            <Text size="sm" c="dimmed">Search the current slice by URI, IP, ISP, host, method, verdict, and time range.</Text>
          </div>
          <Group align="end">
            <TextInput
              w={300}
              label="Quick filter"
              placeholder="IP, ISP, host, method or URI"
              value={quickSearch}
              onChange={(event) => setQuickSearch(event.currentTarget.value)}
              leftSection={<IconSearch size={16} />}
            />
            <Badge variant="light" mb={8}>{logs.total || 0} matches</Badge>
          </Group>
        </Group>
        {logs.items?.length ? (
          <Table.ScrollContainer minWidth={1080}>
            <Table highlightOnHover verticalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Time</Table.Th>
                  <Table.Th>IP</Table.Th>
                  <Table.Th>Host</Table.Th>
                  <Table.Th>Method</Table.Th>
                  <Table.Th>URI</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Latency</Table.Th>
                  <Table.Th>Verdict</Table.Th>
                  <Table.Th>Score</Table.Th>
                  <Table.Th>ISP</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {logs.items.map((entry) => (
                  <Table.Tr key={`${entry.time}-${entry.ip}-${entry.uri}-${entry.status}`}>
                    <Table.Td>{formatDateTime(entry.time)}</Table.Td>
                    <Table.Td>
                      <Button variant="subtle" color="gray" size="compact-sm" px={0} onClick={() => void openIPProfile(entry.ip)}>
                        <Code className="code-chip">{entry.ip}</Code>
                      </Button>
                    </Table.Td>
                    <Table.Td>{entry.host || "-"}</Table.Td>
                    <Table.Td>{entry.method || "-"}</Table.Td>
                    <Table.Td maw={320} style={{ whiteSpace: "normal" }}>{entry.uri || "-"}</Table.Td>
                    <Table.Td><Badge variant="light">{entry.status}</Badge></Table.Td>
                    <Table.Td>{formatLatency(entry.request_time_ms)}</Table.Td>
                    <Table.Td><StatusBadge status={entry.verdict || "unknown"} /></Table.Td>
                    <Table.Td>{entry.score ?? 0}</Table.Td>
                    <Table.Td>{entry.isp || "-"}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        ) : <Text c="dimmed">No log entries found for the current filter.</Text>}
        {logs.total > logPageSize ? (
          <Group justify="space-between" mt="lg">
            <Text size="sm" c="dimmed">
              {logs.offset + 1}–{Math.min(logs.offset + logs.items.length, logs.total)} of {logs.total} requests
            </Text>
            <Pagination value={logPage} onChange={setLogPage} total={Math.ceil(logs.total / logPageSize)} withEdges />
          </Group>
        ) : null}
      </Paper>

      <Modal opened={notificationsOpened} onClose={notificationsModal.close} title="Notification center" size="xl" centered>
        <Stack gap="sm">
          <Group justify="space-between">
            <Text size="sm" c="dimmed">Tracked incidents use the settings-defined monitoring window and are independent of the dashboard filters.</Text>
            <Badge color={activeIncidents.length ? "red" : "gray"} variant="light">{activeIncidents.length} open</Badge>
          </Group>
          {activeIncidents.length ? activeIncidents.slice(0, 8).map((incident) => (
            <Paper key={incident.id} radius="lg" p="md" className="shell-panel">
              <Group justify="space-between" align="start">
                <div>
                  <Text fw={600}>{incident.title}</Text>
                  <Text size="sm" c="dimmed">{incident.summary}</Text>
                  <Text size="xs" c="dimmed">Status: {incident.status} · First seen: {formatDateTime(incident.first_seen)} · Last seen: {formatDateTime(incident.last_seen)}</Text>
                </div>
                <Group gap="xs">
                  <Badge variant="light">{incident.value}</Badge>
                  <Badge color="red" variant="light">{incident.status}</Badge>
                  <Button size="xs" variant="light" color="gray" onClick={() => void dismissIncident(incident)}>Dismiss</Button>
                </Group>
              </Group>
            </Paper>
          )) : <Text size="sm" c="dimmed">{incidentHistory.length ? "No open incidents. Recent items are available in history below." : "No tracked incidents yet."}</Text>}
          <Accordion variant="separated" radius="lg" mt="md">
            <Accordion.Item value="incident-history">
              <Accordion.Control>
                <Group justify="space-between" wrap="nowrap" mr="sm">
                  <Title order={5}>History</Title>
                  <Badge variant="light">{incidentHistory.length}</Badge>
                </Group>
              </Accordion.Control>
              <Accordion.Panel>
                <Stack gap="sm">
                  {incidentHistory.length ? incidentHistory.map((incident) => (
                    <Paper key={`history-${incident.id}`} radius="lg" p="md" className="shell-panel">
                      <Group justify="space-between" align="start">
                        <div>
                          <Text fw={600}>{incident.title}</Text>
                          <Text size="sm" c="dimmed">{incident.summary}</Text>
                          <Text size="xs" c="dimmed">Status: {incident.status} · First seen: {formatDateTime(incident.first_seen)} · Last seen: {formatDateTime(incident.last_seen)}</Text>
                        </div>
                        <Group gap="xs">
                          <Badge variant="light">{incident.value}</Badge>
                          <Badge color={incident.status === "dismissed" ? "gray" : "blue"} variant="light">{incident.status}</Badge>
                          <Button size="xs" variant="light" color="red" leftSection={<IconTrash size={14} />} onClick={() => void deleteHistoryIncident(incident)}>Delete</Button>
                        </Group>
                      </Group>
                    </Paper>
                  )) : <Text size="sm" c="dimmed">No dismissed or resolved incidents yet.</Text>}
                </Stack>
              </Accordion.Panel>
            </Accordion.Item>
          </Accordion>
        </Stack>
      </Modal>

      <Modal opened={filterOpened} onClose={filterModal.close} title="Analytics filters" size="lg" centered>
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
          <TextInput
            label="Quick search"
            description="Matches host, URI, method, IP, or ISP."
            placeholder="login, hetzner, 87.106, example.com"
            value={draftFilters.q}
            onChange={(event) => updateDraft("q", event.currentTarget.value)}
            leftSection={<IconSearch size={16} />}
          />
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <TextInput label="From" description="Local time" type="datetime-local" value={draftFilters.from} onChange={(event) => updateDraft("from", event.currentTarget.value)} />
            <TextInput label="To" description="Local time" type="datetime-local" value={draftFilters.to} onChange={(event) => updateDraft("to", event.currentTarget.value)} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 3 }}>
            <NativeSelect label="Reputation verdict" data={verdictOptions} value={draftFilters.filter} onChange={(event) => updateDraft("filter", event.currentTarget.value)} />
            <NativeSelect label="HTTP method" data={methodOptions} value={draftFilters.method} onChange={(event) => updateDraft("method", event.currentTarget.value)} />
            <NativeSelect label="Status class" data={statusClassOptions} value={draftFilters.statusClass} onChange={(event) => updateDraft("statusClass", event.currentTarget.value)} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 4 }}>
            <TextInput label="Exact status" placeholder="404" value={draftFilters.status} onChange={(event) => updateDraft("status", event.currentTarget.value)} />
            <TextInput label="URI contains" placeholder="/wp-login" value={draftFilters.uriContains} onChange={(event) => updateDraft("uriContains", event.currentTarget.value)} leftSection={<IconSearch size={16} />} />
            <TextInput label="IP contains" placeholder="87.106." value={draftFilters.ipContains} onChange={(event) => updateDraft("ipContains", event.currentTarget.value)} />
            <TextInput label="ISP contains" placeholder="Hetzner" value={draftFilters.ispContains} onChange={(event) => updateDraft("ispContains", event.currentTarget.value)} />
          </SimpleGrid>
          <Checkbox
            label="Exclude internal API routes"
            description="Filters out dashboard requests under /api/... by default so the charts stay focused on external traffic."
            checked={draftFilters.excludeInternalAPI}
            onChange={(event) => updateDraft("excludeInternalAPI", event.currentTarget.checked)}
          />
          <Text size="sm" c="dimmed">
            Any custom filter switches reputation and geodata drilldowns to cache-first mode for faster repeated investigation.
          </Text>
          <Group justify="space-between">
            <Button variant="subtle" color="gray" onClick={resetFilters}>Reset</Button>
            <Group gap="sm">
              <Button variant="light" color="gray" onClick={filterModal.close}>Cancel</Button>
              <Button leftSection={<IconAdjustmentsHorizontal size={16} />} onClick={applyFilters}>Apply filters</Button>
            </Group>
          </Group>
        </Stack>
      </Modal>

      <Modal opened={profileOpened} onClose={profileModal.close} title={activeProfile ? `IP profile · ${activeProfile.ip}` : "IP profile"} size="xl" centered>
        {profileLoading || !activeProfile ? (
          <Text c="dimmed">Loading IP profile...</Text>
        ) : (
          <Stack gap="lg">
            <SimpleGrid cols={{ base: 1, md: 2, xl: 4 }}>
              <SummaryCard label="Requests" value={activeProfile.summary.total_requests?.toLocaleString?.() || "0"} hint="Requests for this IP in the current slice" />
              <SummaryCard label="Errors" value={`${Number(activeProfile.summary.error_rate || 0).toFixed(1)}%`} hint={`${activeProfile.summary.error_requests || 0} requests with 4xx/5xx`} />
              <SummaryCard label="Average Request Time" value={formatLatency(activeProfile.summary.avg_request_time_ms)} hint="Mean request duration for this IP" />
              <SummaryCard label="Transferred" value={formatBytes(activeProfile.summary.transferred_bytes)} hint="Response bytes served to this IP" />
            </SimpleGrid>

            <Paper radius="xl" p="lg" className="soft-panel">
              <Group justify="space-between" align="start">
                <div>
                  <Code className="code-chip">{activeProfile.ip}</Code>
                  <Text size="sm" c="dimmed">Hosts: {activeProfile.hostnames?.length ? activeProfile.hostnames.join(", ") : "-"}</Text>
                  <Text size="sm" c="dimmed">ISP: {activeProfile.isp || "-"}</Text>
                  <Text size="sm" c="dimmed">Location: {[activeProfile.city, activeProfile.region, activeProfile.country].filter(Boolean).join(", ") || "-"}</Text>
                  <Text size="sm" c="dimmed">Reputation: score {activeProfile.score ?? 0} · reports {activeProfile.reports ?? 0}</Text>
                </div>
                <StatusBadge status={activeProfile.verdict || "unknown"} />
              </Group>
            </Paper>

            <ChartCard title="Requests from this IP over time" option={buildLineOption(activeProfile.requests_over_time, "#52a8ff")} />

            <SimpleGrid cols={{ base: 1, xl: 3 }}>
              <CountList title="Status codes" items={activeProfile.status_codes} />
              <CountList title="Top paths" items={activeProfile.top_paths} />
              <CountList title="Top hosts" items={activeProfile.top_hosts} />
            </SimpleGrid>

            <Paper radius="xl" p="lg" className="soft-panel">
              <Group justify="space-between" mb="md">
                <div>
                  <Title order={4}>Recent access log</Title>
                  <Text size="sm" c="dimmed">Latest requests for this IP within the current filter window.</Text>
                </div>
                <Badge variant="light">{activeProfile.recent_requests?.length || 0}</Badge>
              </Group>
              {activeProfile.recent_requests?.length ? (
                <Table.ScrollContainer minWidth={960}>
                  <Table highlightOnHover verticalSpacing="sm">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Time</Table.Th>
                        <Table.Th>Host</Table.Th>
                        <Table.Th>Method</Table.Th>
                        <Table.Th>URI</Table.Th>
                        <Table.Th>Status</Table.Th>
                        <Table.Th>Latency</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {activeProfile.recent_requests.map((entry) => (
                        <Table.Tr key={`${entry.time}-${entry.uri}-${entry.status}`}>
                          <Table.Td>{formatDateTime(entry.time)}</Table.Td>
                          <Table.Td>{entry.host || "-"}</Table.Td>
                          <Table.Td>{entry.method || "-"}</Table.Td>
                          <Table.Td maw={340} style={{ whiteSpace: "normal" }}>{entry.uri || "-"}</Table.Td>
                          <Table.Td><Badge variant="light">{entry.status}</Badge></Table.Td>
                          <Table.Td>{formatLatency(entry.request_time_ms)}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              ) : <Text c="dimmed">No recent requests for this IP in the current slice.</Text>}
            </Paper>
          </Stack>
        )}
      </Modal>
    </Container>
  );
}
