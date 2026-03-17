import {
  Alert,
  Badge,
  Container,
  Paper,
  Stack,
  Text,
  Title,
  createTheme
} from "@mantine/core";
import { IconAlertCircle, IconChartBar, IconCopy, IconDatabase, IconDeviceFloppy, IconDownload, IconEdit, IconGlobe, IconLayoutDashboard, IconLogout, IconMapPin, IconPlus, IconRefresh, IconServer, IconSettings, IconShieldLock, IconTrash } from "@tabler/icons-react";
import { createContext, useContext, useEffect, useRef } from "react";

export const theme = createTheme({
  primaryColor: "red",
  fontFamily: '"Segoe UI Variable Display", "Trebuchet MS", sans-serif',
  headings: { fontFamily: '"Bahnschrift", "Trebuchet MS", sans-serif', fontWeight: "700" },
  defaultRadius: "lg"
});

export const icons = { IconAlertCircle, IconChartBar, IconCopy, IconDatabase, IconDeviceFloppy, IconDownload, IconEdit, IconGlobe, IconLayoutDashboard, IconLogout, IconMapPin, IconPlus, IconRefresh, IconServer, IconSettings, IconShieldLock, IconTrash };

export const pageTitles = {
  login: "Login",
  dashboard: "Dashboard",
  domains: "Domains",
  records: "Records",
  servers: "Servers",
  analytics: "Analytics",
  settings: "Settings",
  serverconfiguration: "Server Configuration"
};

export const navItems = [
  { href: "/", label: "Dashboard", active: "dashboard", icon: IconLayoutDashboard },
  { href: "/domains", label: "Domains", active: "domains", icon: IconGlobe },
  { href: "/servers", label: "Servers", active: "servers", icon: IconServer },
  { href: "/analytics", label: "Analytics", active: "analytics", icon: IconChartBar },
  { href: "/settings", label: "Settings", active: "settings", icon: IconSettings }
];

const SPAContext = createContext({
  navigate: () => undefined,
  navigateUrl: () => undefined,
  refresh: () => undefined,
  handleMutationResponse: async () => undefined
});

export function SPAProvider({ value, children }) {
  return <SPAContext.Provider value={value}>{children}</SPAContext.Provider>;
}

export function useSPA() {
  return useContext(SPAContext);
}

export function statusColor(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "online" || normalized === "genuine") return "teal";
  if (normalized === "checking") return "blue";
  if (normalized === "dnssec error") return "orange";
  if (normalized === "delegation mismatch") return "yellow";
  if (normalized === "offline" || normalized === "suspicious") return "red";
  return "gray";
}

export function downloadText(filename, content) {
  const blob = new Blob([content], { type: "text/plain" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(link.href);
}

export async function fetchJSON(url, init) {
  const response = await fetch(url, { cache: "no-store", ...init });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Unauthorized");
  }
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

export function AppError({ error }) {
  return (
    <Container size="sm" py="xl">
      <Alert color="red" icon={<IconAlertCircle size={16} />} title="Frontend failed to load">
        {error.message}
      </Alert>
    </Container>
  );
}

export function PageHeader({ title, description, actions }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 16, alignItems: "end", marginBottom: 20, flexWrap: "wrap" }}>
      <div>
        <Title order={2}>{title}</Title>
        <Text c="dimmed">{description}</Text>
      </div>
      {actions}
    </div>
  );
}

export function StatusBadge({ status }) {
  return <Badge color={statusColor(status)} variant="light" radius="xl">{status || "Unknown"}</Badge>;
}

export function EmptyState({ title, description }) {
  return (
    <Paper p="xl" radius="xl" className="soft-panel">
      <Stack align="center" gap="xs">
        <Badge variant="dot" color="red">Empty</Badge>
        <Title order={4}>{title}</Title>
        <Text c="dimmed" ta="center">{description}</Text>
      </Stack>
    </Paper>
  );
}

export function ActionForm({ action, fields, confirmMessage, children, className = "inline-form" }) {
  const handleSubmit = (event) => {
    if (confirmMessage && !window.confirm(confirmMessage)) event.preventDefault();
  };
  const spaIgnore = typeof action === "string" && /\/servers\/\d+\/server_configuration$/.test(action);
  return (
    <form method="post" action={action} className={className} onSubmit={handleSubmit} data-spa-ignore={spaIgnore ? "true" : undefined}>
      {Object.entries(fields || {}).map(([name, value]) => value === undefined ? null : <input key={name} type="hidden" name={name} value={String(value)} />)}
      {children}
    </form>
  );
}

export function ChartCard({ title, option }) {
  return (
    <Paper radius="xl" p="lg" className="soft-panel">
      <Stack gap="md">
        <Title order={4}>{title}</Title>
        {option ? <EChart option={option} /> : <Text c="dimmed">No data for the selected time range.</Text>}
      </Stack>
    </Paper>
  );
}

export function EChart({ option }) {
  const ref = useRef(null);
  const instanceRef = useRef(null);
  const optionRef = useRef(option);

  useEffect(() => {
    optionRef.current = option;
    instanceRef.current?.setOption(option, true);
  }, [option]);

  useEffect(() => {
    let active = true;
    let cleanup = () => undefined;

    async function init() {
      if (!ref.current || instanceRef.current) return;

      const echarts = await import("echarts");
      if (!active || !ref.current || instanceRef.current) return;

      const instance = echarts.init(ref.current);
      instanceRef.current = instance;
      instance.setOption(optionRef.current, true);

      const resize = () => instance.resize();
      window.addEventListener("resize", resize);
      cleanup = () => {
        window.removeEventListener("resize", resize);
        instance.dispose();
        instanceRef.current = null;
      };
    }

    void init();

    return () => {
      active = false;
      cleanup();
    };
  }, []);

  return <div ref={ref} className="chart-surface" />;
}

export function MapCard({ points }) {
  const ref = useRef(null);
  const mapRef = useRef(null);
  const layerRef = useRef(null);
  const leafletRef = useRef(null);

  useEffect(() => {
    let active = true;

    async function init() {
      if (!ref.current || mapRef.current) return;

      const leaflet = await import("leaflet");
      const L = leaflet.default;
      if (!active || !ref.current || mapRef.current) return;

      leafletRef.current = L;
      const map = L.map(ref.current, { scrollWheelZoom: false }).setView([20, 0], 2);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "&copy; OpenStreetMap contributors" }).addTo(map);
      layerRef.current = L.layerGroup().addTo(map);
      mapRef.current = map;
    }

    void init();

    return () => {
      active = false;
      mapRef.current?.remove();
      mapRef.current = null;
      layerRef.current = null;
      leafletRef.current = null;
    };
  }, []);

  useEffect(() => {
    const L = leafletRef.current;
    if (!L || !mapRef.current || !layerRef.current) return;

    layerRef.current.clearLayers();
    const bounds = [];
    points.forEach((point) => {
      if (typeof point.lat !== "number" || typeof point.lon !== "number") return;
      const marker = L.circleMarker([point.lat, point.lon], { radius: 6, color: "#ff6d4d", fillColor: "#52a8ff", fillOpacity: 0.8 });
      const label = `${point.ip}${point.city || point.region || point.country ? ` - ${[point.city, point.region, point.country].filter(Boolean).join(", ")}` : ""}`;
      marker.bindPopup(label).addTo(layerRef.current);
      bounds.push([point.lat, point.lon]);
    });

    if (bounds.length > 0) mapRef.current.fitBounds(bounds, { padding: [24, 24] });
  }, [points]);

  return <div ref={ref} className="map-surface" />;
}

export function buildLineOption(series, color) {
  if (!series?.labels?.length) return null;
  return {
    tooltip: { trigger: "axis" },
    grid: { top: 24, left: 36, right: 16, bottom: 28 },
    xAxis: { type: "category", data: series.labels, axisLabel: { color: "#94a3b8" }, axisLine: { lineStyle: { color: "#334155" } } },
    yAxis: { type: "value", axisLabel: { color: "#94a3b8" }, splitLine: { lineStyle: { color: "rgba(148,163,184,0.18)" } } },
    series: [{ type: "line", smooth: true, data: series.values, areaStyle: { color: `${color}22` }, lineStyle: { color }, itemStyle: { color } }]
  };
}

export function buildStatusOption(statusCodes) {
  const labels = Object.keys(statusCodes || {});
  if (!labels.length) return null;
  return {
    tooltip: { trigger: "item" },
    grid: { top: 24, left: 36, right: 16, bottom: 28 },
    xAxis: { type: "category", data: labels, axisLabel: { color: "#94a3b8" }, axisLine: { lineStyle: { color: "#334155" } } },
    yAxis: { type: "value", axisLabel: { color: "#94a3b8" }, splitLine: { lineStyle: { color: "rgba(148,163,184,0.18)" } } },
    series: [{ type: "bar", data: labels.map((label) => statusCodes[label]), itemStyle: { color: "#ff6d4d" } }]
  };
}

export function buildRankingOption(series, color = "#ff6d4d") {
  if (!series?.labels?.length) return null;
  const data = series.values.map((value, index) => ({
    value,
    urls: Array.isArray(series.urls?.[index]) ? series.urls[index] : []
  }));
  return {
    tooltip: {
      trigger: "item",
      formatter: (param) => {
        const name = escapeTooltipHTML(String(param.name || ""));
        const value = typeof param.data?.value === "number" ? param.data.value : Number(param.value || 0);
        const urls = Array.isArray(param.data?.urls) ? param.data.urls : [];
        const urlList = urls.length
          ? urls.map((url) => `<div style="margin-top:4px;color:#cbd5e1">${escapeTooltipHTML(String(url))}</div>`).join("")
          : '<div style="margin-top:4px;color:#94a3b8">No URL details available</div>';
        return `<div><div style="font-weight:600;margin-bottom:4px">${name}</div><div style="margin-bottom:6px">Requests: ${value}</div><div style="color:#94a3b8">Top URLs</div>${urlList}</div>`;
      }
    },
    grid: { top: 24, left: 88, right: 16, bottom: 28 },
    xAxis: { type: "value", axisLabel: { color: "#94a3b8" }, splitLine: { lineStyle: { color: "rgba(148,163,184,0.18)" } } },
    yAxis: { type: "category", data: series.labels, inverse: true, axisLabel: { color: "#94a3b8" } },
    series: [{ type: "bar", data, itemStyle: { color }, barMaxWidth: 18 }]
  };
}

function escapeTooltipHTML(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function buildTopUrisOption(series) {
  if (!series?.labels?.length) return null;
  const activeCodes = Object.keys(series.status_codes || {}).filter((code) => series.status_codes[code]?.some((value) => value > 0));
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    legend: { data: activeCodes, textStyle: { color: "#cbd5e1" } },
    grid: { top: 24, left: 80, right: 16, bottom: 28 },
    xAxis: { type: "value", axisLabel: { color: "#94a3b8" }, splitLine: { lineStyle: { color: "rgba(148,163,184,0.18)" } } },
    yAxis: { type: "category", data: series.labels, axisLabel: { color: "#94a3b8" } },
    series: activeCodes.map((code) => ({ name: code, type: "bar", stack: "status", data: series.status_codes[code] }))
  };
}

