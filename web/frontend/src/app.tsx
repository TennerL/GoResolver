import React from "react";
import { AppShell, Box, Burger, Button, Group, MantineProvider, Paper, Stack, Text } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import { AppError, SPAProvider, fetchJSON, navItems, pageTitles, theme } from "./common";
import { LoginPageView, DashboardPageView, DomainsPageView, RecordsPageView, ServersPageView, SettingsPageView } from "./pages/core-pages";

const AnalyticsPageView = React.lazy(() => import("./pages/analytics-page").then((module) => ({ default: module.AnalyticsPageView })));
const ServerConfigurationPageView = React.lazy(() => import("./pages/server-config-page").then((module) => ({ default: module.ServerConfigurationPageView })));

class ErrorBoundary extends React.Component<any, any> {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return <AppError error={this.state.error instanceof Error ? this.state.error : new Error(String(this.state.error))} />;
    }

    return this.props.children;
  }
}

function LoadingPage() {
  return <Paper radius="xl" p="lg" className="soft-panel"><Text c="dimmed">Loading page...</Text></Paper>;
}

function normalizePath(pathname) {
  if (!pathname || pathname === "/") return "/";
  return pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

function activeForView(view) {
  if (view === "records") return "domains";
  if (view === "serverconfiguration") return "servers";
  return view;
}

function sameLocation(url, pathname, search) {
  return normalizePath(url.pathname) === normalizePath(pathname) && url.search === search;
}

function buildLoginPage(search) {
  const params = new URLSearchParams(search);
  return {
    Active: "login",
    View: "login",
    Data: {
      Error: params.get("error") || ""
    }
  };
}

function resolveRoute(pathname, search) {
  const path = normalizePath(pathname);

  if (path === "/login") {
    return { key: `${path}${search}`, view: "login", staticPage: buildLoginPage(search) };
  }
  if (path === "/") {
    return { key: path, view: "dashboard", apiPath: "/api/pages/dashboard" };
  }
  if (path === "/domains") {
    return { key: path, view: "domains", apiPath: "/api/pages/domains" };
  }
  if (path === "/servers") {
    return { key: path, view: "servers", apiPath: "/api/pages/servers" };
  }
  if (path === "/analytics") {
    return { key: path, view: "analytics", staticPage: { Active: "analytics", View: "analytics" } };
  }
  if (path === "/settings") {
    return { key: `${path}${search}`, view: "settings", apiPath: `/api/pages/settings${search}` };
  }

  const recordsMatch = path.match(/^\/domains\/(\d+)\/records$/);
  if (recordsMatch) {
    return { key: path, view: "records", apiPath: `/api/pages/domains/${recordsMatch[1]}/records` };
  }

  const serverConfigMatch = path.match(/^\/servers\/(\d+)\/server_configuration$/);
  if (serverConfigMatch) {
    return { key: `${path}${search}`, view: "serverconfiguration", apiPath: `/api/pages/servers/${serverConfigMatch[1]}/server_configuration` };
  }

  return { key: `${path}${search}`, view: "unknown", error: new Error(`Unsupported route: ${path}`) };
}

function ShellLayout({ page, routeKey, children }) {
  const [opened, { toggle, close }] = useDisclosure(false);
  const active = page.Active || activeForView(page.View);

  return <AppShell header={{ height: 78 }} navbar={{ width: 290, breakpoint: "sm", collapsed: { mobile: !opened } }} padding="md">
    <AppShell.Header className="shell-panel"><Group h="100%" px="md" justify="space-between"><Group gap="sm"><Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" /><Box><Text fw={800} size="lg">GoResolver</Text><Text size="xs" c="dimmed">{pageTitles[page.View] || "GoResolver"}</Text></Box></Group><Button component="a" href="/logout" data-spa-ignore="true" variant="light" color="gray">Logout</Button></Group></AppShell.Header>
    <AppShell.Navbar p="md" className="shell-panel"><Stack mt="xl" gap="xs">{navItems.map((item) => { const Icon = item.icon; const isActive = active === item.active; return <Button key={item.href} component="a" href={item.href} justify="flex-start" variant={isActive ? "light" : "subtle"} color={isActive ? "red" : "gray"} leftSection={<Icon size={16} />} onClick={close}>{item.label}</Button>; })}</Stack></AppShell.Navbar>
    <AppShell.Main><Box className="page-surface"><ErrorBoundary key={routeKey}>{children}</ErrorBoundary></Box></AppShell.Main>
  </AppShell>;
}

function renderPage(page) {
  switch (page.View) {
    case "dashboard": return <DashboardPageView page={page} />;
    case "domains": return <DomainsPageView page={page} />;
    case "records": return <RecordsPageView page={page} />;
    case "servers": return <ServersPageView page={page} />;
    case "analytics": return <AnalyticsPageView page={page} />;
    case "settings": return <SettingsPageView page={page} />;
    case "serverconfiguration": return <ServerConfigurationPageView page={page} />;
    default: return <AppError error={new Error(`Unsupported page view: ${page.View || "unknown"}`)} />;
  }
}

export function App() {
  const [locationState, setLocationState] = React.useState(() => ({ pathname: window.location.pathname, search: window.location.search }));
  const [pageCache, setPageCache] = React.useState({});
  const [refreshToken, setRefreshToken] = React.useState(0);
  const pendingPageLoads = React.useRef({});

  const route = React.useMemo(() => resolveRoute(locationState.pathname, locationState.search), [locationState.pathname, locationState.search]);
  const cachedPage = route.key ? pageCache[route.key] : null;
  const [state, setState] = React.useState(() => {
    if (route.error) return { page: null, error: route.error, loading: false };
    if (route.staticPage) return { page: route.staticPage, error: null, loading: false };
    if (cachedPage) return { page: cachedPage, error: null, loading: false };
    return { page: null, error: null, loading: true };
  });

  const syncLocation = React.useCallback((pathname, search = "", options = {}) => {
    const nextPath = `${pathname}${search}`;
    const currentPath = `${window.location.pathname}${window.location.search}`;
    if (nextPath !== currentPath) {
      if (options.replace) {
        window.history.replaceState(null, "", nextPath);
      } else {
        window.history.pushState(null, "", nextPath);
      }
    }
    setLocationState({ pathname, search });
    if (!options.preserveScroll) {
      window.scrollTo({ top: 0, left: 0 });
    }
  }, []);

  const navigate = React.useCallback((pathname, search = "", options = {}) => {
    const normalizedPath = normalizePath(pathname);
    const nextSearch = search || "";
    if (normalizedPath === normalizePath(window.location.pathname) && nextSearch === window.location.search) {
      if (options.refresh) {
        setPageCache((current) => {
          const next = { ...current };
          delete next[resolveRoute(normalizedPath, nextSearch).key];
          return next;
        });
        setRefreshToken((value) => value + 1);
      }
      return;
    }
    syncLocation(normalizedPath, nextSearch, options);
  }, [syncLocation]);

  const navigateUrl = React.useCallback((value, options = {}) => {
    const url = new URL(value, window.location.origin);
    if (url.origin !== window.location.origin) {
      window.location.assign(url.toString());
      return;
    }
    navigate(url.pathname, url.search, options);
  }, [navigate]);

  const refresh = React.useCallback(() => {
    if (!route.key) return;
    setPageCache((current) => {
      const next = { ...current };
      delete next[route.key];
      return next;
    });
    setRefreshToken((value) => value + 1);
  }, [route.key]);

  const invalidateRouteCache = React.useCallback((pathname, search = "") => {
    const key = resolveRoute(pathname, search).key;
    if (!key) return;
    setPageCache((current) => {
      if (!(key in current)) {
        return current;
      }
      const next = { ...current };
      delete next[key];
      return next;
    });
  }, []);

  const handleMutationResponse = React.useCallback(async (response) => {
    if (response.status === 401) {
      window.location.assign("/login");
      return;
    }

    if (!response.ok) {
      const message = await response.text().catch(() => "");
      throw new Error(message || `${response.status} ${response.statusText}`);
    }

    if (response.redirected && response.url) {
      const redirected = new URL(response.url, window.location.origin);
      if (redirected.origin !== window.location.origin) {
        window.location.assign(redirected.toString());
        return;
      }

      if (sameLocation(redirected, window.location.pathname, window.location.search)) {
        refresh();
      } else {
        invalidateRouteCache(redirected.pathname, redirected.search);
        navigate(redirected.pathname, redirected.search);
      }
      return;
    }

    refresh();
  }, [invalidateRouteCache, navigate, refresh]);

  React.useEffect(() => {
    const handlePopState = () => {
      setLocationState({ pathname: window.location.pathname, search: window.location.search });
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  React.useEffect(() => {
    const handleClick = (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const target = event.target instanceof Element ? event.target.closest("a[href]") : null;
      if (!target) return;
      if (target.dataset.spaIgnore === "true" || target.hasAttribute("download")) return;
      if (target.target && target.target !== "_self") return;

      const url = new URL(target.href, window.location.href);
      if (url.origin !== window.location.origin) return;

      const nextRoute = resolveRoute(url.pathname, url.search);
      if (nextRoute.error) return;

      event.preventDefault();
      navigate(url.pathname, url.search);
    };

    document.addEventListener("click", handleClick);
    return () => document.removeEventListener("click", handleClick);
  }, [navigate]);

  React.useEffect(() => {
    const handleSubmit = (event) => {
      if (event.defaultPrevented) return;
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (form.dataset.spaIgnore === "true") return;

      const method = String(form.method || "get").toUpperCase();
      const action = form.action || window.location.href;
      const url = new URL(action, window.location.origin);
      if (url.origin !== window.location.origin) return;

      event.preventDefault();

      if (method === "GET") {
        const params = new URLSearchParams(new FormData(form));
        const search = params.toString();
        navigate(url.pathname, search ? `?${search}` : "");
        return;
      }

      const submitter = event.submitter;
      const formData = new FormData(form);
      if ((submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) && submitter.name) {
        formData.append(submitter.name, submitter.value);
      }

      const hasBinaryField = Array.from(formData.values()).some((value) => value instanceof File && value.name !== "");
      const requestInit = hasBinaryField
        ? { method, body: formData }
        : {
            method,
            headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: (() => {
              const params = new URLSearchParams();
              for (const [key, value] of formData.entries()) {
                if (typeof value === "string") {
                  params.append(key, value);
                }
              }
              return params;
            })()
          };

      void fetch(url.toString(), requestInit).then(handleMutationResponse).catch((error) => {
        window.alert(error instanceof Error ? error.message : "Request failed");
      });
    };

    document.addEventListener("submit", handleSubmit);
    return () => document.removeEventListener("submit", handleSubmit);
  }, [handleMutationResponse, navigate]);

  React.useEffect(() => {
    let cancelled = false;

    if (route.error) {
      setState({ page: null, error: route.error, loading: false });
      return () => {
        cancelled = true;
      };
    }

    if (route.staticPage) {
      setState({ page: route.staticPage, error: null, loading: false });
      return () => {
        cancelled = true;
      };
    }

    if (cachedPage) {
      setState({ page: cachedPage, error: null, loading: false });
      return () => {
        cancelled = true;
      };
    }

    setState((current) => ({ page: current.page, error: null, loading: true }));

    const requestKey = `${route.key}:${refreshToken}`;
    let request = pendingPageLoads.current[requestKey];

    if (!request) {
      request = fetchJSON(route.apiPath).finally(() => {
        if (pendingPageLoads.current[requestKey] === request) {
          delete pendingPageLoads.current[requestKey];
        }
      });
      pendingPageLoads.current[requestKey] = request;
    }

    void request.then((page) => {
        if (cancelled) return;
        setPageCache((current) => ({ ...current, [route.key]: page }));
        setState({ page, error: null, loading: false });
      })
      .catch((error) => {
        if (cancelled) return;
        const nextError = error instanceof Error ? error : new Error("Failed to load page");
        setState((current) => ({ page: current.page, error: nextError, loading: false }));
      });

    return () => {
      cancelled = true;
    };
  }, [cachedPage, refreshToken, route.apiPath, route.error, route.key, route.staticPage]);

  React.useEffect(() => {
    const view = state.page?.View || route.view;
    document.title = `GoResolver · ${pageTitles[view] || "GoResolver"}`;
  }, [state.page, route.view]);

  const spaValue = React.useMemo(() => ({
    navigate,
    navigateUrl,
    refresh,
    handleMutationResponse
  }), [handleMutationResponse, navigate, navigateUrl, refresh]);

  const shellPage = state.page || { Active: activeForView(route.view), View: route.view };
  const mainContent = state.error && !state.page
    ? <AppError error={state.error} />
    : state.loading && !state.page
      ? <LoadingPage />
      : state.page
        ? <React.Suspense fallback={<LoadingPage />}>{renderPage(state.page)}</React.Suspense>
        : <LoadingPage />;

  return <MantineProvider theme={theme} defaultColorScheme="dark">
    <Notifications position="top-right" />
    <SPAProvider value={spaValue}>
      {route.view === "login"
        ? (state.page ? <ErrorBoundary key={route.key}><LoginPageView page={state.page} /></ErrorBoundary> : mainContent)
        : <ShellLayout page={shellPage} routeKey={route.key}>{mainContent}</ShellLayout>}
    </SPAProvider>
  </MantineProvider>;
}
