export const ruleTypeOptions = [
  { value: "connlimit", label: "Connection Limit" },
  { value: "syn", label: "SYN Flood Protection" },
  { value: "dnat", label: "DNAT (Port Forward)" },
  { value: "ratelimit", label: "Rate Limit" },
  { value: "block", label: "Block IP" },
  { value: "allow", label: "Allow IP" },
  { value: "masquerade", label: "Masquerade (NAT)" },
  { value: "custom", label: "Custom / Advanced" }
];

export const errorCodeOptions = ["400","401","402","403","404","405","406","407","408","409","410","411","412","413","414","415","416","417","418","422","426","428","429","431","500","501","502","503","504","505"].map((value) => ({ value, label: value }));

export function getInitialServerTab() {
  const params = new URLSearchParams(window.location.search);
  return params.get("tab") || "tab1";
}

export function updateListItem(items, index, field, value) {
  return items.map((item, itemIndex) => (itemIndex === index ? { ...item, [field]: value } : item));
}

export function mapSite(site) {
  return { ID: String(site.ID), Server_Name: site.Server_Name || "", Server_Port: String(site.Server_Port || ""), SSL_Enabled: String(site.SSL_Enabled ?? 0), SSL_Redirect: String(site.SSL_Redirect ?? 0), HSTS: String(site.HSTS ?? 0), Proxy_Pass_Port: String(site.Proxy_Pass_Port || ""), Proxy_Intercept_Errors: String(site.Proxy_Intercept_Errors ?? 0), Websockets: String(site.Websockets ?? 0) };
}

export function mapErrorPage(errorPage) {
  return { ID: errorPage.ID, Site_ID: errorPage.Site_ID || "*", ErrorPage_ID: errorPage.ErrorPage_ID || "", Enabled: errorPage.Enabled ? "1" : "0" };
}

export function mapErrorFile(file) {
  return { ID: file.ID, Error_Code: file.Error_Code || "", ResponseType: file.ResponseType || "html", Filename: file.Filename || "", Path: file.Path || "" };
}

export function mapDDoS(policy) {
  return { Enabled: !!policy.Enabled, Mode: policy.Mode || "off", Preset: policy.Preset || "medium", RateLimit: String(policy.RateLimit ?? ""), Burst: String(policy.Burst ?? ""), ConnLimit: String(policy.ConnLimit ?? ""), SynRate: String(policy.SynRate ?? ""), SynBurst: String(policy.SynBurst ?? ""), ChallengeDelay: String(policy.ChallengeDelay ?? ""), CookieTTL: String(policy.CookieTTL ?? ""), Whitelist: policy.Whitelist || "" };
}

export function mapFail2Ban(policy) {
  return { Enabled: !!policy.Enabled, MaxRetry: String(policy.MaxRetry ?? ""), FindTimeSeconds: String(policy.FindTimeSeconds ?? ""), BanTimeSeconds: String(policy.BanTimeSeconds ?? ""), StatusCodes: policy.StatusCodes || "", IgnoreIPs: policy.IgnoreIPs || "", UseXForwardedFor: !!policy.UseXForwardedFor, BanGlobally: !!policy.BanGlobally };
}

export function mapSystemNginxSite(site) {
  const serverName = site.ServerName ?? site.server_name ?? "";
  const listenPort = site.ListenPort ?? site.listen_port ?? 443;
  const ssl = site.SSL ?? site.ssl ?? false;
  const http2 = site.HTTP2 ?? site.http2 ?? false;
  const mode = site.Mode ?? site.mode ?? "proxy";
  const certPath = site.CertPath ?? site.cert_path ?? "";
  const keyPath = site.KeyPath ?? site.key_path ?? "";
  const sslConfigPath = site.SSLConfigPath ?? site.ssl_config_path ?? "";
  const sslDhParamPath = site.SSLDhParamPath ?? site.ssl_dhparam_path ?? "";
  const rootPath = site.RootPath ?? site.root_path ?? "";
  const indexFiles = site.IndexFiles ?? site.index_files ?? "index.php index.html";
  const proxyPassURL = site.ProxyPassURL ?? site.proxy_pass_url ?? "";
  const staticAliasPath = site.StaticAliasPath ?? site.static_alias_path ?? "";
  const phpEnabled = site.PHPEnabled ?? site.php_enabled ?? false;
  const phpSocket = site.PHPSocket ?? site.php_socket ?? "";
  const phpMyAdminEnabled = site.PHPMyAdminEnabled ?? site.phpmyadmin_enabled ?? false;
  const phpMyAdminSocket = site.PHPMyAdminSocket ?? site.phpmyadmin_socket ?? "";
  const proxyBufferingOff = site.ProxyBufferingOff ?? site.proxy_buffering_off ?? false;
  const accessLogOffStatic = site.AccessLogOffStatic ?? site.access_log_off_static ?? false;
  const staticExpires = site.StaticExpires ?? site.static_expires ?? "1h";
  const staticCacheControl = site.StaticCacheControl ?? site.static_cache_control ?? "public";
  return {
    ID: site.ID || "",
    ServerName: serverName,
    ListenPort: String(listenPort),
    SSL: ssl ? "1" : "0",
    HTTP2: http2 ? "1" : "0",
    Mode: mode,
    CertPath: certPath,
    KeyPath: keyPath,
    SSLConfigPath: sslConfigPath,
    SSLDhParamPath: sslDhParamPath,
    RootPath: rootPath,
    IndexFiles: indexFiles,
    ProxyPassURL: proxyPassURL,
    StaticAliasPath: staticAliasPath,
    PHPEnabled: phpEnabled ? "1" : "0",
    PHPSocket: phpSocket,
    PHPMyAdminEnabled: phpMyAdminEnabled ? "1" : "0",
    PHPMyAdminSocket: phpMyAdminSocket,
    ProxyBufferingOff: proxyBufferingOff ? "1" : "0",
    AccessLogOffStatic: accessLogOffStatic ? "1" : "0",
    StaticExpires: staticExpires,
    StaticCacheControl: staticCacheControl
  };
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

export function buildServerConfigFormState(page) {
  const sites = asArray(page?.Data).filter((item) => item?.Server_Name !== "dummy").map(mapSite);
  const errorPages = asArray(page?.ErrorPages).map(mapErrorPage);
  const errorFiles = asArray(page?.ErrorFiles).map(mapErrorFile);
  const systemNginxSites = asArray(page?.SystemNginxSites).map(mapSystemNginxSite);

  return { TopServerName: page.ServerName || "", SystemNginxConfig: page.SystemNginxConfig || "", SystemNginxImport: "", SystemNginxSites: systemNginxSites, NewSystemNginxSites: [], VPNIP: page.IP || "", VPNFile: page.VPN_File || "", Sites: sites, NewSites: [], ErrorPages: errorPages, NewErrorPages: [], ErrorFiles: errorFiles, DDoS: mapDDoS(page.DDoSPolicy || {}), Fail2Ban: mapFail2Ban(page.Fail2BanPolicy || {}) };
}

export function emptySiteRow() {
  return { ID: "", Server_Name: "", Server_Port: "80", SSL_Enabled: "0", SSL_Redirect: "0", HSTS: "0", Proxy_Pass_Port: "8080", Proxy_Intercept_Errors: "0", Websockets: "0" };
}

export function emptyErrorPageRow() {
  return { ID: "", Site_ID: "*", ErrorPage_ID: "", Enabled: "1" };
}

export function emptySystemNginxSiteRow() {
  return {
    ID: "",
    ServerName: "",
    ListenPort: "443",
    SSL: "1",
    HTTP2: "1",
    Mode: "static",
    CertPath: "",
    KeyPath: "",
    SSLConfigPath: "/etc/letsencrypt/options-ssl-nginx.conf",
    SSLDhParamPath: "/etc/letsencrypt/ssl-dhparams.pem",
    RootPath: "/var/www/html",
    IndexFiles: "index.php index.html",
    ProxyPassURL: "",
    StaticAliasPath: "",
    PHPEnabled: "0",
    PHPSocket: "/run/php/php8.1-fpm.sock",
    PHPMyAdminEnabled: "0",
    PHPMyAdminSocket: "/run/php/phpmyadmin.sock",
    ProxyBufferingOff: "1",
    AccessLogOffStatic: "1",
    StaticExpires: "1h",
    StaticCacheControl: "public"
  };
}

export function defaultRuleForm() {
  return { rule_type: "connlimit", protocol: "tcp", rule_table: "filter", rule_chain: "INPUT", rule_action: "append", rule_position: "", source_ip: "", dest_ip: "", source_port: "", port: "", in_interface: "", out_interface: "", conn_limit: "", rate: "", burst: "", to_ip: "", to_port: "", conn_state: "", icmp_type: "", target: "DROP", reject_with: "", log_prefix: "", log_level: "", rule_comment: "", extra_args: "" };
}

export function applyRuleTypeDefaults(type, current) {
  const next = { ...current, rule_type: type };
  if (type === "dnat") { next.rule_table = "nat"; next.rule_chain = "PREROUTING"; next.target = "DNAT"; }
  else if (type === "masquerade") { next.rule_table = "nat"; next.rule_chain = "POSTROUTING"; next.target = "MASQUERADE"; }
  else if (type === "allow") { next.rule_table = "filter"; next.rule_chain = "INPUT"; next.target = "ACCEPT"; }
  else if (type === "block") { next.rule_table = "filter"; next.rule_chain = "INPUT"; next.target = "DROP"; }
  else if (type !== "custom") { next.rule_table = "filter"; next.rule_chain = "INPUT"; }
  return next;
}
