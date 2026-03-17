export type PageView =
  | "login"
  | "dashboard"
  | "domains"
  | "records"
  | "servers"
  | "analytics"
  | "settings"
  | "serverconfiguration";

export interface DashboardItem {
  Name: string;
  Status: string;
}

export interface Domain {
  ID: number;
  Name: string;
  Status: string;
}

export interface DnsRecord {
  ID: number;
  Domain_id: number;
  Name: string;
  Type: string;
  Content: string;
  Ttl: number;
}

export interface Server {
  ID: number;
  Domain_ID: number;
  Name: string;
  IP: string;
  VPN_File: string;
  Status: string;
  IsSystem?: boolean;
}

export interface SettingItem {
  Key: string;
  Label: string;
  Value: string;
  Group: string;
  Help: string;
  ReadOnly: boolean;
}

export interface SettingsPageState {
  Items: SettingItem[];
  Saved: boolean;
}

export interface ServerConfiguration {
  ID: number;
  Server_Name: string;
  Server_Port: number;
  SSL_Enabled: number;
  SSL_Redirect: number;
  HSTS: number;
  Proxy_Pass_Port: number;
  Proxy_Intercept_Errors: number;
  Proxy_Connect_Timeout: number;
  Proxy_Read_Timeout: number;
  Proxy_Send_Timeout: number;
  Websockets: number;
  IP: string;
  VPN_File: string;
  Port: number;
  ServerID: string;
  Name: string;
  Cert_Path: string;
  Key_Path: string;
  Cert_Issued: string;
  Cert_Expiration: string;
}

export interface ServerErrorPage {
  ID: string;
  Server_ID: string;
  Site_ID: string;
  Server_Name: string;
  ErrorPage_ID: string;
  Name: string;
  Enabled: boolean;
  Is_Default: boolean;
}

export interface ServerErrorFile {
  ID: string;
  Error_Code: string;
  ResponseType: string;
  Filename: string;
  File: string;
  Path: string;
}

export interface IPTablesRule {
  Table: string;
  Chain: string;
  Num: string;
  Pkts: string;
  Bytes: string;
  Target: string;
  Prot: string;
  Opt: string;
  In: string;
  Out: string;
  Source: string;
  Destination: string;
  Extra: string;
  Limit: string;
}

export interface DDoSPolicy {
  ServerID: string;
  Enabled: boolean;
  Mode: string;
  Preset: string;
  RateLimit: number;
  Burst: number;
  ConnLimit: number;
  SynRate: number;
  SynBurst: number;
  ChallengeDelay: number;
  CookieTTL: number;
  Whitelist: string;
}

export interface Fail2BanPolicy {
  ServerID: string;
  Enabled: boolean;
  MaxRetry: number;
  FindTimeSeconds: number;
  BanTimeSeconds: number;
  StatusCodes: string;
  IgnoreIPs: string;
  UseXForwardedFor: boolean;
  BanGlobally: boolean;
}

export interface Fail2BanBan {
  ServerID: string;
  IP: string;
  HitCount: number;
  BannedAt: string;
  ExpiresAt: string;
}

export interface SystemNginxSite {
  ID: string;
  ServerName: string;
  ListenPort: number;
  SSL: boolean;
  HTTP2: boolean;
  Mode: string;
  EnableDDoS: boolean;
  CertPath: string;
  KeyPath: string;
  SSLConfigPath: string;
  SSLDhParamPath: string;
  RootPath: string;
  IndexFiles: string;
  ProxyPassURL: string;
  StaticAliasPath: string;
  PHPEnabled: boolean;
  PHPSocket: string;
  PHPMyAdminEnabled: boolean;
  PHPMyAdminSocket: string;
  ProxyBufferingOff: boolean;
  AccessLogOffStatic: boolean;
  StaticExpires: string;
  StaticCacheControl: string;
}

export interface BasePage {
  Active: string;
  View: PageView;
}

export interface LoginPage extends BasePage {
  View: "login";
  Data: Record<string, string>;
}

export interface DashboardPage extends BasePage {
  View: "dashboard";
  Data: DashboardItem[];
  Servers: Server[];
}

export interface DomainsPage extends BasePage {
  View: "domains";
  Data: Domain[];
}

export interface RecordsPage extends BasePage {
  View: "records";
  Data: DnsRecord[];
  DomainID: string;
}

export interface ServersPage extends BasePage {
  View: "servers";
  Data: Server[];
  SuggestedIP: string;
}

export interface AnalyticsPage extends BasePage {
  View: "analytics";
}

export interface SettingsPage extends BasePage {
  View: "settings";
  Data: SettingsPageState;
}

export interface ServerConfigurationPage extends BasePage {
  View: "serverconfiguration";
  Data: ServerConfiguration[];
  ServerID: string;
  ServerName: string;
  IP: string;
  IsSystemServer?: boolean;
  SystemNginxConfig?: string;
  SystemNginxSites?: SystemNginxSite[];
  VPN_File: string;
  ErrorPages: ServerErrorPage[];
  ErrorFiles: ServerErrorFile[];
  IPTablesRules: IPTablesRule[];
  DDoSPolicy: DDoSPolicy;
  Fail2BanPolicy: Fail2BanPolicy;
  Fail2BanBans: Fail2BanBan[];
}

export type AppPage =
  | LoginPage
  | DashboardPage
  | DomainsPage
  | RecordsPage
  | ServersPage
  | AnalyticsPage
  | SettingsPage
  | ServerConfigurationPage;

export interface TimeSeries {
  labels: string[];
  values: number[];
}

export interface TopUrisSeries {
  labels: string[];
  status_codes: Record<string, number[]>;
}

export interface AnalyticsResponse {
  requests_over_time: TimeSeries;
  status_codes: Record<string, number>;
  top_uris: TopUrisSeries;
  avg_request_time: TimeSeries;
}

export interface ReputationEntry {
  ip: string;
  verdict: string;
  score?: number;
  reports?: number;
  hostnames?: string[];
  isp?: string;
}

export interface GeoPoint {
  ip: string;
  lat: number;
  lon: number;
  city?: string;
  region?: string;
  country?: string;
}
