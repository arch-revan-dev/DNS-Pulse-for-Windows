export type DnsProtocol = 'DoH' | 'DoT' | 'UDP' | 'SNI443';

export type DnsCategory =
  | 'Smart-DNS'
  | 'Скоростные'
  | 'Антиреклама'
  | 'Игры и Регионы'
  | 'Магистральные'
  | 'Свои / Найденные'
  | 'Личные токены';

export type BypassVerdict =
  | 'UNCHECKED'
  | 'TESTING'
  | 'VERIFIED_PROXY_OK'
  | 'DIRECT_NO_PROXY'
  | 'GEO_REDIRECT_BLOCKED'
  | 'PROXY_PORT_DEAD'
  | 'DNS_TIMEOUT';

export type SortMode =
  | 'BEST'
  | 'LOWEST_PING'
  | 'HIGHEST_TPS'
  | 'FAVORITES_FIRST'
  | 'ALPHABETICAL';

export type PresetGroupId = 'ai' | 'ai_apps' | 'all' | 'custom';

export interface DomainPreset {
  id: string;
  label: string;
  domain: string;
  group: PresetGroupId;
  requiresBypass: boolean;
  companionDomains: string[];
}

export interface DnsServer {
  id: string;
  name: string;
  provider: string;
  protocol: DnsProtocol;
  primaryIp: string;
  secondaryIp?: string;
  dohUrl?: string;
  dotHost?: string;
  smartProxyIp?: string;
  port?: number;
  category: DnsCategory;
  country: string;
  tags: string[];
  description: string;
  supportsBypass: boolean;
  isBuiltin: boolean;
  isFavorite: boolean;
  isSubscription: boolean;
  isFreeUnlimited: boolean;
  lastLatencyMs: number | null;
  minLatencyMs: number | null;
  avgLatencyMs: number | null;
  jitterMs: number | null;
  lastTps: number | null;
  verdict: BypassVerdict;
  verdictReason: string;
  resolvedIps: string[];
  companionPassed: boolean | null;
  port443Ok: boolean | null;
  httpStatus: number | null;
  lastCheckedDomain: string | null;
  lastCheckedAt: string | null;
  historyMs: number[];
}

export interface FilterState {
  category: 'Все' | DnsCategory;
  bypassOnly: boolean;
  favoritesOnly: boolean;
  encryptedOnly: boolean;
  freeOnly: boolean;
  search: string;
  sortMode: SortMode;
}

export interface ProbeResult {
  serverId: string;
  targetDomain: string;
  requiresBypass: boolean;
  latencyMs: number | null;
  minLatencyMs: number | null;
  avgLatencyMs: number | null;
  jitterMs: number | null;
  tps: number | null;
  resolvedIps: string[];
  verdict: BypassVerdict;
  verdictReason: string;
  companionPassed: boolean | null;
  companionDetails: Array<{ domain: string; ips: string[]; isDirect: boolean }>;
  port443Ok: boolean | null;
  httpStatus: number | null;
  redirectLocation: string | null;
  checkedAt: string;
}

export interface TunnelState {
  active: boolean;
  serverId: string | null;
  serverName: string | null;
  endpoint: string | null;
  protocol: DnsProtocol | null;
  targetDomain: string;
  listenAddress: string;
  localProxyAddress: string;
  proxyConnectionsHandled: number;
  splitRouting: boolean;
  nrptEnabled: boolean;
  queriesHandled: number;
  cacheHits: number;
  startedAt: string | null;
  rotationQueueIds: string[];
}

export interface SyncStatus {
  cachedHostsCount: number;
  lastSyncAt: string | null;
  sources: Array<{ name: string; url: string; count: number; ok: boolean; error?: string }>;
}

export interface DiscoveryNode {
  id: string;
  ipOrEndpoint: string;
  name: string;
  protocol: DnsProtocol;
  latencyMs: number;
  verdict: BypassVerdict;
  verdictReason: string;
  port443Ok: boolean;
  savedToDb: boolean;
}

export type AutopilotPhase = 'idle' | 'running' | 'active' | 'degraded' | 'error';

export interface AutopilotStep {
  id: string;
  label: string;
  status: 'pending' | 'active' | 'done' | 'warn' | 'error';
  detail?: string;
}

export interface AutopilotSwitchEvent {
  at: string;
  fromServerName: string | null;
  toServerName: string;
  reason: string;
}

export interface AutopilotServiceCheck {
  id: string;
  label: string;
  domain: string;
  ok: boolean;
  latencyMs: number | null;
  verdict: BypassVerdict;
}

export interface AutopilotState {
  phase: AutopilotPhase;
  watchdogEnabled: boolean;
  activeServerId: string | null;
  activeServerName: string | null;
  activeProtocol: DnsProtocol | null;
  activeLatencyMs: number | null;
  localDnsAddress: string;
  localProxyAddress: string;
  standbyCount: number;
  testedCount: number;
  verifiedCount: number;
  lastCheckAt: string | null;
  summary: string;
  steps: AutopilotStep[];
  serviceChecks: AutopilotServiceCheck[];
  switchHistory: AutopilotSwitchEvent[];
}
