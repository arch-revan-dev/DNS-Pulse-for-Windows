import {
  BypassVerdict,
  DnsCategory,
  DnsProtocol,
  DnsServer,
  FilterState,
  SortMode,
} from './types';

export const CATEGORY_LIST: Array<'Все' | DnsCategory> = [
  'Все',
  'Smart-DNS',
  'Скоростные',
  'Антиреклама',
  'Игры и Регионы',
  'Магистральные',
  'Свои / Найденные',
  'Личные токены',
];

export function hasActiveFilter(filter: FilterState): boolean {
  return (
    filter.category !== 'Все' ||
    filter.bypassOnly ||
    filter.favoritesOnly ||
    filter.encryptedOnly ||
    filter.freeOnly ||
    filter.search.trim().length > 0
  );
}

export function getCategoryCounts(
  servers: DnsServer[]
): Record<'Все' | DnsCategory, number> {
  const counts: Record<'Все' | DnsCategory, number> = {
    Все: servers.length,
    'Smart-DNS': 0,
    Скоростные: 0,
    Антиреклама: 0,
    'Игры и Регионы': 0,
    Магистральные: 0,
    'Свои / Найденные': 0,
    'Личные токены': 0,
  };

  for (const s of servers) {
    if (counts[s.category] !== undefined) {
      counts[s.category] += 1;
    }
  }
  return counts;
}

export function filterServers(
  servers: DnsServer[],
  filter: FilterState,
  requiresBypass: boolean
): DnsServer[] {
  const q = filter.search.trim().toLowerCase();

  return servers.filter((s) => {
    if (filter.category !== 'Все' && s.category !== filter.category) {
      return false;
    }

    if (filter.freeOnly && s.isSubscription) {
      return false;
    }

    if (filter.favoritesOnly && !s.isFavorite) {
      return false;
    }

    if (filter.encryptedOnly && s.protocol !== 'DoH' && s.protocol !== 'DoT') {
      return false;
    }

    if (filter.bypassOnly) {
      if (requiresBypass) {
        const isOkOrCandidate =
          s.verdict === 'VERIFIED_PROXY_OK' ||
          (s.verdict === 'UNCHECKED' && s.supportsBypass);
        if (!isOkOrCandidate) return false;
      } else {
        if (!s.supportsBypass && s.verdict !== 'VERIFIED_PROXY_OK') return false;
      }
    }

    if (q) {
      const haystack = [
        s.name,
        s.provider,
        s.primaryIp,
        s.secondaryIp ?? '',
        s.dohUrl ?? '',
        s.dotHost ?? '',
        s.smartProxyIp ?? '',
        s.country,
        s.description,
        ...s.tags,
      ]
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(q)) return false;
    }

    return true;
  });
}

function getEffectiveLatency(s: DnsServer): number {
  if (s.lastLatencyMs !== null && s.lastLatencyMs > 0) return s.lastLatencyMs;
  if (s.avgLatencyMs !== null && s.avgLatencyMs > 0) return s.avgLatencyMs;
  return Number.MAX_SAFE_INTEGER;
}

function getEffectiveTps(s: DnsServer): number {
  return s.lastTps !== null && s.lastTps >= 0 ? s.lastTps : -1;
}

function verdictRank(verdict: BypassVerdict, supportsBypass: boolean): number {
  switch (verdict) {
    case 'VERIFIED_PROXY_OK':
      return 0;
    case 'UNCHECKED':
      return supportsBypass ? 1 : 2;
    case 'DIRECT_NO_PROXY':
      return 3;
    case 'GEO_REDIRECT_BLOCKED':
      return 4;
    case 'PROXY_PORT_DEAD':
      return 5;
    case 'DNS_TIMEOUT':
      return 6;
    default:
      return 2;
  }
}

/**
 * Sorts servers strictly according to the selected SortMode.
 * Never forces isFavorite DESC unless SortMode === 'FAVORITES_FIRST'.
 * Uses persisted lastLatencyMs and lastTps so sorting works right on app startup.
 */
export function sortServers(
  servers: DnsServer[],
  sortMode: SortMode
): DnsServer[] {
  const copy = [...servers];
  copy.sort((a, b) => {
    switch (sortMode) {
      case 'BEST': {
        const ra = verdictRank(a.verdict, a.supportsBypass);
        const rb = verdictRank(b.verdict, b.supportsBypass);
        if (ra !== rb) return ra - rb;
        const la = getEffectiveLatency(a);
        const lb = getEffectiveLatency(b);
        if (la !== lb) return la - lb;
        return a.name.localeCompare(b.name, 'ru');
      }
      case 'LOWEST_PING': {
        const la = getEffectiveLatency(a);
        const lb = getEffectiveLatency(b);
        if (la !== lb) return la - lb;
        return a.name.localeCompare(b.name, 'ru');
      }
      case 'HIGHEST_TPS': {
        const ta = getEffectiveTps(a);
        const tb = getEffectiveTps(b);
        if (ta !== tb) return tb - ta;
        const la = getEffectiveLatency(a);
        const lb = getEffectiveLatency(b);
        if (la !== lb) return la - lb;
        return a.name.localeCompare(b.name, 'ru');
      }
      case 'FAVORITES_FIRST': {
        if (a.isFavorite !== b.isFavorite) return a.isFavorite ? -1 : 1;
        const la = getEffectiveLatency(a);
        const lb = getEffectiveLatency(b);
        if (la !== lb) return la - lb;
        return a.name.localeCompare(b.name, 'ru');
      }
      case 'ALPHABETICAL':
      default:
        return a.name.localeCompare(b.name, 'ru');
    }
  });
  return copy;
}

export function buildRotationQueue(
  servers: DnsServer[],
  currentServerId: string | null
): string[] {
  const verified = sortServers(
    servers.filter((s) => s.verdict === 'VERIFIED_PROXY_OK'),
    'LOWEST_PING'
  );
  const candidates =
    verified.length > 0
      ? verified
      : sortServers(
          servers.filter((s) => s.supportsBypass && !s.isSubscription),
          'LOWEST_PING'
        ).slice(0, 20);

  const ids = candidates.map((s) => s.id);
  if (currentServerId && !ids.includes(currentServerId)) {
    ids.unshift(currentServerId);
  }
  return ids;
}

export function getNextRotationServerId(
  queueIds: string[],
  currentServerId: string | null
): string | null {
  if (queueIds.length === 0) return null;
  if (!currentServerId) return queueIds[0];
  const idx = queueIds.indexOf(currentServerId);
  if (idx === -1 || idx + 1 >= queueIds.length) return queueIds[0];
  return queueIds[idx + 1];
}

/**
 * Parses hosts files (e.g. https://dns.malw.link/hosts), skipping 0.0.0.0 and 127.0.0.1 adblock lines
 * and extracting only real proxied domain hosts.
 */
export function parseDynamicBypassHosts(rawText: string): string[] {
  const hosts = new Set<string>();
  const lines = rawText.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const ip = parts[0].trim();
      const host = parts[1].trim().toLowerCase();
      // Skip adblock sinkhole lines
      if (
        ip === '0.0.0.0' ||
        ip === '127.0.0.1' ||
        ip === '::1' ||
        ip === '::'
      ) {
        continue;
      }
      if (isValidHostname(host)) {
        hosts.add(host);
      }
    } else if (parts.length === 1 && isValidHostname(parts[0])) {
      hosts.add(parts[0].toLowerCase());
    }
  }

  return Array.from(hosts);
}

function isValidHostname(host: string): boolean {
  if (!host || host.length > 253) return false;
  if (host === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return false;
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host);
}

export function detectProtocolFromEndpoint(endpoint: string): DnsProtocol {
  const s = endpoint.trim().toLowerCase();
  if (s.startsWith('https://') || s.startsWith('http://')) return 'DoH';
  if (s.startsWith('tls://')) return 'DoT';
  if (s.startsWith('smartproxy://') || s.endsWith(':443')) return 'SNI443';
  if (!/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(s) && s.includes('.')) return 'DoT';
  return 'UDP';
}

export function createDefaultServerTemplate(
  partial: Partial<DnsServer> & { name: string }
): DnsServer {
  const id =
    partial.id ||
    `custom_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  return {
    id,
    name: partial.name,
    provider: partial.provider || 'Пользовательский',
    protocol: partial.protocol || 'UDP',
    primaryIp: partial.primaryIp || '',
    secondaryIp: partial.secondaryIp,
    dohUrl: partial.dohUrl,
    dotHost: partial.dotHost,
    smartProxyIp: partial.smartProxyIp,
    port: partial.port,
    category: partial.category || 'Свои / Найденные',
    country: partial.country || 'CUSTOM',
    tags: partial.tags || ['custom'],
    description: partial.description || 'Пользовательская запись DNS',
    supportsBypass: partial.supportsBypass ?? false,
    isBuiltin: partial.isBuiltin ?? false,
    isFavorite: partial.isFavorite ?? false,
    isSubscription: partial.isSubscription ?? false,
    isFreeUnlimited: partial.isFreeUnlimited ?? !partial.isSubscription,
    lastLatencyMs: partial.lastLatencyMs ?? null,
    minLatencyMs: partial.minLatencyMs ?? null,
    avgLatencyMs: partial.avgLatencyMs ?? null,
    jitterMs: partial.jitterMs ?? null,
    lastTps: partial.lastTps ?? null,
    verdict: partial.verdict ?? 'UNCHECKED',
    verdictReason: partial.verdictReason ?? 'Не проверялся',
    resolvedIps: partial.resolvedIps ?? [],
    companionPassed: partial.companionPassed ?? null,
    port443Ok: partial.port443Ok ?? null,
    httpStatus: partial.httpStatus ?? null,
    lastCheckedDomain: partial.lastCheckedDomain ?? null,
    lastCheckedAt: partial.lastCheckedAt ?? null,
    historyMs: partial.historyMs ?? [],
  };
}

/**
 * Parses JSON, CSV, or free-form plain text lines (DoH URLs, IPs, hostnames) into DnsServer entries.
 */
export function parseImportedServers(rawText: string): DnsServer[] {
  const trimmed = rawText.trim();
  if (!trimmed) return [];

  // 1. JSON array or object with servers[]
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      const arr = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed.servers)
          ? parsed.servers
          : [parsed];
      return arr
        .filter((item: Record<string, unknown>) => item && (item.name || item.dohUrl || item.primaryIp || item.dotHost))
        .map((item: Record<string, unknown>, idx: number) => {
          const endpoint = String(item.dohUrl || item.dotHost || item.primaryIp || '');
          const protocol = (item.protocol as DnsProtocol) || detectProtocolFromEndpoint(endpoint);
          const isSub = Boolean(item.isSubscription);
          return createDefaultServerTemplate({
            id: typeof item.id === 'string' ? item.id : `imp_${Date.now()}_${idx}`,
            name: String(item.name || endpoint || `Imported #${idx + 1}`),
            provider: String(item.provider || 'Импорт JSON'),
            protocol,
            primaryIp: String(item.primaryIp || ''),
            secondaryIp: item.secondaryIp ? String(item.secondaryIp) : undefined,
            dohUrl: item.dohUrl ? String(item.dohUrl) : protocol === 'DoH' ? endpoint : undefined,
            dotHost: item.dotHost ? String(item.dotHost) : protocol === 'DoT' ? endpoint.replace(/^tls:\/\//i, '') : undefined,
            smartProxyIp: item.smartProxyIp ? String(item.smartProxyIp) : undefined,
            category: (item.category as DnsCategory) || (isSub ? 'Личные токены' : 'Свои / Найденные'),
            country: String(item.country || 'CUSTOM'),
            tags: Array.isArray(item.tags) ? item.tags.map(String) : ['imported'],
            description: String(item.description || 'Импортировано из JSON'),
            supportsBypass: Boolean(item.supportsBypass ?? true),
            isBuiltin: false,
            isFavorite: Boolean(item.isFavorite ?? false),
            isSubscription: isSub,
            isFreeUnlimited: !isSub,
          });
        });
    } catch {
      // Fall through to CSV / plain-text parser
    }
  }

  const lines = trimmed
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#') && !l.startsWith('//'));

  const results: DnsServer[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip CSV header row
    if (i === 0 && /name|protocol|endpoint|primaryIp/i.test(line) && line.includes(',')) {
      continue;
    }

    // 2. CSV line
    if (line.includes(',') || line.includes(';')) {
      const sep = line.includes(';') ? ';' : ',';
      const cols = line.split(sep).map((c) => c.trim().replace(/^"|"$/g, ''));
      const endpoint = cols.find((c) => c.startsWith('http') || c.startsWith('tls://') || /^\d+\.\d+\.\d+\.\d+/.test(c)) || cols[1] || cols[0];
      const name = cols[0] && cols[0] !== endpoint ? cols[0] : endpoint;
      const protocol = detectProtocolFromEndpoint(endpoint);
      const isBypass = /smart|bypass|proxy|true|1|да/i.test(cols.join(' '));
      results.push(
        createDefaultServerTemplate({
          id: `csv_${Date.now()}_${i}`,
          name,
          provider: cols[2] || 'Импорт CSV',
          protocol,
          primaryIp: /^\d+\.\d+\.\d+\.\d+/.test(endpoint) ? endpoint.split(':')[0] : '',
          dohUrl: protocol === 'DoH' ? endpoint : undefined,
          dotHost: protocol === 'DoT' ? endpoint.replace(/^tls:\/\//i, '') : undefined,
          smartProxyIp: protocol === 'SNI443' ? endpoint.replace(/^smartproxy:\/\//i, '').split(':')[0] : undefined,
          category: 'Свои / Найденные',
          supportsBypass: isBypass || protocol === 'SNI443',
          description: 'Импортировано из CSV',
        })
      );
      continue;
    }

    // 3. Plain-text: "<endpoint> <optional name>" or just "<host/url/ip>"
    const tokens = line.split(/\s+/);
    let rawEndpoint = tokens[0];
    const customName = tokens.slice(1).join(' ').trim();
    const protocol = detectProtocolFromEndpoint(rawEndpoint);

    let dohUrl: string | undefined;
    let dotHost: string | undefined;
    let primaryIp = '';
    let smartProxyIp: string | undefined;

    if (protocol === 'DoH') {
      dohUrl = rawEndpoint;
    } else if (protocol === 'DoT') {
      const host = rawEndpoint.replace(/^tls:\/\//i, '');
      dotHost = host;
      dohUrl = `https://${host}/dns-query`;
    } else if (protocol === 'SNI443') {
      smartProxyIp = rawEndpoint.replace(/^smartproxy:\/\//i, '').split(':')[0];
      primaryIp = smartProxyIp;
    } else {
      primaryIp = rawEndpoint.split(':')[0];
    }

    const displayName =
      customName ||
      (dohUrl ? new URL(dohUrl).hostname : dotHost || primaryIp);

    results.push(
      createDefaultServerTemplate({
        id: `txt_${Date.now()}_${i}`,
        name: displayName,
        provider: 'Импорт списком',
        protocol: dohUrl && !rawEndpoint.startsWith('tls://') ? 'DoH' : protocol,
        primaryIp,
        dohUrl,
        dotHost,
        smartProxyIp,
        category: 'Свои / Найденные',
        supportsBypass: true,
        description: 'Импортировано из текстового списка',
      })
    );
  }

  return results;
}

export function exportServersToCsv(servers: DnsServer[]): string {
  const header = 'name,protocol,primaryIp,dohUrl,dotHost,category,supportsBypass,lastLatencyMs,lastTps,verdict';
  const escape = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = servers.map((s) =>
    [
      s.name,
      s.protocol,
      s.primaryIp,
      s.dohUrl ?? '',
      s.dotHost ?? '',
      s.category,
      s.supportsBypass,
      s.lastLatencyMs ?? '',
      s.lastTps ?? '',
      s.verdict,
    ]
      .map(escape)
      .join(',')
  );
  return [header, ...rows].join('\n');
}
