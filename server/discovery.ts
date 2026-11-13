import {
  createDefaultServerTemplate,
  detectProtocolFromEndpoint,
  parseDynamicBypassHosts,
} from '../src/core/filterSort';
import { DiscoveryNode, DnsServer, SyncStatus } from '../src/core/types';
import { dnsDb } from './db';
import { checkTcpPort443, queryUdp53, runFourStageProbe, runWithConcurrency } from './prober';

const HOST_SOURCES = [
  {
    name: 'Malw.link Hosts',
    url: 'https://dns.malw.link/hosts',
  },
  {
    name: 'GitHub ImMALWARE/dns.malw.link',
    url: 'https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts',
  },
];

const COMMUNITY_DNS_SOURCES = [
  {
    name: 'szanko02/QuickDNS (res/default_profiles.json)',
    url: 'https://raw.githubusercontent.com/szanko02/QuickDNS/main/res/default_profiles.json',
  },
  {
    name: 'szanko02/QuickDNS (default_profiles.json)',
    url: 'https://raw.githubusercontent.com/szanko02/QuickDNS/main/default_profiles.json',
  },
  {
    name: 'neiroseti-ai/hb-ai-xbox-dns',
    url: 'https://raw.githubusercontent.com/neiroseti-ai/hb-ai-xbox-dns/main/README.md',
  },
  {
    name: 'vezlin1/antigravity-bypass-russia',
    url: 'https://raw.githubusercontent.com/vezlin1/antigravity-bypass-russia/main/README.md',
  },
];

async function fetchTextWithTimeout(url: string, timeoutMs = 4500): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'DNS-Pulse-Sync/1.0',
      },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

export async function syncOnlineHostsAndCommunityDns(): Promise<{
  syncStatus: SyncStatus;
  discoveredServers: DnsServer[];
}> {
  const allHosts: string[] = [];
  const sourceReports: SyncStatus['sources'] = [];

  await Promise.all(
    HOST_SOURCES.map(async (src) => {
      try {
        const text = await fetchTextWithTimeout(src.url, 4500);
        const hosts = parseDynamicBypassHosts(text);
        allHosts.push(...hosts);
        sourceReports.push({ name: src.name, url: src.url, count: hosts.length, ok: true });
      } catch (err) {
        sourceReports.push({
          name: src.name,
          url: src.url,
          count: 0,
          ok: false,
          error: err instanceof Error ? err.message : 'Fetch error',
        });
      }
    })
  );

  const discoveredServers: DnsServer[] = [];
  const seenEndpoints = new Set(
    dnsDb
      .getAllServers()
      .flatMap((s) => [s.dohUrl, s.dotHost, s.primaryIp].filter(Boolean) as string[])
  );

  await Promise.all(
    COMMUNITY_DNS_SOURCES.map(async (src) => {
      try {
        const text = await fetchTextWithTimeout(src.url, 4500);
        let foundCount = 0;

        // Extract DoH URLs (skip personal tokens like /kkkrbbawqq2 or long random path tokens)
        const dohMatches = text.match(/https:\/\/[a-z0-9.-]+\/dns-query/gi) ?? [];
        for (const url of dohMatches) {
          if (seenEndpoints.has(url)) continue;
          seenEndpoints.add(url);
          foundCount++;
          const host = new URL(url).hostname;
          discoveredServers.push(
            createDefaultServerTemplate({
              id: `comm_${host.replace(/[^a-z0-9]/gi, '_')}`,
              name: `${host} (Community)`,
              provider: src.name.split(' ')[0],
              protocol: 'DoH',
              dohUrl: url,
              dotHost: host,
              category: 'Свои / Найденные',
              supportsBypass: true,
              description: `Найдено в ${src.name}`,
            })
          );
        }

        // Parse JSON profiles if QuickDNS JSON
        if (src.url.endsWith('.json') && text.trim().startsWith('{') || text.trim().startsWith('[')) {
          try {
            const parsed = JSON.parse(text);
            const items = Array.isArray(parsed) ? parsed : Object.values(parsed).flat();
            for (const item of items) {
              if (!item || typeof item !== 'object') continue;
              const obj = item as Record<string, unknown>;
              const endpoint = String(obj.doh || obj.url || obj.ip || obj.primary || '');
              if (!endpoint || seenEndpoints.has(endpoint)) continue;
              if (endpoint.includes('kkkrbbawqq2')) continue;
              seenEndpoints.add(endpoint);
              foundCount++;
              const proto = detectProtocolFromEndpoint(endpoint);
              discoveredServers.push(
                createDefaultServerTemplate({
                  id: `comm_${Buffer.from(endpoint).toString('hex').slice(0, 12)}`,
                  name: String(obj.name || endpoint),
                  provider: 'QuickDNS Community',
                  protocol: proto,
                  primaryIp: proto === 'UDP' ? endpoint : '',
                  dohUrl: proto === 'DoH' ? endpoint : undefined,
                  dotHost: proto === 'DoT' ? endpoint.replace(/^tls:\/\//i, '') : undefined,
                  category: 'Свои / Найденные',
                  supportsBypass: true,
                  description: `Профиль из ${src.name}`,
                })
              );
            }
          } catch {
            // Not JSON
          }
        }

        sourceReports.push({ name: src.name, url: src.url, count: foundCount, ok: true });
      } catch (err) {
        sourceReports.push({
          name: src.name,
          url: src.url,
          count: 0,
          ok: false,
          error: err instanceof Error ? err.message : 'Fetch error',
        });
      }
    })
  );

  if (discoveredServers.length > 0) {
    dnsDb.upsertServers(discoveredServers);
  }

  const syncStatus: SyncStatus = {
    cachedHostsCount: allHosts.length,
    lastSyncAt: new Date().toISOString(),
    sources: sourceReports,
  };
  dnsDb.saveCachedHosts(allHosts, syncStatus);

  return {
    syncStatus: dnsDb.getCachedHosts().syncStatus,
    discoveredServers,
  };
}

export async function runParserAndBypassCheck(
  targetDomain: string,
  requiresBypass: boolean
): Promise<{
  syncStatus: SyncStatus;
  liveNodes: DiscoveryNode[];
}> {
  const { syncStatus } = await syncOnlineHostsAndCommunityDns();
  const candidates = dnsDb
    .getAllServers()
    .filter((s) => s.supportsBypass && !s.isSubscription)
    .slice(0, 24);

  const probeResults = await runWithConcurrency(candidates, 6, async (srv) => {
    const res = await runFourStageProbe(srv, targetDomain, requiresBypass);
    dnsDb.saveProbeResult(res);
    return { srv, res };
  });

  const liveNodes: DiscoveryNode[] = probeResults
    .filter(({ res }) => res.verdict === 'VERIFIED_PROXY_OK' || res.latencyMs !== null)
    .sort((a, b) => {
      if (a.res.verdict === 'VERIFIED_PROXY_OK' && b.res.verdict !== 'VERIFIED_PROXY_OK') return -1;
      if (b.res.verdict === 'VERIFIED_PROXY_OK' && a.res.verdict !== 'VERIFIED_PROXY_OK') return 1;
      return (a.res.latencyMs ?? 9999) - (b.res.latencyMs ?? 9999);
    })
    .map(({ srv, res }) => ({
      id: srv.id,
      ipOrEndpoint: srv.dohUrl || srv.smartProxyIp || srv.primaryIp || srv.dotHost || srv.name,
      name: srv.name,
      protocol: srv.protocol,
      latencyMs: res.latencyMs ?? 0,
      verdict: res.verdict,
      verdictReason: res.verdictReason,
      port443Ok: Boolean(res.port443Ok),
      savedToDb: true,
    }));

  return { syncStatus, liveNodes };
}

function expandSubnetTargets(subnetInput: string): string[] {
  const clean = subnetInput.trim();
  if (!clean || clean.toUpperCase() === 'AUTO') {
    // Verified Smart-DNS & GeoHide prefix seeds (targeted IPs around known relays + nearby neighbors)
    const autoTargets = [
      '192.255.159.240',
      '192.255.159.241',
      '192.255.159.242',
      '192.3.233.253',
      '107.175.76.134',
      '5.175.161.40',
      '5.175.161.3',
      '143.20.64.192',
      '37.221.93.141',
      '179.254.166.171',
      '164.5.224.81',
      '83.220.169.155',
      '212.109.195.93',
      '212.109.221.20',
      '176.99.11.77',
      '80.78.247.254',
      '185.236.104.104',
      '135.106.217.200',
      '83.217.211.149',
      '1.1.1.1',
      '8.8.8.8',
      '9.9.9.9',
      '94.140.14.14',
      '77.88.8.8',
    ];
    return autoTargets;
  }

  // Single IP
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
    return [clean];
  }

  // CIDR /24
  const cidrMatch = clean.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\/24$/);
  if (cidrMatch) {
    const prefix = cidrMatch[1];
    const ips: string[] = [];
    for (let host = 1; host <= 254; host++) {
      ips.push(`${prefix}.${host}`);
    }
    return ips;
  }

  throw new Error('Укажите AUTO, одиночный IP или подсеть вида X.Y.Z.0/24');
}

export async function scanSubnetNodes(params: {
  subnet: string;
  targetDomain: string;
  requiresBypass: boolean;
  scanUdp53: boolean;
  checkPort443: boolean;
}): Promise<{
  scannedCount: number;
  foundNodes: DiscoveryNode[];
}> {
  const ips = expandSubnetTargets(params.subnet);
  const foundNodes: DiscoveryNode[] = [];
  const toSave: DnsServer[] = [];

  await runWithConcurrency(ips, 24, async (ip) => {
    let udpMs: number | null = null;
    let tcp443Ms: number | null = null;
    let resolvedIps: string[] = [];

    if (params.scanUdp53) {
      try {
        const res = await queryUdp53(ip, params.targetDomain, 1100);
        udpMs = res.latencyMs;
        resolvedIps = res.ips;
      } catch {
        // UDP 53 closed/timeout
      }
    }

    if (params.checkPort443) {
      try {
        tcp443Ms = await checkTcpPort443(ip, 1100);
      } catch {
        // 443 closed/timeout
      }
    }

    if (udpMs === null && tcp443Ms === null) return;

    const tempServer = createDefaultServerTemplate({
      id: `scan_${ip.replace(/\./g, '_')}`,
      name: `Узел ${ip}`,
      provider: 'Сканер подсетей',
      protocol: udpMs !== null ? 'UDP' : 'SNI443',
      primaryIp: ip,
      smartProxyIp: tcp443Ms !== null ? ip : undefined,
      port: tcp443Ms !== null ? 443 : 53,
      category: 'Свои / Найденные',
      supportsBypass: tcp443Ms !== null,
      description: `Найден сканером (${params.subnet})`,
    });

    const probe = await runFourStageProbe(tempServer, params.targetDomain, params.requiresBypass);
    const latency = probe.latencyMs ?? udpMs ?? tcp443Ms ?? 0;

    tempServer.lastLatencyMs = latency;
    tempServer.minLatencyMs = probe.minLatencyMs ?? latency;
    tempServer.avgLatencyMs = probe.avgLatencyMs ?? latency;
    tempServer.jitterMs = probe.jitterMs ?? 0;
    tempServer.lastTps = probe.tps ?? 1;
    tempServer.verdict = probe.verdict;
    tempServer.verdictReason = probe.verdictReason;
    tempServer.resolvedIps = probe.resolvedIps.length > 0 ? probe.resolvedIps : resolvedIps;
    tempServer.port443Ok = probe.port443Ok ?? (tcp443Ms !== null);
    tempServer.httpStatus = probe.httpStatus;
    tempServer.lastCheckedDomain = params.targetDomain;
    tempServer.lastCheckedAt = probe.checkedAt;
    tempServer.historyMs = [Math.round(latency)];

    toSave.push(tempServer);
    foundNodes.push({
      id: tempServer.id,
      ipOrEndpoint: ip,
      name: tempServer.name,
      protocol: tempServer.protocol,
      latencyMs: Math.round(latency),
      verdict: probe.verdict,
      verdictReason: probe.verdictReason,
      port443Ok: Boolean(tempServer.port443Ok),
      savedToDb: true,
    });
  });

  if (toSave.length > 0) {
    dnsDb.upsertServers(toSave);
  }

  foundNodes.sort((a, b) => a.latencyMs - b.latencyMs);
  return {
    scannedCount: ips.length,
    foundNodes,
  };
}
