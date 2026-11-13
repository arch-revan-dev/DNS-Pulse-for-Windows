import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import {
  classifyFourStageVerdict,
  isBogonOrLoopbackIp,
  isDirectServiceIp,
} from '../src/core/antiDirectIp';
import { decodeDnsResponse, encodeDnsQuery, toBase64Url } from '../src/core/dnsPacket';
import { getCompanionDomainsForHost } from '../src/core/presets';
import { DnsServer, ProbeResult } from '../src/core/types';

const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36';

export async function queryUdp53(
  serverIp: string,
  domain: string,
  timeoutMs = 2600
): Promise<{ ips: string[]; latencyMs: number }> {
  const start = performance.now();
  const queryPacket = encodeDnsQuery(domain, 1);

  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          socket.close();
        } catch {
          // ignore
        }
        reject(new Error(`UDP 53 timeout (${serverIp})`));
      }
    }, timeoutMs);

    socket.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        try {
          socket.close();
        } catch {
          // ignore
        }
        reject(err);
      }
    });

    socket.on('message', (msg) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        const elapsed = Math.max(1, Math.round(performance.now() - start));
        try {
          socket.close();
        } catch {
          // ignore
        }
        try {
          const decoded = decodeDnsResponse(new Uint8Array(msg));
          resolve({ ips: decoded.ips, latencyMs: elapsed });
        } catch (err) {
          reject(err);
        }
      }
    });

    socket.send(queryPacket, 53, serverIp, (err) => {
      if (err && !settled) {
        settled = true;
        clearTimeout(timer);
        try {
          socket.close();
        } catch {
          // ignore
        }
        reject(err);
      }
    });
  });
}

export async function queryDoH(
  dohUrl: string,
  domain: string,
  timeoutMs = 3200
): Promise<{ ips: string[]; latencyMs: number }> {
  const queryPacket = encodeDnsQuery(domain, 1);
  const start = performance.now();

  const tryPost = async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(dohUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          Accept: 'application/dns-message',
          'User-Agent': BROWSER_UA,
        },
        body: Buffer.from(queryPacket),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = new Uint8Array(await res.arrayBuffer());
      const decoded = decodeDnsResponse(buf);
      return decoded.ips;
    } finally {
      clearTimeout(timer);
    }
  };

  const tryGetFallback = async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const sep = dohUrl.includes('?') ? '&' : '?';
      const url = `${dohUrl}${sep}dns=${toBase64Url(queryPacket)}`;
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          Accept: 'application/dns-message',
          'User-Agent': BROWSER_UA,
        },
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP GET ${res.status}`);
      const buf = new Uint8Array(await res.arrayBuffer());
      const decoded = decodeDnsResponse(buf);
      return decoded.ips;
    } finally {
      clearTimeout(timer);
    }
  };

  let ips: string[];
  try {
    ips = await tryPost();
  } catch {
    ips = await tryGetFallback();
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - start));
  return { ips, latencyMs };
}

export async function queryDoT(
  dotHost: string,
  fallbackIp: string,
  domain: string,
  timeoutMs = 3200
): Promise<{ ips: string[]; latencyMs: number }> {
  const start = performance.now();
  const queryPacket = encodeDnsQuery(domain, 1);
  const frame = Buffer.alloc(2 + queryPacket.length);
  frame.writeUInt16BE(queryPacket.length, 0);
  Buffer.from(queryPacket).copy(frame, 2);

  const connectTarget = dotHost || fallbackIp;

  return new Promise((resolve, reject) => {
    let settled = false;
    const chunks: Buffer[] = [];
    let expectedLen = -1;

    const socket = tls.connect(
      {
        host: connectTarget,
        port: 853,
        servername: dotHost || undefined,
        timeout: timeoutMs,
      },
      () => {
        socket.write(frame);
      }
    );

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`DoT 853 timeout (${connectTarget})`));
      }
    }, timeoutMs);

    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const joined = Buffer.concat(chunks);
      if (expectedLen === -1 && joined.length >= 2) {
        expectedLen = joined.readUInt16BE(0);
      }
      if (expectedLen > 0 && joined.length >= 2 + expectedLen && !settled) {
        settled = true;
        clearTimeout(timer);
        socket.end();
        const elapsed = Math.max(1, Math.round(performance.now() - start));
        try {
          const msg = joined.subarray(2, 2 + expectedLen);
          const decoded = decodeDnsResponse(new Uint8Array(msg));
          resolve({ ips: decoded.ips, latencyMs: elapsed });
        } catch (err) {
          reject(err);
        }
      }
    });

    socket.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(err);
      }
    });
  });
}

export async function resolveWithServer(
  server: DnsServer,
  domain: string,
  timeoutMs = 2800
): Promise<{ ips: string[]; latencyMs: number }> {
  if (server.protocol === 'SNI443') {
    const proxyIp = server.smartProxyIp || server.primaryIp;
    if (!proxyIp) throw new Error('No SNI proxy IP configured');
    const start = performance.now();
    await checkTcpPort443(proxyIp, timeoutMs);
    return {
      ips: [proxyIp],
      latencyMs: Math.max(1, Math.round(performance.now() - start)),
    };
  }

  if (server.protocol === 'DoH' && server.dohUrl) {
    try {
      return await queryDoH(server.dohUrl, domain, timeoutMs);
    } catch (err) {
      if (server.primaryIp) {
        return await queryUdp53(server.primaryIp, domain, timeoutMs);
      }
      throw err;
    }
  }

  if (server.protocol === 'DoT' && (server.dotHost || server.primaryIp)) {
    try {
      return await queryDoT(server.dotHost || '', server.primaryIp, domain, timeoutMs);
    } catch (err) {
      if (server.dohUrl) return await queryDoH(server.dohUrl, domain, timeoutMs);
      if (server.primaryIp) return await queryUdp53(server.primaryIp, domain, timeoutMs);
      throw err;
    }
  }

  if (server.primaryIp) {
    return await queryUdp53(server.primaryIp, domain, timeoutMs);
  }

  if (server.dohUrl) {
    return await queryDoH(server.dohUrl, domain, timeoutMs);
  }

  throw new Error('Server has no IP, DoH URL, or DoT host');
}

export async function checkTcpPort443(ip: string, timeoutMs = 2200): Promise<number> {
  const start = performance.now();
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: ip, port: 443 });
    let done = false;
    sock.setTimeout(timeoutMs);

    sock.on('connect', () => {
      if (!done) {
        done = true;
        const ms = Math.max(1, Math.round(performance.now() - start));
        sock.destroy();
        resolve(ms);
      }
    });

    sock.on('timeout', () => {
      if (!done) {
        done = true;
        sock.destroy();
        reject(new Error(`TCP 443 timeout (${ip})`));
      }
    });

    sock.on('error', (err) => {
      if (!done) {
        done = true;
        sock.destroy();
        reject(err);
      }
    });
  });
}

/**
 * Stage 4: Real TCP 443 + TLS SNI + HTTP HEAD/GET (no auto-redirect)
 * to detect /docs/available-regions, /sorry/index, 403/451/502/504, or valid 200/3xx service responses.
 */
export async function probeTlsHttpSni443(
  targetIp: string,
  sniDomain: string,
  timeoutMs = 3200
): Promise<{
  port443Ok: boolean;
  httpStatus: number | null;
  redirectLocation: string | null;
}> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (port443Ok: boolean, httpStatus: number | null, redirectLocation: string | null) => {
      if (!settled) {
        settled = true;
        resolve({ port443Ok, httpStatus, redirectLocation });
      }
    };

    const rawSocket = net.connect({ host: targetIp, port: 443 });
    rawSocket.setTimeout(timeoutMs);

    rawSocket.on('timeout', () => {
      rawSocket.destroy();
      finish(false, null, null);
    });

    rawSocket.on('error', () => {
      rawSocket.destroy();
      finish(false, null, null);
    });

    rawSocket.on('connect', () => {
      const tlsSock = tls.connect(
        {
          socket: rawSocket,
          servername: sniDomain,
          rejectUnauthorized: false,
          ALPNProtocols: ['http/1.1'],
        },
        () => {
          const req =
            `HEAD / HTTP/1.1\r\n` +
            `Host: ${sniDomain}\r\n` +
            `User-Agent: ${BROWSER_UA}\r\n` +
            `Accept: text/html,*/*\r\n` +
            `Connection: close\r\n\r\n`;
          tlsSock.write(req);
        }
      );

      tlsSock.setTimeout(timeoutMs);
      let rawResponse = '';

      tlsSock.on('data', (chunk) => {
        rawResponse += chunk.toString('utf8');
        if (rawResponse.includes('\r\n\r\n') || rawResponse.length > 4096) {
          tlsSock.destroy();
          const statusMatch = rawResponse.match(/^HTTP\/\d\.\d\s+(\d{3})/i);
          const locMatch = rawResponse.match(/\r\nlocation:\s*([^\r\n]+)/i);
          const status = statusMatch ? Number(statusMatch[1]) : 200;
          const location = locMatch ? locMatch[1].trim() : null;
          finish(true, status, location);
        }
      });

      tlsSock.on('end', () => {
        const statusMatch = rawResponse.match(/^HTTP\/\d\.\d\s+(\d{3})/i);
        const locMatch = rawResponse.match(/\r\nlocation:\s*([^\r\n]+)/i);
        const status = statusMatch ? Number(statusMatch[1]) : null;
        const location = locMatch ? locMatch[1].trim() : null;
        finish(status !== null, status, location);
      });

      tlsSock.on('timeout', () => {
        tlsSock.destroy();
        finish(false, null, null);
      });

      tlsSock.on('error', () => {
        tlsSock.destroy();
        finish(false, null, null);
      });
    });
  });
}

/**
 * Full 4-Stage Anti-False-Positive DNS + Bypass Verification Engine
 */
export async function runFourStageProbe(
  server: DnsServer,
  targetDomain: string,
  requiresBypass: boolean
): Promise<ProbeResult> {
  const checkedAt = new Date().toISOString();

  // Stage 1: 2 sequential queries + 2 concurrent burst queries to calculate min/avg/current/jitter/TPS
  const latencies: number[] = [];
  let primaryIps: string[] = [];
  let timedOut = false;

  try {
    const r1 = await resolveWithServer(server, targetDomain, 2800);
    latencies.push(r1.latencyMs);
    primaryIps = r1.ips;

    const r2 = await resolveWithServer(server, targetDomain, 2600);
    latencies.push(r2.latencyMs);
    if (primaryIps.length === 0) primaryIps = r2.ips;

    // Parallel burst for realistic TPS
    const burstStart = performance.now();
    const burst = await Promise.allSettled([
      resolveWithServer(server, targetDomain, 2500),
      resolveWithServer(server, targetDomain, 2500),
    ]);
    const burstElapsedSec = Math.max(0.015, (performance.now() - burstStart) / 1000);
    let burstOk = 0;
    for (const item of burst) {
      if (item.status === 'fulfilled') {
        burstOk++;
        latencies.push(item.value.latencyMs);
      }
    }

    const minMs = Math.min(...latencies);
    const avgMs = Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length);
    const currentMs = latencies[latencies.length - 1];
    const maxDiff = Math.max(...latencies.map((v) => Math.abs(v - avgMs)));
    const tps = Number(((burstOk > 0 ? burstOk : 1) / burstElapsedSec).toFixed(1));

    // Stage 2: Bogon + Anti-Direct-IP
    const validIps = primaryIps.filter((ip) => !isBogonOrLoopbackIp(ip));
    const allDirect =
      requiresBypass &&
      validIps.length > 0 &&
      validIps.every((ip) => isDirectServiceIp(ip, targetDomain));

    // Stage 3: Companion API domains check (critical for AI Studio / Gemini / Spotify / Xbox)
    const companionDomains = requiresBypass ? getCompanionDomainsForHost(targetDomain) : [];
    const companionDetails: Array<{ domain: string; ips: string[]; isDirect: boolean }> = [];
    let companionPassed: boolean | null = companionDomains.length > 0 ? true : null;

    if (requiresBypass && companionDomains.length > 0 && validIps.length > 0 && !allDirect) {
      const compResults = await Promise.allSettled(
        companionDomains.map(async (cDomain) => {
          const res = await resolveWithServer(server, cDomain, 2400);
          const cValid = res.ips.filter((ip) => !isBogonOrLoopbackIp(ip));
          const isDir = cValid.length > 0 && cValid.every((ip) => isDirectServiceIp(ip, cDomain));
          return { domain: cDomain, ips: res.ips, isDirect: isDir };
        })
      );

      for (const cr of compResults) {
        if (cr.status === 'fulfilled') {
          companionDetails.push(cr.value);
          if (cr.value.isDirect || cr.value.ips.length === 0) {
            companionPassed = false;
          }
        } else {
          companionPassed = false;
        }
      }
    }

    // Stage 4: Real TCP 443 + TLS SNI + HTTP redirect check on returned proxy IP
    let port443Ok: boolean | null = null;
    let httpStatus: number | null = null;
    let redirectLocation: string | null = null;

    if (validIps.length > 0 && !allDirect) {
      const sniProbe = await probeTlsHttpSni443(validIps[0], targetDomain, 3200);
      port443Ok = sniProbe.port443Ok;
      httpStatus = sniProbe.httpStatus;
      redirectLocation = sniProbe.redirectLocation;
    }

    const { verdict, reason } = classifyFourStageVerdict({
      requiresBypass,
      resolvedIps: primaryIps,
      companionPassed,
      port443Ok,
      httpStatus,
      redirectLocation,
      targetDomain,
      timedOut: false,
    });

    return {
      serverId: server.id,
      targetDomain,
      requiresBypass,
      latencyMs: currentMs,
      minLatencyMs: minMs,
      avgLatencyMs: avgMs,
      jitterMs: maxDiff,
      tps,
      resolvedIps: primaryIps,
      verdict,
      verdictReason: reason,
      companionPassed,
      companionDetails,
      port443Ok,
      httpStatus,
      redirectLocation,
      checkedAt,
    };
  } catch {
    timedOut = true;
    const { verdict, reason } = classifyFourStageVerdict({
      requiresBypass,
      resolvedIps: [],
      companionPassed: null,
      port443Ok: null,
      httpStatus: null,
      redirectLocation: null,
      targetDomain,
      timedOut,
    });

    return {
      serverId: server.id,
      targetDomain,
      requiresBypass,
      latencyMs: null,
      minLatencyMs: null,
      avgLatencyMs: null,
      jitterMs: null,
      tps: 0,
      resolvedIps: [],
      verdict,
      verdictReason: reason,
      companionPassed: null,
      companionDetails: [],
      port443Ok: null,
      httpStatus: null,
      redirectLocation: null,
      checkedAt,
    };
  }
}

export async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;

  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const idx = cursor++;
      if (idx >= items.length) break;
      results[idx] = await worker(items[idx]);
    }
  });

  await Promise.all(runners);
  return results;
}
