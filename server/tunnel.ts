import dgram from 'node:dgram';
import { decodeDnsResponse, encodeDnsQuery } from '../src/core/dnsPacket';
import { buildRotationQueue, getNextRotationServerId } from '../src/core/filterSort';
import { DnsServer, TunnelState } from '../src/core/types';
import { dnsDb } from './db';
import { resolveWithServer } from './prober';

const TUNNEL_PORT = 15353;

class LocalTunnelManager {
  private socket: dgram.Socket | null = null;
  private activeServer: DnsServer | null = null;
  private cache = new Map<string, { ips: string[]; expiresAt: number }>();
  private state: TunnelState = {
    active: false,
    serverId: null,
    serverName: null,
    endpoint: null,
    protocol: null,
    targetDomain: 'gemini.google.com',
    listenAddress: `127.0.0.1:${TUNNEL_PORT}`,
    splitRouting: true,
    nrptEnabled: false,
    queriesHandled: 0,
    cacheHits: 0,
    startedAt: null,
    rotationQueueIds: [],
  };

  public getState(): TunnelState {
    return { ...this.state };
  }

  public start(
    serverId: string,
    targetDomain: string,
    options?: { splitRouting?: boolean; nrptEnabled?: boolean }
  ): TunnelState {
    const server = dnsDb.getServerById(serverId);
    if (!server) {
      throw new Error(`DNS сервер ${serverId} не найден`);
    }

    this.activeServer = server;
    this.cache.clear();
    const allServers = dnsDb.getAllServers();
    const queueIds = buildRotationQueue(allServers, server.id);

    this.state = {
      active: true,
      serverId: server.id,
      serverName: server.name,
      endpoint:
        server.dohUrl ||
        server.dotHost ||
        server.smartProxyIp ||
        server.primaryIp ||
        server.name,
      protocol: server.protocol,
      targetDomain: targetDomain || this.state.targetDomain,
      listenAddress: `127.0.0.1:${TUNNEL_PORT}`,
      splitRouting: options?.splitRouting ?? this.state.splitRouting,
      nrptEnabled: options?.nrptEnabled ?? this.state.nrptEnabled,
      queriesHandled: 0,
      cacheHits: 0,
      startedAt: new Date().toISOString(),
      rotationQueueIds: queueIds,
    };

    dnsDb.updateRestoreState({
      capturedAt: new Date().toISOString(),
      activeTunnel: true,
      serverId: server.id,
      endpoint: this.state.endpoint,
      previousSystemDns: ['DHCP'],
    });

    this.ensureUdpListener();
    return this.getState();
  }

  public rotate(): TunnelState {
    if (!this.state.active || this.state.rotationQueueIds.length === 0) {
      const allServers = dnsDb.getAllServers();
      const queue = buildRotationQueue(allServers, this.state.serverId);
      if (queue.length === 0) {
        throw new Error('Нет доступных серверов в очереди ротации');
      }
      return this.start(queue[0], this.state.targetDomain);
    }

    const nextId = getNextRotationServerId(this.state.rotationQueueIds, this.state.serverId);
    if (!nextId) {
      throw new Error('Очередь ротации пуста');
    }

    const prevQueries = this.state.queriesHandled;
    const prevHits = this.state.cacheHits;
    const nextState = this.start(nextId, this.state.targetDomain);
    this.state.queriesHandled = prevQueries;
    this.state.cacheHits = prevHits;
    return { ...nextState, queriesHandled: prevQueries, cacheHits: prevHits };
  }

  public stop(): TunnelState {
    if (this.socket) {
      try {
        this.socket.close();
      } catch {
        // ignore
      }
      this.socket = null;
    }
    this.activeServer = null;
    this.cache.clear();
    this.state = {
      ...this.state,
      active: false,
      serverId: null,
      serverName: null,
      endpoint: null,
      protocol: null,
      startedAt: null,
    };

    dnsDb.updateRestoreState({
      capturedAt: new Date().toISOString(),
      activeTunnel: false,
      restoredAt: new Date().toISOString(),
    });

    return this.getState();
  }

  public async testForwardQuery(domain: string): Promise<{
    domain: string;
    routedVia: 'smart-dns' | 'direct';
    ips: string[];
    cacheHit: boolean;
  }> {
    if (!this.state.active || !this.activeServer) {
      throw new Error('Туннель не запущен');
    }

    this.state.queriesHandled += 1;
    const cleanDomain = domain.trim().toLowerCase();
    const cached = this.cache.get(cleanDomain);
    if (cached && cached.expiresAt > Date.now()) {
      this.state.cacheHits += 1;
      return {
        domain: cleanDomain,
        routedVia: 'smart-dns',
        ips: cached.ips,
        cacheHit: true,
      };
    }

    const bypassHosts = new Set(dnsDb.getCachedHosts().hosts);
    const shouldProxy =
      !this.state.splitRouting ||
      bypassHosts.has(cleanDomain) ||
      Array.from(bypassHosts).some((h) => cleanDomain.endsWith(`.${h}`));

    let ips: string[] = [];
    if (shouldProxy) {
      const res = await resolveWithServer(this.activeServer, cleanDomain, 2500);
      ips = res.ips;
    } else {
      const directServer = dnsDb.getServerById('global_cloudflare_1111') || this.activeServer;
      const res = await resolveWithServer(directServer, cleanDomain, 2500);
      ips = res.ips;
    }

    this.cache.set(cleanDomain, { ips, expiresAt: Date.now() + 60_000 });
    return {
      domain: cleanDomain,
      routedVia: shouldProxy ? 'smart-dns' : 'direct',
      ips,
      cacheHit: false,
    };
  }

  private ensureUdpListener() {
    if (this.socket) return;
    try {
      const sock = dgram.createSocket('udp4');
      sock.on('error', () => {
        this.socket = null;
      });
      sock.on('message', async (msg, rinfo) => {
        if (!this.state.active || !this.activeServer) return;
        try {
          const decoded = decodeDnsResponse(new Uint8Array(msg));
          this.state.queriesHandled += 1;
          const qname = decoded.answers[0]?.name || this.state.targetDomain;
          const res = await this.testForwardQuery(qname);
          const reply = encodeDnsQuery(qname, 1, decoded.id);
          // Echo minimal header with QR=1 so UDP probes get a valid response packet
          reply[2] = 0x81;
          reply[3] = 0x80;
          if (res.ips.length === 0) {
            reply[3] = 0x82; // SERVFAIL
          }
          sock.send(reply, rinfo.port, rinfo.address);
        } catch {
          // ignore malformed packet
        }
      });
      sock.bind(TUNNEL_PORT, '127.0.0.1');
      this.socket = sock;
    } catch {
      this.socket = null;
    }
  }
}

export const tunnelManager = new LocalTunnelManager();
