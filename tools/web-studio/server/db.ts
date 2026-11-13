import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { buildFullBuiltinCatalog } from '../src/core/catalogSeed';
import { DnsServer, ProbeResult, SyncStatus } from '../src/core/types';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_PATH = path.join(DATA_DIR, 'dns_pulse.db');
const VAULT_PATH = path.join(DATA_DIR, 'custom_dns_vault.json');
const HOSTS_CACHE_PATH = path.join(DATA_DIR, 'dynamic_bypass_domains_cache.json');
const RESTORE_STATE_PATH = path.join(DATA_DIR, 'restore_network_state.json');
const SETTINGS_PATH = path.join(DATA_DIR, 'app_settings.json');
const REPO_ROOT_TSV_PATH = path.resolve(process.cwd(), '../../assets/dns_catalog_1000.tsv');
const LOCAL_TSV_PATH = path.resolve(process.cwd(), 'assets/dns_catalog_1000.tsv');
const TSV_PATH = fs.existsSync(REPO_ROOT_TSV_PATH) ? REPO_ROOT_TSV_PATH : LOCAL_TSV_PATH;

export interface AppSettings {
  theme: 'dark' | 'light';
  autoConnectBestOnRotate: boolean;
  freeOnly: boolean;
  hotkeyRotate: string;
}

const DEFAULT_SETTINGS: AppSettings = {
  theme: 'dark',
  autoConnectBestOnRotate: true,
  freeOnly: false,
  hotkeyRotate: 'Ctrl+Alt+R',
};

const DEFAULT_BYPASS_DOMAINS = [
  'gemini.google.com',
  'aistudio.google.com',
  'alkalimakersuite-pa.clients6.google.com',
  'generativelanguage.googleapis.com',
  'makersuite.google.com',
  'chatgpt.com',
  'api.openai.com',
  'auth.openai.com',
  'claude.ai',
  'api.anthropic.com',
  'copilot.microsoft.com',
  'open.spotify.com',
  'spclient.wg.spotify.com',
  'apresolve.spotify.com',
  'xboxlive.com',
  'user.auth.xboxlive.com',
  'xsts.auth.xboxlive.com',
  'brawlstars.com',
  'play.geforcenow.com',
];

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function rowToServer(row: Record<string, unknown>): DnsServer {
  return {
    id: String(row.id),
    name: String(row.name),
    provider: String(row.provider),
    protocol: row.protocol as DnsServer['protocol'],
    primaryIp: String(row.primaryIp || ''),
    secondaryIp: row.secondaryIp ? String(row.secondaryIp) : undefined,
    dohUrl: row.dohUrl ? String(row.dohUrl) : undefined,
    dotHost: row.dotHost ? String(row.dotHost) : undefined,
    smartProxyIp: row.smartProxyIp ? String(row.smartProxyIp) : undefined,
    port: row.port !== null && row.port !== undefined ? Number(row.port) : undefined,
    category: row.category as DnsServer['category'],
    country: String(row.country || 'GLOBAL'),
    tags: JSON.parse(String(row.tagsJson || '[]')),
    description: String(row.description || ''),
    supportsBypass: Boolean(row.supportsBypass),
    isBuiltin: Boolean(row.isBuiltin),
    isFavorite: Boolean(row.isFavorite),
    isSubscription: Boolean(row.isSubscription),
    isFreeUnlimited: Boolean(row.isFreeUnlimited),
    lastLatencyMs: row.lastLatencyMs !== null ? Number(row.lastLatencyMs) : null,
    minLatencyMs: row.minLatencyMs !== null ? Number(row.minLatencyMs) : null,
    avgLatencyMs: row.avgLatencyMs !== null ? Number(row.avgLatencyMs) : null,
    jitterMs: row.jitterMs !== null ? Number(row.jitterMs) : null,
    lastTps: row.lastTps !== null ? Number(row.lastTps) : null,
    verdict: (row.verdict as DnsServer['verdict']) || 'UNCHECKED',
    verdictReason: String(row.verdictReason || 'Не проверялся'),
    resolvedIps: JSON.parse(String(row.resolvedIpsJson || '[]')),
    companionPassed:
      row.companionPassed === null || row.companionPassed === undefined
        ? null
        : Boolean(row.companionPassed),
    port443Ok:
      row.port443Ok === null || row.port443Ok === undefined
        ? null
        : Boolean(row.port443Ok),
    httpStatus: row.httpStatus !== null && row.httpStatus !== undefined ? Number(row.httpStatus) : null,
    lastCheckedDomain: row.lastCheckedDomain ? String(row.lastCheckedDomain) : null,
    lastCheckedAt: row.lastCheckedAt ? String(row.lastCheckedAt) : null,
    historyMs: JSON.parse(String(row.historyMsJson || '[]')),
  };
}

class DnsDatabase {
  private db: DatabaseSync;

  constructor() {
    ensureDataDir();
    this.db = new DatabaseSync(DB_PATH);
    this.initSchema();
    this.seedBuiltinsIfMissing();
    this.restoreFromVaultIfNeeded();
    this.ensureDefaultHostsCache();
    this.ensureRestoreStatePlaceholder();
  }

  private initSchema() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS dns_servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        provider TEXT NOT NULL,
        protocol TEXT NOT NULL,
        primaryIp TEXT NOT NULL DEFAULT '',
        secondaryIp TEXT,
        dohUrl TEXT,
        dotHost TEXT,
        smartProxyIp TEXT,
        port INTEGER,
        category TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT 'GLOBAL',
        tagsJson TEXT NOT NULL DEFAULT '[]',
        description TEXT NOT NULL DEFAULT '',
        supportsBypass INTEGER NOT NULL DEFAULT 0,
        isBuiltin INTEGER NOT NULL DEFAULT 0,
        isFavorite INTEGER NOT NULL DEFAULT 0,
        isSubscription INTEGER NOT NULL DEFAULT 0,
        isFreeUnlimited INTEGER NOT NULL DEFAULT 1,
        lastLatencyMs REAL,
        minLatencyMs REAL,
        avgLatencyMs REAL,
        jitterMs REAL,
        lastTps REAL,
        verdict TEXT NOT NULL DEFAULT 'UNCHECKED',
        verdictReason TEXT NOT NULL DEFAULT 'Не проверялся',
        resolvedIpsJson TEXT NOT NULL DEFAULT '[]',
        companionPassed INTEGER,
        port443Ok INTEGER,
        httpStatus INTEGER,
        lastCheckedDomain TEXT,
        lastCheckedAt TEXT,
        historyMsJson TEXT NOT NULL DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_dns_category ON dns_servers(category);
      CREATE INDEX IF NOT EXISTS idx_dns_latency ON dns_servers(lastLatencyMs);
    `);
  }

  private getInsertOrIgnoreStmt() {
    return this.db.prepare(`
      INSERT OR IGNORE INTO dns_servers (
        id, name, provider, protocol, primaryIp, secondaryIp, dohUrl, dotHost,
        smartProxyIp, port, category, country, tagsJson, description,
        supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited,
        lastLatencyMs, minLatencyMs, avgLatencyMs, jitterMs, lastTps,
        verdict, verdictReason, resolvedIpsJson, companionPassed, port443Ok,
        httpStatus, lastCheckedDomain, lastCheckedAt, historyMsJson
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `);
  }

  public seedBuiltinsIfMissing(): { added: number; total: number } {
    const tsvText = fs.existsSync(TSV_PATH) ? fs.readFileSync(TSV_PATH, 'utf8') : '';
    const builtins = buildFullBuiltinCatalog(tsvText);
    const stmt = this.getInsertOrIgnoreStmt();
    let added = 0;

    this.db.exec('BEGIN');
    try {
      for (const s of builtins) {
        const res = stmt.run(
          s.id,
          s.name,
          s.provider,
          s.protocol,
          s.primaryIp,
          s.secondaryIp ?? null,
          s.dohUrl ?? null,
          s.dotHost ?? null,
          s.smartProxyIp ?? null,
          s.port ?? null,
          s.category,
          s.country,
          JSON.stringify(s.tags),
          s.description,
          s.supportsBypass ? 1 : 0,
          1,
          0, // NEVER pre-star
          0, // NEVER subscription token
          1,
          s.lastLatencyMs,
          s.minLatencyMs,
          s.avgLatencyMs,
          s.jitterMs,
          s.lastTps,
          s.verdict,
          s.verdictReason,
          JSON.stringify(s.resolvedIps),
          null,
          null,
          null,
          null,
          null,
          '[]'
        );
        if (Number(res.changes) > 0) added++;
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    const total = this.getCount();
    return { added, total };
  }

  private restoreFromVaultIfNeeded() {
    if (!fs.existsSync(VAULT_PATH)) return;
    try {
      const raw = fs.readFileSync(VAULT_PATH, 'utf8');
      const vaultServers = JSON.parse(raw) as DnsServer[];
      if (Array.isArray(vaultServers) && vaultServers.length > 0) {
        this.upsertServers(vaultServers);
      }
    } catch {
      // Ignore corrupt backup vault
    }
  }

  private syncVault() {
    const customServers = this.getAllServers().filter((s) => !s.isBuiltin || s.isFavorite);
    fs.writeFileSync(VAULT_PATH, JSON.stringify(customServers, null, 2), 'utf8');
  }

  private ensureDefaultHostsCache() {
    if (!fs.existsSync(HOSTS_CACHE_PATH)) {
      const payload = {
        hosts: DEFAULT_BYPASS_DOMAINS,
        lastSyncAt: null,
        sources: [],
      };
      fs.writeFileSync(HOSTS_CACHE_PATH, JSON.stringify(payload, null, 2), 'utf8');
    }
  }

  private ensureRestoreStatePlaceholder() {
    if (!fs.existsSync(RESTORE_STATE_PATH)) {
      fs.writeFileSync(
        RESTORE_STATE_PATH,
        JSON.stringify(
          {
            capturedAt: null,
            adapters: [],
            activeTunnel: false,
          },
          null,
          2
        ),
        'utf8'
      );
    }
  }

  public getCount(): number {
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM dns_servers').get() as { cnt: number };
    return Number(row.cnt);
  }

  /**
   * Notice: NO hardcoded `ORDER BY isFavorite DESC` in SQL!
   * Sorting is handled cleanly by filterSort.ts or explicit query parameters.
   */
  public getAllServers(): DnsServer[] {
    const rows = this.db.prepare('SELECT * FROM dns_servers').all() as Array<Record<string, unknown>>;
    return rows.map(rowToServer);
  }

  public getServerById(id: string): DnsServer | null {
    const row = this.db.prepare('SELECT * FROM dns_servers WHERE id = ?').get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToServer(row) : null;
  }

  public upsertServers(servers: DnsServer[]): number {
    const stmt = this.db.prepare(`
      INSERT INTO dns_servers (
        id, name, provider, protocol, primaryIp, secondaryIp, dohUrl, dotHost,
        smartProxyIp, port, category, country, tagsJson, description,
        supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited,
        lastLatencyMs, minLatencyMs, avgLatencyMs, jitterMs, lastTps,
        verdict, verdictReason, resolvedIpsJson, companionPassed, port443Ok,
        httpStatus, lastCheckedDomain, lastCheckedAt, historyMsJson
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?
      )
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        provider = excluded.provider,
        protocol = excluded.protocol,
        primaryIp = excluded.primaryIp,
        secondaryIp = excluded.secondaryIp,
        dohUrl = excluded.dohUrl,
        dotHost = excluded.dotHost,
        smartProxyIp = excluded.smartProxyIp,
        port = excluded.port,
        category = excluded.category,
        country = excluded.country,
        tagsJson = excluded.tagsJson,
        description = excluded.description,
        supportsBypass = excluded.supportsBypass,
        isFavorite = excluded.isFavorite,
        isSubscription = excluded.isSubscription,
        isFreeUnlimited = excluded.isFreeUnlimited
    `);

    this.db.exec('BEGIN');
    try {
      for (const s of servers) {
        stmt.run(
          s.id,
          s.name,
          s.provider,
          s.protocol,
          s.primaryIp || '',
          s.secondaryIp ?? null,
          s.dohUrl ?? null,
          s.dotHost ?? null,
          s.smartProxyIp ?? null,
          s.port ?? null,
          s.category,
          s.country,
          JSON.stringify(s.tags || []),
          s.description || '',
          s.supportsBypass ? 1 : 0,
          s.isBuiltin ? 1 : 0,
          s.isFavorite ? 1 : 0,
          s.isSubscription ? 1 : 0,
          s.isFreeUnlimited ? 1 : 0,
          s.lastLatencyMs,
          s.minLatencyMs,
          s.avgLatencyMs,
          s.jitterMs,
          s.lastTps,
          s.verdict,
          s.verdictReason,
          JSON.stringify(s.resolvedIps || []),
          s.companionPassed === null ? null : s.companionPassed ? 1 : 0,
          s.port443Ok === null ? null : s.port443Ok ? 1 : 0,
          s.httpStatus,
          s.lastCheckedDomain,
          s.lastCheckedAt,
          JSON.stringify(s.historyMs || [])
        );
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.syncVault();
    return servers.length;
  }

  public toggleFavorite(id: string): DnsServer | null {
    const existing = this.getServerById(id);
    if (!existing) return null;
    const nextFav = !existing.isFavorite;
    this.db
      .prepare('UPDATE dns_servers SET isFavorite = ? WHERE id = ?')
      .run(nextFav ? 1 : 0, id);
    this.syncVault();
    return this.getServerById(id);
  }

  public deleteCustomServer(id: string): boolean {
    const existing = this.getServerById(id);
    if (!existing || existing.isBuiltin) return false;
    this.db.prepare('DELETE FROM dns_servers WHERE id = ?').run(id);
    this.syncVault();
    return true;
  }

  public saveProbeResult(result: ProbeResult): DnsServer | null {
    const existing = this.getServerById(result.serverId);
    if (!existing) return null;

    const history = [...(existing.historyMs || [])];
    if (result.latencyMs !== null && result.latencyMs > 0) {
      history.push(Math.round(result.latencyMs));
      while (history.length > 12) history.shift();
    }

    this.db
      .prepare(
        `UPDATE dns_servers SET
          lastLatencyMs = ?,
          minLatencyMs = ?,
          avgLatencyMs = ?,
          jitterMs = ?,
          lastTps = ?,
          verdict = ?,
          verdictReason = ?,
          resolvedIpsJson = ?,
          companionPassed = ?,
          port443Ok = ?,
          httpStatus = ?,
          lastCheckedDomain = ?,
          lastCheckedAt = ?,
          historyMsJson = ?
        WHERE id = ?`
      )
      .run(
        result.latencyMs,
        result.minLatencyMs,
        result.avgLatencyMs,
        result.jitterMs,
        result.tps,
        result.verdict,
        result.verdictReason,
        JSON.stringify(result.resolvedIps),
        result.companionPassed === null ? null : result.companionPassed ? 1 : 0,
        result.port443Ok === null ? null : result.port443Ok ? 1 : 0,
        result.httpStatus,
        result.targetDomain,
        result.checkedAt,
        JSON.stringify(history),
        result.serverId
      );

    return this.getServerById(result.serverId);
  }

  public getCachedHosts(): { hosts: string[]; syncStatus: SyncStatus } {
    this.ensureDefaultHostsCache();
    try {
      const data = JSON.parse(fs.readFileSync(HOSTS_CACHE_PATH, 'utf8'));
      const hosts: string[] = Array.isArray(data.hosts) ? data.hosts : DEFAULT_BYPASS_DOMAINS;
      return {
        hosts,
        syncStatus: {
          cachedHostsCount: hosts.length,
          lastSyncAt: data.lastSyncAt ?? null,
          sources: Array.isArray(data.sources) ? data.sources : [],
        },
      };
    } catch {
      return {
        hosts: DEFAULT_BYPASS_DOMAINS,
        syncStatus: {
          cachedHostsCount: DEFAULT_BYPASS_DOMAINS.length,
          lastSyncAt: null,
          sources: [],
        },
      };
    }
  }

  public saveCachedHosts(hosts: string[], syncStatus: SyncStatus) {
    const merged = Array.from(new Set([...DEFAULT_BYPASS_DOMAINS, ...hosts]));
    fs.writeFileSync(
      HOSTS_CACHE_PATH,
      JSON.stringify(
        {
          hosts: merged,
          lastSyncAt: syncStatus.lastSyncAt,
          sources: syncStatus.sources,
        },
        null,
        2
      ),
      'utf8'
    );
  }

  public getSettings(): AppSettings {
    if (!fs.existsSync(SETTINGS_PATH)) {
      fs.writeFileSync(SETTINGS_PATH, JSON.stringify(DEFAULT_SETTINGS, null, 2), 'utf8');
      return DEFAULT_SETTINGS;
    }
    try {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8')) };
    } catch {
      return DEFAULT_SETTINGS;
    }
  }

  public saveSettings(patch: Partial<AppSettings>): AppSettings {
    const next = { ...this.getSettings(), ...patch };
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(next, null, 2), 'utf8');
    return next;
  }

  public updateRestoreState(state: Record<string, unknown>) {
    fs.writeFileSync(RESTORE_STATE_PATH, JSON.stringify(state, null, 2), 'utf8');
  }
}

export const dnsDb = new DnsDatabase();
