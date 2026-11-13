import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Gauge,
  Moon,
  Pencil,
  Radar,
  RefreshCw,
  RotateCcw,
  Search,
  Square,
  Sun,
  X,
} from 'lucide-react';
import { ConfigsTab } from './components/ConfigsTab';
import { DiscoveryModal } from './components/DiscoveryModal';
import { ManualAddModal } from './components/ManualAddModal';
import { ServerCard } from './components/ServerCard';
import { ServerDetailsDrawer } from './components/ServerDetailsDrawer';
import {
  CATEGORY_LIST,
  filterServers,
  getCategoryCounts,
  hasActiveFilter,
  sortServers,
} from './core/filterSort';
import { DOMAIN_PRESETS, getPresetsForGroup, PRESET_GROUPS } from './core/presets';
import {
  DnsServer,
  FilterState,
  PresetGroupId,
  SortMode,
  SyncStatus,
  TunnelState,
} from './core/types';

type ActiveTab = 'tester' | 'catalog' | 'configs';

interface AppSettings {
  theme: 'dark' | 'light';
  autoConnectBestOnRotate: boolean;
  freeOnly: boolean;
  hotkeyRotate: string;
}

const DEFAULT_FILTER: FilterState = {
  category: 'Все',
  bypassOnly: false,
  favoritesOnly: false,
  encryptedOnly: false,
  freeOnly: false,
  search: '',
  sortMode: 'BEST',
};

export default function App() {
  const [servers, setServers] = useState<DnsServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<ActiveTab>('tester');

  const [presetGroup, setPresetGroup] = useState<PresetGroupId>('ai');
  const [targetDomain, setTargetDomain] = useState<string>('gemini.google.com');
  const [requiresBypass, setRequiresBypass] = useState<boolean>(true);
  const [editingCustomDomain, setEditingCustomDomain] = useState<boolean>(false);

  const [filter, setFilter] = useState<FilterState>(DEFAULT_FILTER);
  const [visibleLimit, setVisibleLimit] = useState<number>(40);

  const [probingIds, setProbingIds] = useState<Set<string>>(new Set());
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [isLive, setIsLive] = useState(false);

  const [tunnel, setTunnel] = useState<TunnelState>({
    active: false,
    serverId: null,
    serverName: null,
    endpoint: null,
    protocol: null,
    targetDomain: 'gemini.google.com',
    listenAddress: '127.0.0.1:15353',
    splitRouting: true,
    nrptEnabled: false,
    queriesHandled: 0,
    cacheHits: 0,
    startedAt: null,
    rotationQueueIds: [],
  });

  const [syncStatus, setSyncStatus] = useState<SyncStatus>({
    cachedHostsCount: 0,
    lastSyncAt: null,
    sources: [],
  });

  const [settings, setSettings] = useState<AppSettings>({
    theme: 'dark',
    autoConnectBestOnRotate: true,
    freeOnly: false,
    hotkeyRotate: 'Ctrl+Alt+R',
  });

  const [discoveryOpen, setDiscoveryOpen] = useState(false);
  const [manualAddOpen, setManualAddOpen] = useState(false);
  const [detailsServerId, setDetailsServerId] = useState<string | null>(null);
  const [tunnelTestFeedback, setTunnelTestFeedback] = useState<string | null>(null);

  const liveTimerRef = useRef<number | null>(null);

  // Sync HTML .dark class with settings.theme
  useEffect(() => {
    const root = document.documentElement;
    if (settings.theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [settings.theme]);

  // Initial bootstrap from SQLite backend
  const loadBootstrap = useCallback(async () => {
    try {
      const res = await fetch('/api/bootstrap');
      const data = await res.json();
      setServers(data.servers || []);
      if (data.syncStatus) setSyncStatus(data.syncStatus);
      if (data.settings) {
        setSettings(data.settings);
        setFilter((prev) => ({ ...prev, freeOnly: Boolean(data.settings.freeOnly) }));
      }
      if (data.tunnel) setTunnel(data.tunnel);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadBootstrap();
  }, [loadBootstrap]);

  const mergeUpdatedServers = useCallback((updatedList: DnsServer[]) => {
    if (!updatedList.length) return;
    const map = new Map(updatedList.map((s) => [s.id, s]));
    setServers((prev) => prev.map((s) => map.get(s.id) ?? s));
  }, []);

  const categoryCounts = useMemo(() => getCategoryCounts(servers), [servers]);

  const filteredAndSorted = useMemo(() => {
    const filtered = filterServers(servers, filter, requiresBypass);
    return sortServers(filtered, filter.sortMode);
  }, [servers, filter, requiresBypass]);

  const visibleServers = useMemo(
    () => filteredAndSorted.slice(0, visibleLimit),
    [filteredAndSorted, visibleLimit]
  );

  const bestVerifiedId = useMemo(() => {
    const verified = sortServers(
      servers.filter((s) => s.verdict === 'VERIFIED_PROXY_OK' && !s.isSubscription),
      'LOWEST_PING'
    );
    return verified[0]?.id ?? null;
  }, [servers]);

  const detailsServer = useMemo(
    () => (detailsServerId ? servers.find((s) => s.id === detailsServerId) ?? null : null),
    [detailsServerId, servers]
  );

  const activeGroupLabel = useMemo(
    () => PRESET_GROUPS.find((g) => g.id === presetGroup)?.label ?? 'ИИ',
    [presetGroup]
  );

  const groupPresets = useMemo(() => getPresetsForGroup(presetGroup), [presetGroup]);

  const handleSelectGroup = (groupId: PresetGroupId) => {
    setPresetGroup(groupId);
    if (groupId === 'custom') {
      setEditingCustomDomain(true);
      setRequiresBypass(true);
      return;
    }
    setEditingCustomDomain(false);
    const list = getPresetsForGroup(groupId);
    if (list.length > 0) {
      setTargetDomain(list[0].domain);
      setRequiresBypass(list[0].requiresBypass);
    }
  };

  const handleSelectPreset = (domain: string, bypass: boolean) => {
    setTargetDomain(domain);
    setRequiresBypass(bypass);
    setEditingCustomDomain(false);
  };

  const handleProbeSingle = async (server: DnsServer) => {
    setProbingIds((prev) => new Set(prev).add(server.id));
    try {
      const res = await fetch('/api/probe/single', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serverId: server.id,
          targetDomain,
          requiresBypass,
        }),
      });
      const data = await res.json();
      if (data.server) {
        mergeUpdatedServers([data.server]);
      }
    } finally {
      setProbingIds((prev) => {
        const next = new Set(prev);
        next.delete(server.id);
        return next;
      });
    }
  };

  const runBatchProbe = useCallback(
    async (targetIds: string[]) => {
      if (targetIds.length === 0) return;
      setProbingIds((prev) => {
        const next = new Set(prev);
        targetIds.forEach((id) => next.add(id));
        return next;
      });
      try {
        const res = await fetch('/api/probe/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            serverIds: targetIds,
            targetDomain,
            requiresBypass,
          }),
        });
        const data = await res.json();
        if (Array.isArray(data.servers)) {
          mergeUpdatedServers(data.servers);
        }
      } finally {
        setProbingIds((prev) => {
          const next = new Set(prev);
          targetIds.forEach((id) => next.delete(id));
          return next;
        });
      }
    },
    [targetDomain, requiresBypass, mergeUpdatedServers]
  );

  const handleBenchmarkVisible = async () => {
    setIsBenchmarking(true);
    try {
      const ids = filteredAndSorted.slice(0, 18).map((s) => s.id);
      await runBatchProbe(ids);
    } finally {
      setIsBenchmarking(false);
    }
  };

  // LIVE 4-stage monitoring loop every 2.5s
  useEffect(() => {
    if (!isLive) {
      if (liveTimerRef.current !== null) {
        window.clearInterval(liveTimerRef.current);
        liveTimerRef.current = null;
      }
      return;
    }

    const tick = () => {
      const topIds = filteredAndSorted.slice(0, 8).map((s) => s.id);
      runBatchProbe(topIds);
    };

    tick();
    liveTimerRef.current = window.setInterval(tick, 2800);
    return () => {
      if (liveTimerRef.current !== null) {
        window.clearInterval(liveTimerRef.current);
        liveTimerRef.current = null;
      }
    };
  }, [isLive, filteredAndSorted, runBatchProbe]);

  const handleToggleFavorite = async (server: DnsServer) => {
    const res = await fetch(`/api/servers/${encodeURIComponent(server.id)}/favorite`, {
      method: 'POST',
    });
    const data = await res.json();
    if (data.server) mergeUpdatedServers([data.server]);
  };

  const handleDeleteCustom = async (server: DnsServer) => {
    const res = await fetch(`/api/servers/${encodeURIComponent(server.id)}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      setServers((prev) => prev.filter((s) => s.id !== server.id));
      setDetailsServerId(null);
    }
  };

  const handleToggleStart = async (server: DnsServer) => {
    if (tunnel.active && tunnel.serverId === server.id) {
      const res = await fetch('/api/tunnel/stop', { method: 'POST' });
      const data = await res.json();
      setTunnel(data.tunnel);
      setTunnelTestFeedback(null);
      return;
    }
    const res = await fetch('/api/tunnel/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        serverId: server.id,
        targetDomain,
        splitRouting: true,
      }),
    });
    const data = await res.json();
    if (data.tunnel) setTunnel(data.tunnel);
  };

  const handleRotateTunnel = useCallback(async () => {
    const res = await fetch('/api/tunnel/rotate', { method: 'POST' });
    const data = await res.json();
    if (data.tunnel) {
      setTunnel(data.tunnel);
      setTunnelTestFeedback(`Ротация выполнена: ${data.tunnel.serverName}`);
    }
  }, []);

  const handleStopTunnel = async () => {
    const res = await fetch('/api/tunnel/stop', { method: 'POST' });
    const data = await res.json();
    setTunnel(data.tunnel);
    setTunnelTestFeedback(null);
  };

  const handleTestTunnelQuery = async () => {
    const res = await fetch('/api/tunnel/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: targetDomain }),
    });
    const data = await res.json();
    if (data.tunnel) setTunnel(data.tunnel);
    if (data.result) {
      setTunnelTestFeedback(
        `${data.result.domain} → ${data.result.routedVia === 'smart-dns' ? 'Smart-DNS' : 'Прямой'} (${data.result.ips.join(', ') || 'нет A'})`
      );
    }
  };

  // Global Ctrl+Alt+R hotkey for instant tunnel rotation
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.altKey && e.key.toLowerCase() === 'r') {
        e.preventDefault();
        handleRotateTunnel();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [handleRotateTunnel]);

  const handleUpdateSettings = async (patch: Partial<AppSettings>) => {
    const next = { ...settings, ...patch };
    setSettings(next);
    if (patch.freeOnly !== undefined) {
      setFilter((prev) => ({ ...prev, freeOnly: Boolean(patch.freeOnly) }));
    }
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
  };

  const handleSyncHosts = async () => {
    const res = await fetch('/api/sync/hosts', { method: 'POST' });
    const data = await res.json();
    if (data.syncStatus) setSyncStatus(data.syncStatus);
    if (Array.isArray(data.servers)) setServers(data.servers);
  };

  const handleRestoreBuiltins = async () => {
    const res = await fetch('/api/servers/restore-builtins', { method: 'POST' });
    const data = await res.json();
    if (Array.isArray(data.servers)) setServers(data.servers);
  };

  const activeFiltersPresent = hasActiveFilter(filter);

  return (
    <div className="min-h-screen bg-[#F7F8FA] dark:bg-[#0B0D10] text-[#0F172A] dark:text-[#F1F5F9] transition-colors">
      {/* Top Bar: 3-zone contract on desktop, clean responsive wrap on mobile */}
      <header className="md:sticky md:top-0 z-30 bg-[#FFFFFF]/95 dark:bg-[#13161B]/95 backdrop-blur-sm border-b border-[#DCE1E8] dark:border-[#262C36]">
        <div className="max-w-[1340px] mx-auto px-4 sm:px-6 py-2 md:py-0 md:h-14 flex flex-wrap md:flex-nowrap items-center justify-between gap-2 md:gap-8">
          {/* Zone 1: Single-line Brand Wordmark */}
          <div className="flex items-center gap-3 shrink-0">
            <span className="text-base font-bold tracking-tight text-[#0F172A] dark:text-[#F1F5F9] whitespace-nowrap shrink-0">
              DNS Pulse
            </span>
          </div>

          {/* Zone 2: Concise Navigation Tabs */}
          <nav aria-label="Основные разделы" className="order-3 md:order-2 w-full md:w-auto flex items-center gap-5 sm:gap-7 border-t md:border-t-0 border-[#DCE1E8] dark:border-[#262C36] pt-1 md:pt-0">
            {(
              [
                { id: 'tester', label: 'Тестер' },
                { id: 'catalog', label: 'Каталог' },
                { id: 'configs', label: 'Конфиги' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setActiveTab(tab.id);
                  if (tab.id === 'catalog') {
                    setVisibleLimit((prev) => Math.max(prev, 100));
                  }
                }}
                className={`py-2 md:py-4 text-sm font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeTab === tab.id
                    ? 'border-[#22C55E] text-[#0F172A] dark:text-[#F1F5F9]'
                    : 'border-transparent text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          {/* Zone 3: Actions */}
          <div className="order-2 md:order-3 flex items-center gap-1.5 sm:gap-2 shrink-0">
            <button
              type="button"
              onClick={() =>
                handleUpdateSettings({ theme: settings.theme === 'dark' ? 'light' : 'dark' })
              }
              aria-label={settings.theme === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему'}
              className="min-h-[36px] w-[36px] rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] inline-flex items-center justify-center text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] cursor-pointer shrink-0"
              title="Переключить тему"
            >
              {settings.theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            <button
              type="button"
              onClick={() => setDiscoveryOpen(true)}
              className="min-h-[36px] px-3 sm:px-3.5 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer hover:bg-[#E2E8F0] dark:hover:bg-[#242B35]"
            >
              <Radar className="w-3.5 h-3.5" />
              <span>Подбор</span>
            </button>

            <button
              type="button"
              onClick={() => setIsLive((prev) => !prev)}
              aria-pressed={isLive}
              title="Автопроверка топ-8 серверов каждые 2.8 сек"
              className={`min-h-[36px] px-3 sm:px-3.5 py-1.5 rounded-md border text-xs font-semibold inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                isLive
                  ? 'bg-[#22C55E] border-[#22C55E] text-[#0B0D10]'
                  : 'bg-[#EEF1F5] dark:bg-[#1B2028] border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>LIVE</span>
            </button>

            <button
              type="button"
              onClick={handleBenchmarkVisible}
              disabled={isBenchmarking}
              className="min-h-[36px] px-3 sm:px-4 py-1.5 rounded-md bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <Gauge className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{isBenchmarking ? 'Проверка...' : 'Тест скорости'}</span>
              <span className="sm:hidden">{isBenchmarking ? '...' : 'Тест'}</span>
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-[1340px] mx-auto px-4 sm:px-6 py-5 space-y-4">
        {/* Active Tunnel / Tray Notification Bar */}
        {tunnel.active && (
          <section
            aria-label="Активный DNS-туннель"
            className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#22C55E]/70 px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3"
          >
            <div className="min-w-0 space-y-0.5">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs font-semibold text-[#16A34A] dark:text-[#22C55E]">
                <span>Активен туннель: {tunnel.serverName}</span>
                <span className="font-mono text-[#64748B] dark:text-[#94A3B8]">
                  · {tunnel.listenAddress} · Запросов: {tunnel.queriesHandled} (кэш: {tunnel.cacheHits})
                </span>
              </div>
              <div className="font-mono text-xs text-[#64748B] dark:text-[#94A3B8] truncate">
                {tunnel.endpoint} · Цель: {tunnel.targetDomain}
                {tunnelTestFeedback ? ` · ${tunnelTestFeedback}` : ''}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleTestTunnelQuery}
                className="min-h-[34px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] whitespace-nowrap shrink-0 cursor-pointer"
              >
                Проверить запрос
              </button>
              <button
                type="button"
                onClick={handleRotateTunnel}
                title="Горячая клавиша Ctrl+Alt+R"
                className="min-h-[34px] px-3.5 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer hover:bg-[#E2E8F0] dark:hover:bg-[#242B35]"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Ротация ↻</span>
              </button>
              <button
                type="button"
                onClick={handleStopTunnel}
                className="min-h-[34px] px-3.5 py-1.5 rounded-md bg-[#EF4444] text-[#FFFFFF] text-xs font-semibold inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer hover:bg-[#DC2626]"
              >
                <Square className="w-3 h-3 fill-current" />
                <span>Откл</span>
              </button>
            </div>
          </section>
        )}

        {activeTab === 'configs' ? (
          <ConfigsTab
            servers={servers}
            syncStatus={syncStatus}
            settings={settings}
            onOpenManualAdd={() => setManualAddOpen(true)}
            onOpenDiscovery={() => setDiscoveryOpen(true)}
            onServersImported={(all) => setServers(all)}
            onSyncHosts={handleSyncHosts}
            onUpdateSettings={handleUpdateSettings}
            onRestoreBuiltins={handleRestoreBuiltins}
          />
        ) : (
          <>
            {/* Mode & Domain Preset Panel */}
            <section
              aria-label="Режим проверки и выбор домена"
              className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-4 space-y-3"
            >
              {/* Compact header: "Режим: ИИ" on left, clickable domain badge "gemini.google.com ✎" on right */}
              <div className="flex items-center justify-between gap-4">
                <div className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] whitespace-nowrap shrink-0">
                  Режим: {activeGroupLabel}
                </div>

                {editingCustomDomain ? (
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      setEditingCustomDomain(false);
                    }}
                    className="flex items-center gap-1.5"
                  >
                    <input
                      type="text"
                      value={targetDomain}
                      onChange={(e) => setTargetDomain(e.target.value)}
                      autoFocus
                      aria-label="Свой домен проверки"
                      className="min-h-[32px] w-56 px-2.5 py-1 rounded font-mono text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#22C55E] text-[#0F172A] dark:text-[#F1F5F9] focus:outline-none"
                    />
                    <button
                      type="submit"
                      className="min-h-[32px] px-2.5 py-1 rounded bg-[#22C55E] text-[#0B0D10] text-xs font-semibold cursor-pointer"
                    >
                      ОК
                    </button>
                  </form>
                ) : (
                  <button
                    type="button"
                    onClick={() => setEditingCustomDomain(true)}
                    aria-label={`Изменить домен проверки ${targetDomain}`}
                    className="min-h-[32px] px-3 py-1 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] font-mono text-xs text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 max-w-[260px] cursor-pointer hover:border-[#94A3B8]"
                  >
                    <span className="truncate">{targetDomain}</span>
                    <Pencil className="w-3 h-3 shrink-0 text-[#64748B] dark:text-[#94A3B8]" />
                  </button>
                )}
              </div>

              {/* Preset Groups + Sub-pills */}
              <div className="flex flex-col sm:flex-row sm:items-center gap-2.5">
                <div className="inline-flex items-center gap-1 p-1 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] shrink-0 self-start">
                  {PRESET_GROUPS.map((g) => (
                    <button
                      key={g.id}
                      type="button"
                      onClick={() => handleSelectGroup(g.id)}
                      className={`min-h-[30px] px-3 py-1 rounded text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                        presetGroup === g.id
                          ? 'bg-[#FFFFFF] dark:bg-[#13161B] text-[#0F172A] dark:text-[#F1F5F9] shadow-xs'
                          : 'text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9]'
                      }`}
                    >
                      {g.label}
                    </button>
                  ))}
                </div>

                {groupPresets.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    {groupPresets.map((preset) => (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() => handleSelectPreset(preset.domain, preset.requiresBypass)}
                        className={`min-h-[32px] px-3 py-1 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer border ${
                          targetDomain === preset.domain
                            ? 'bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] border-transparent'
                            : 'bg-[#F7F8FA] dark:bg-[#0B0D10] text-[#0F172A] dark:text-[#F1F5F9] border-[#DCE1E8] dark:border-[#262C36] hover:border-[#94A3B8]'
                        }`}
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                )}

                {presetGroup === 'custom' && (
                  <label className="inline-flex items-center gap-2 text-xs text-[#64748B] dark:text-[#94A3B8] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={requiresBypass}
                      onChange={(e) => setRequiresBypass(e.target.checked)}
                      className="accent-[#22C55E]"
                    />
                    <span>Проверять обход (Anti-Direct-IP + 443)</span>
                  </label>
                )}
              </div>
            </section>

            {/* Categories with live counters */}
            <section aria-label="Категории серверов" className="flex flex-wrap items-center gap-1.5">
              {CATEGORY_LIST.map((cat) => {
                const count = categoryCounts[cat] ?? 0;
                const active = filter.category === cat;
                return (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => {
                      setFilter((prev) => ({ ...prev, category: cat }));
                      setVisibleLimit(activeTab === 'catalog' ? 100 : 40);
                    }}
                    className={`min-h-[34px] px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 inline-flex items-center gap-1.5 border transition-colors cursor-pointer ${
                      active
                        ? 'bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] border-transparent'
                        : 'bg-[#FFFFFF] dark:bg-[#13161B] text-[#0F172A] dark:text-[#F1F5F9] border-[#DCE1E8] dark:border-[#262C36] hover:border-[#94A3B8]'
                    }`}
                  >
                    <span>{cat}</span>
                    <span
                      className={`font-mono text-[11px] tabular-nums ${
                        active ? 'opacity-80' : 'text-[#64748B] dark:text-[#94A3B8]'
                      }`}
                    >
                      {count}
                    </span>
                  </button>
                );
              })}
            </section>

            {/* Quick Filters, Live Search & Sort Bar */}
            <section
              aria-label="Фильтры и сортировка"
              className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3"
            >
              <div className="relative flex-1 min-w-[220px]">
                <Search className="w-3.5 h-3.5 text-[#64748B] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={filter.search}
                  onChange={(e) => setFilter((prev) => ({ ...prev, search: e.target.value }))}
                  aria-label="Поиск DNS-серверов"
                  placeholder="Поиск по имени, провайдеру, IP, DoH URL, DoT, тегам..."
                  className="w-full min-h-[36px] pl-9 pr-8 py-1.5 rounded-md text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9] focus:outline-none focus:border-[#22C55E]"
                />
                {filter.search && (
                  <button
                    type="button"
                    onClick={() => setFilter((prev) => ({ ...prev, search: '' }))}
                    aria-label="Очистить поиск"
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#64748B] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setFilter((prev) => ({ ...prev, bypassOnly: !prev.bypassOnly }))}
                  aria-pressed={filter.bypassOnly}
                  className={`min-h-[36px] px-3 py-1.5 rounded-md border text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                    filter.bypassOnly
                      ? 'bg-[#22C55E]/15 border-[#22C55E] text-[#16A34A] dark:text-[#22C55E]'
                      : 'bg-[#F7F8FA] dark:bg-[#0B0D10] border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]'
                  }`}
                >
                  ✓ Обход 443
                </button>

                <button
                  type="button"
                  onClick={() => setFilter((prev) => ({ ...prev, favoritesOnly: !prev.favoritesOnly }))}
                  aria-pressed={filter.favoritesOnly}
                  className={`min-h-[36px] px-3 py-1.5 rounded-md border text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                    filter.favoritesOnly
                      ? 'bg-[#F59E0B]/15 border-[#F59E0B] text-[#D97706] dark:text-[#F59E0B]'
                      : 'bg-[#F7F8FA] dark:bg-[#0B0D10] border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]'
                  }`}
                >
                  ★ Избранные
                </button>

                <button
                  type="button"
                  onClick={() => setFilter((prev) => ({ ...prev, encryptedOnly: !prev.encryptedOnly }))}
                  aria-pressed={filter.encryptedOnly}
                  className={`min-h-[36px] px-3 py-1.5 rounded-md border text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                    filter.encryptedOnly
                      ? 'bg-[#0F172A] dark:bg-[#F1F5F9] border-transparent text-[#FFFFFF] dark:text-[#0B0D10]'
                      : 'bg-[#F7F8FA] dark:bg-[#0B0D10] border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]'
                  }`}
                >
                  DoH / DoT
                </button>

                <button
                  type="button"
                  onClick={() =>
                    handleUpdateSettings({ freeOnly: !filter.freeOnly })
                  }
                  aria-pressed={filter.freeOnly}
                  className={`min-h-[36px] px-3 py-1.5 rounded-md border text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                    filter.freeOnly
                      ? 'bg-[#0F172A] dark:bg-[#F1F5F9] border-transparent text-[#FFFFFF] dark:text-[#0B0D10]'
                      : 'bg-[#F7F8FA] dark:bg-[#0B0D10] border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]'
                  }`}
                >
                  Только бесплатные
                </button>

                <select
                  value={filter.sortMode}
                  onChange={(e) =>
                    setFilter((prev) => ({ ...prev, sortMode: e.target.value as SortMode }))
                  }
                  aria-label="Сортировка серверов"
                  className="min-h-[36px] px-3 py-1.5 rounded-md text-xs font-medium bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer"
                >
                  <option value="BEST">Сорт: Обход + Пинг</option>
                  <option value="LOWEST_PING">Сорт: Пинг (мс)</option>
                  <option value="HIGHEST_TPS">Сорт: Скорость TPS</option>
                  <option value="FAVORITES_FIRST">Сорт: Избранные</option>
                  <option value="ALPHABETICAL">Сорт: По алфавиту</option>
                </select>

                {activeFiltersPresent && (
                  <button
                    type="button"
                    onClick={() => setFilter({ ...DEFAULT_FILTER, sortMode: filter.sortMode })}
                    className="min-h-[36px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span className="tabular-nums">
                      Сброс ({filteredAndSorted.length}/{servers.length})
                    </span>
                  </button>
                )}
              </div>
            </section>

            {/* Server List */}
            {loading ? (
              <div className="space-y-3" aria-busy="true">
                {[1, 2, 3, 4].map((n) => (
                  <div
                    key={n}
                    className="h-[88px] rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] animate-pulse"
                  />
                ))}
              </div>
            ) : filteredAndSorted.length === 0 ? (
              <div className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-10 text-center space-y-3">
                <div className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
                  По текущим фильтрам серверы не найдены
                </div>
                <p className="text-xs text-[#64748B] dark:text-[#94A3B8]">
                  Попробуйте сбросить фильтры, изменить поисковый запрос или добавить сервер вручную.
                </p>
                <div className="flex justify-center gap-2">
                  <button
                    type="button"
                    onClick={() => setFilter(DEFAULT_FILTER)}
                    className="min-h-[38px] px-4 py-2 rounded-md bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold cursor-pointer"
                  >
                    Сбросить фильтры
                  </button>
                  <button
                    type="button"
                    onClick={() => setDiscoveryOpen(true)}
                    className="min-h-[38px] px-4 py-2 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer"
                  >
                    Открыть Подбор
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-2.5">
                <div className="flex items-center justify-between text-xs text-[#64748B] dark:text-[#94A3B8] px-1">
                  <span className="tabular-nums">
                    Показано {visibleServers.length} из {filteredAndSorted.length} (всего в базе:{' '}
                    {servers.length})
                  </span>
                  {activeTab === 'catalog' && (
                    <button
                      type="button"
                      onClick={() => setManualAddOpen(true)}
                      className="text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] hover:underline cursor-pointer"
                    >
                      + Добавить свой DNS
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 gap-2.5">
                  {visibleServers.map((srv) => (
                    <ServerCard
                      key={srv.id}
                      server={srv}
                      isActive={tunnel.active && tunnel.serverId === srv.id}
                      isBest={srv.id === bestVerifiedId}
                      isProbing={probingIds.has(srv.id)}
                      onProbeSingle={handleProbeSingle}
                      onToggleStart={handleToggleStart}
                      onToggleFavorite={handleToggleFavorite}
                      onOpenDetails={(s) => setDetailsServerId(s.id)}
                    />
                  ))}
                </div>

                {visibleServers.length < filteredAndSorted.length && (
                  <div className="pt-2 flex justify-center">
                    <button
                      type="button"
                      onClick={() => setVisibleLimit((prev) => prev + 60)}
                      className="min-h-[40px] px-6 py-2 rounded-md bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] hover:border-[#94A3B8] cursor-pointer"
                    >
                      Показать ещё (+{Math.min(60, filteredAndSorted.length - visibleServers.length)})
                    </button>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </main>

      {/* Modals & Drawers */}
      <DiscoveryModal
        open={discoveryOpen}
        initialDomain={targetDomain}
        onClose={() => setDiscoveryOpen(false)}
        onServersUpdated={(updated, nextSync) => {
          setServers(updated);
          if (nextSync) setSyncStatus(nextSync);
        }}
      />

      <ManualAddModal
        open={manualAddOpen}
        onClose={() => setManualAddOpen(false)}
        onCreated={(srv) => {
          setServers((prev) => [srv, ...prev]);
        }}
      />

      <ServerDetailsDrawer
        server={detailsServer}
        onClose={() => setDetailsServerId(null)}
        onProbe={handleProbeSingle}
        onDeleteCustom={handleDeleteCustom}
      />
    </div>
  );
}
