import { classifyFourStageVerdict, isBogonOrLoopbackIp } from '../src/core/antiDirectIp';
import {
  rankAiAutopilotCandidates,
  selectNextFailoverNode,
  shouldTriggerWatchdogFailover,
} from '../src/core/autopilot';
import {
  AutopilotServiceCheck,
  AutopilotState,
  AutopilotStep,
  DnsServer,
} from '../src/core/types';
import { dnsDb } from './db';
import { runParserAndBypassCheck, syncOnlineHostsAndCommunityDns } from './discovery';
import {
  probeTlsHttpSni443,
  resolveWithServer,
  runFourStageProbe,
  runWithConcurrency,
} from './prober';
import { tunnelManager } from './tunnel';

const AI_VERIFICATION_TARGETS = [
  { id: 'gemini', label: 'Gemini / AI Studio', domain: 'gemini.google.com' },
  { id: 'antigravity', label: 'Google Antigravity', domain: 'cloudcode-pa.googleapis.com' },
  { id: 'claude', label: 'Claude / Claude Code', domain: 'api.anthropic.com' },
  { id: 'chatgpt', label: 'ChatGPT / Codex CLI', domain: 'chatgpt.com' },
  { id: 'cursor', label: 'Cursor / Windsurf', domain: 'api2.cursor.sh' },
];

const WATCHDOG_INTERVAL_MS = 40_000;

function createInitialSteps(): AutopilotStep[] {
  return [
    { id: 'sync', label: 'Обновление списков', status: 'pending' },
    { id: 'probe', label: 'Подбор узла', status: 'pending' },
    { id: 'tunnel', label: 'Прокси 127.0.0.1:18753', status: 'pending' },
    { id: 'apps', label: 'Проверка сервисов', status: 'pending' },
  ];
}

class AiAutopilotOrchestrator {
  private watchdogTimer: ReturnType<typeof setInterval> | null = null;
  private isRunning = false;
  private recentlyFailedIds = new Set<string>();
  private state: AutopilotState = {
    phase: 'idle',
    watchdogEnabled: true,
    activeServerId: null,
    activeServerName: null,
    activeProtocol: null,
    activeLatencyMs: null,
    localDnsAddress: '127.0.0.1:15353',
    localProxyAddress: '127.0.0.1:18753',
    standbyCount: 0,
    testedCount: 0,
    verifiedCount: 0,
    lastCheckAt: null,
    summary: 'Готов к запуску.',
    steps: createInitialSteps(),
    serviceChecks: [],
    switchHistory: [],
  };

  public getState(): AutopilotState {
    const tunnel = tunnelManager.getState();
    return {
      ...this.state,
      localDnsAddress: tunnel.listenAddress,
      localProxyAddress: tunnel.localProxyAddress,
      steps: this.state.steps.map((s) => ({ ...s })),
      serviceChecks: this.state.serviceChecks.map((c) => ({ ...c })),
      switchHistory: this.state.switchHistory.slice(0, 12),
    };
  }

  private setStep(id: string, status: AutopilotStep['status'], detail?: string) {
    this.state.steps = this.state.steps.map((s) =>
      s.id === id ? { ...s, status, detail: detail ?? s.detail } : s
    );
  }

  public async start(): Promise<AutopilotState> {
    if (this.isRunning) {
      return this.getState();
    }

    this.isRunning = true;
    this.stopWatchdog();
    this.recentlyFailedIds.clear();
    this.state = {
      ...this.state,
      phase: 'running',
      watchdogEnabled: true,
      testedCount: 0,
      verifiedCount: 0,
      serviceChecks: [],
      steps: createInitialSteps(),
      summary: 'Подбор рабочего узла...',
    };

    try {
      // Step 1: Refresh community feeds & Smart-DNS configs (real network fetch, gracefully handles offline)
      this.setStep('sync', 'active', 'Загрузка фидов...');
      try {
        const synced = await Promise.race([
          syncOnlineHostsAndCommunityDns(),
          new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000)),
        ]);
        const hostsCount = synced?.syncStatus?.cachedHostsCount ?? dnsDb.getCachedHosts().hosts.length;
        this.setStep('sync', 'done', `${hostsCount} доменов`);
      } catch {
        this.setStep('sync', 'warn', 'Локальный кэш');
      }

      // Step 2: Parallel 4-stage probe across top AI Smart-DNS & SNI-Proxy candidates
      this.setStep('probe', 'active', 'Тест кандидатов...');
      const allServers = dnsDb.getAllServers();
      const rankedCandidates = rankAiAutopilotCandidates(allServers).slice(0, 14);

      const probedServers: DnsServer[] = [];
      await runWithConcurrency(rankedCandidates, 6, async (srv) => {
        const result = await runFourStageProbe(srv, 'gemini.google.com', true);
        const saved = dnsDb.saveProbeResult(result);
        if (saved) probedServers.push(saved);
        this.state.testedCount += 1;
        if (result.verdict === 'VERIFIED_PROXY_OK') {
          this.state.verifiedCount += 1;
        }
      });

      let freshRanked = rankAiAutopilotCandidates(dnsDb.getAllServers());
      let verifiedPool = freshRanked.filter((s) => s.verdict === 'VERIFIED_PROXY_OK');

      // Auto-harvest fresh nodes via Parser if zero verified built-ins responded
      if (verifiedPool.length === 0) {
        this.setStep('probe', 'active', 'Поиск новых узлов...');
        try {
          await Promise.race([
            runParserAndBypassCheck('gemini.google.com', true),
            new Promise<null>((resolve) => setTimeout(() => resolve(null), 8000)),
          ]);
        } catch {
          // ignore parser network failures
        }
        freshRanked = rankAiAutopilotCandidates(dnsDb.getAllServers());
        verifiedPool = freshRanked.filter((s) => s.verdict === 'VERIFIED_PROXY_OK');
      }

      const bestNode = verifiedPool[0] ?? freshRanked[0] ?? null;
      if (!bestNode) {
        this.setStep('probe', 'error', 'Узлы не найдены');
        this.state.phase = 'error';
        this.state.summary = 'Рабочий узел не найден. Проверьте сеть.';
        return this.getState();
      }

      const isVerifiedBest = bestNode.verdict === 'VERIFIED_PROXY_OK';
      this.setStep(
        'probe',
        isVerifiedBest ? 'done' : 'warn',
        isVerifiedBest
          ? `${verifiedPool.length} рабочих · ${bestNode.name} (${Math.round(bestNode.lastLatencyMs ?? 0)} мс)`
          : `Резервный узел: ${bestNode.name}`
      );

      // Step 3: Activate Local DNS (127.0.0.1:15353) + Local HTTP CONNECT Proxy (127.0.0.1:18753)
      this.setStep('tunnel', 'active', `Запуск ${bestNode.name}...`);
      const tunnel = tunnelManager.start(bestNode.id, 'gemini.google.com', {
        splitRouting: true,
        nrptEnabled: false,
      });
      this.setStep(
        'tunnel',
        'done',
        `http://${tunnel.localProxyAddress}`
      );

      // Step 4: Verify key AI web + desktop app endpoints through the selected node
      this.setStep('apps', 'active', 'Проверка сервисов...');
      const checks = await this.verifyAiServices(bestNode);
      const passedCount = checks.filter((c) => c.ok).length;
      this.state.serviceChecks = checks;
      this.setStep(
        'apps',
        passedCount > 0 ? 'done' : 'warn',
        `${passedCount} из ${checks.length} доступны`
      );

      this.state.activeServerId = bestNode.id;
      this.state.activeServerName = bestNode.name;
      this.state.activeProtocol = bestNode.protocol;
      this.state.activeLatencyMs = bestNode.lastLatencyMs;
      this.state.standbyCount = Math.max(0, verifiedPool.length - 1);
      this.state.lastCheckAt = new Date().toISOString();
      this.state.phase = isVerifiedBest ? 'active' : 'degraded';
      this.state.summary = isVerifiedBest
        ? `Активен ${bestNode.name} (${Math.round(bestNode.lastLatencyMs ?? 0)} мс) · автопереключение включено`
        : `Запущен через ${bestNode.name} · часть узлов ограничена`;

      this.startWatchdog();
      return this.getState();
    } catch (err) {
      this.state.phase = 'error';
      this.state.summary =
        err instanceof Error ? `Ошибка: ${err.message}` : 'Ошибка запуска';
      return this.getState();
    } finally {
      this.isRunning = false;
    }
  }

  public stop(): AutopilotState {
    this.stopWatchdog();
    tunnelManager.stop();
    this.recentlyFailedIds.clear();
    this.state = {
      ...this.state,
      phase: 'idle',
      activeServerId: null,
      activeServerName: null,
      activeProtocol: null,
      activeLatencyMs: null,
      standbyCount: 0,
      summary: 'Обход отключён.',
      steps: createInitialSteps(),
    };
    return this.getState();
  }

  public async forceRotate(reason = 'Ручная смена AI-узла'): Promise<AutopilotState> {
    const ranked = rankAiAutopilotCandidates(dnsDb.getAllServers());
    const currentId = this.state.activeServerId;
    const prevName = this.state.activeServerName;

    if (currentId) {
      this.recentlyFailedIds.add(currentId);
    }

    const next = selectNextFailoverNode(ranked, currentId, this.recentlyFailedIds);
    if (!next) {
      return this.getState();
    }

    const probe = await runFourStageProbe(next, 'gemini.google.com', true);
    const saved = dnsDb.saveProbeResult(probe) ?? next;

    tunnelManager.start(saved.id, 'gemini.google.com', {
      splitRouting: true,
      nrptEnabled: false,
    });

    this.state.activeServerId = saved.id;
    this.state.activeServerName = saved.name;
    this.state.activeProtocol = saved.protocol;
    this.state.activeLatencyMs = saved.lastLatencyMs;
    this.state.lastCheckAt = new Date().toISOString();
    this.state.phase = saved.verdict === 'VERIFIED_PROXY_OK' ? 'active' : 'degraded';
    this.state.summary = `Переключено на ${saved.name} (${saved.lastLatencyMs !== null ? `${Math.round(saved.lastLatencyMs)} мс` : '—'}). Причина: ${reason}`;
    this.state.switchHistory.unshift({
      at: new Date().toISOString(),
      fromServerName: prevName,
      toServerName: saved.name,
      reason,
    });

    this.state.serviceChecks = await this.verifyAiServices(saved);
    return this.getState();
  }

  private async verifyAiServices(server: DnsServer): Promise<AutopilotServiceCheck[]> {
    const results = await runWithConcurrency(AI_VERIFICATION_TARGETS, 2, async (target) => {
      try {
        const resolved = await resolveWithServer(server, target.domain, 3000);
        const validIps = resolved.ips.filter((ip) => !isBogonOrLoopbackIp(ip));
        if (validIps.length === 0) {
          return {
            id: target.id,
            label: target.label,
            domain: target.domain,
            ok: false,
            latencyMs: resolved.latencyMs,
            verdict: 'DNS_TIMEOUT',
          } satisfies AutopilotServiceCheck;
        }

        const tlsCheck = await probeTlsHttpSni443(validIps[0], target.domain, 3000);
        const { verdict } = classifyFourStageVerdict({
          requiresBypass: true,
          resolvedIps: validIps,
          companionPassed: true,
          port443Ok: tlsCheck.port443Ok,
          httpStatus: tlsCheck.httpStatus,
          redirectLocation: tlsCheck.redirectLocation,
          targetDomain: target.domain,
          timedOut: false,
        });

        const ok = verdict === 'VERIFIED_PROXY_OK' || tlsCheck.port443Ok;
        return {
          id: target.id,
          label: target.label,
          domain: target.domain,
          ok,
          latencyMs: resolved.latencyMs,
          verdict,
        } satisfies AutopilotServiceCheck;
      } catch {
        return {
          id: target.id,
          label: target.label,
          domain: target.domain,
          ok: false,
          latencyMs: null,
          verdict: 'DNS_TIMEOUT',
        } satisfies AutopilotServiceCheck;
      }
    });
    return results;
  }

  private startWatchdog() {
    this.stopWatchdog();
    this.watchdogTimer = setInterval(() => {
      this.runWatchdogTick().catch(() => {
        // Never crash server on transient watchdog error
      });
    }, WATCHDOG_INTERVAL_MS);
  }

  private stopWatchdog() {
    if (this.watchdogTimer !== null) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  private async runWatchdogTick() {
    if (this.isRunning || !this.state.activeServerId) return;
    if (this.state.phase !== 'active' && this.state.phase !== 'degraded') return;

    const current = dnsDb.getServerById(this.state.activeServerId);
    if (!current) return;

    const probe = await runFourStageProbe(current, 'gemini.google.com', true);
    const updated = dnsDb.saveProbeResult(probe) ?? current;
    this.state.activeLatencyMs = updated.lastLatencyMs;
    this.state.lastCheckAt = new Date().toISOString();

    const decision = shouldTriggerWatchdogFailover(probe, 2500);
    if (decision.shouldSwitch) {
      await this.forceRotate(`Авто-переключение: ${decision.reason}`);
    }
  }
}

export const autopilotOrchestrator = new AiAutopilotOrchestrator();
