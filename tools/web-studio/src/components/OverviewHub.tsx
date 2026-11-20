import React, { useState } from 'react';
import {
  AppWindow,
  Check,
  Copy,
  Loader2,
  Power,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import {
  AI_READINESS_SERVICES,
  AiReadinessService,
  buildPowerShellLaunchCommand,
  DEFAULT_LOCAL_PAC_PORT,
  DEFAULT_LOCAL_PROXY_PORT,
  DESKTOP_AI_APPS,
} from '../core/aiApps';
import { BypassVerdict, TunnelState } from '../core/types';

export interface ServiceReadinessState {
  status: 'idle' | 'checking' | 'ok' | 'direct' | 'error';
  verdict?: BypassVerdict;
  latencyMs: number | null;
  resolvedIp: string | null;
  detail: string;
}

interface OverviewHubProps {
  tunnel: TunnelState;
  activeServerLatencyMs: number | null;
  autopilotBusy: boolean;
  autopilotMessage: string | null;
  serviceChecks: Record<AiReadinessService['id'], ServiceReadinessState>;
  checkingServices: boolean;
  onToggleAutopilot: () => void;
  onRotateTunnel: () => void;
  onVerifyAllServices: () => void;
  onOpenTesterForDomain: (domain: string) => void;
}

export const OverviewHub: React.FC<OverviewHubProps> = ({
  tunnel,
  activeServerLatencyMs,
  autopilotBusy,
  autopilotMessage,
  serviceChecks,
  checkingServices,
  onToggleAutopilot,
  onRotateTunnel,
  onVerifyAllServices,
  onOpenTesterForDomain,
}) => {
  const [copiedAppId, setCopiedAppId] = useState<string | null>(null);

  const handleCopyCommand = async (appId: string, command: string) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(command);
      }
    } catch {
      // Fallback still confirms command selection in restricted contexts
    }
    setCopiedAppId(appId);
    window.setTimeout(() => {
      setCopiedAppId((current) => (current === appId ? null : current));
    }, 1800);
  };

  const statusHeadline = autopilotBusy
    ? 'Подбор рабочего узла...'
    : tunnel.active
      ? 'Обход активен'
      : 'Готов к запуску';

  const statusSubtitle = autopilotBusy
    ? autopilotMessage || 'Тестируем Smart-DNS и проверяем обход сервисов ИИ'
    : tunnel.active
      ? `${tunnel.serverName || 'Smart-DNS'}${activeServerLatencyMs !== null ? ` · ${Math.round(activeServerLatencyMs)} мс` : ''}${tunnel.protocol ? ` · ${tunnel.protocol}` : ''}`
      : autopilotMessage || 'Нажмите кнопку — подберём быстрый Smart-DNS и проверим доступ к ИИ';

  return (
    <div className="max-w-[840px] mx-auto space-y-5 pb-8">
      {/* Frosted Squircle Hero Card */}
      <section
        aria-label="Управление обходом"
        className="glass-surface rounded-[24px] overflow-hidden"
      >
        <div className="px-6 sm:px-10 pt-9 pb-7 flex flex-col items-center text-center">
          {/* Tactile iOS × Windows 11 Power Orb */}
          <div
            className={`relative flex items-center justify-center w-[144px] h-[144px] rounded-full transition-colors duration-300 ${
              tunnel.active
                ? 'bg-[#34C759]/14 dark:bg-[#30D158]/16'
                : autopilotBusy
                  ? 'bg-[#007AFF]/12 dark:bg-[#0A84FF]/16'
                  : 'bg-black/[0.04] dark:bg-white/[0.05]'
            }`}
          >
            <button
              type="button"
              onClick={onToggleAutopilot}
              disabled={autopilotBusy}
              aria-label={tunnel.active ? 'Переключатель обхода: активен' : 'Переключатель обхода: выключен'}
              aria-pressed={tunnel.active}
              className={`relative w-[114px] h-[114px] rounded-full flex items-center justify-center transition-all duration-200 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[#007AFF] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent active:scale-[0.97] disabled:cursor-wait ${
                tunnel.active
                  ? 'bg-[#34C759] dark:bg-[#30D158] text-white shadow-[0_10px_28px_-6px_rgba(48,209,88,0.55)]'
                  : 'bg-white dark:bg-[#232732] text-[#0F172A] dark:text-[#F5F7FA] border border-black/[0.08] dark:border-white/[0.12] shadow-[0_8px_22px_-10px_rgba(15,23,42,0.22)] hover:border-[#007AFF]/45 dark:hover:border-[#0A84FF]/55'
              }`}
            >
              {autopilotBusy ? (
                <Loader2 className="w-10 h-10 animate-spin text-[#007AFF] dark:text-[#0A84FF]" />
              ) : (
                <Power className="w-10 h-10 stroke-[2.2]" />
              )}
            </button>
          </div>

          <h1 className="mt-5 text-[24px] leading-tight font-semibold tracking-[-0.02em] text-[#0F172A] dark:text-[#F5F7FA]">
            {statusHeadline}
          </h1>
          <p className="mt-1.5 text-sm text-[#5C6672] dark:text-[#9CA3AF] max-w-[460px]">
            {statusSubtitle}
          </p>

          {/* Primary Squircle Action Controls */}
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
            <button
              type="button"
              onClick={onToggleAutopilot}
              disabled={autopilotBusy}
              className={`min-h-[44px] px-7 py-2.5 rounded-[14px] text-sm font-semibold transition-all cursor-pointer disabled:opacity-65 disabled:cursor-wait ${
                tunnel.active
                  ? 'bg-[#FF3B30]/12 dark:bg-[#FF453A]/18 text-[#D70015] dark:text-[#FF6961] border border-[#FF3B30]/25 hover:bg-[#FF3B30]/18'
                  : 'bg-[#007AFF] dark:bg-[#0A84FF] text-white hover:bg-[#0066D6] dark:hover:bg-[#1E8FFF] shadow-[0_6px_18px_-6px_rgba(0,122,255,0.55)]'
              }`}
            >
              {autopilotBusy
                ? 'Подключаем...'
                : tunnel.active
                  ? 'Отключить обход'
                  : 'Включить обход'}
            </button>

            {tunnel.active && (
              <button
                type="button"
                onClick={onRotateTunnel}
                disabled={autopilotBusy}
                className="min-h-[44px] px-4 py-2.5 rounded-[14px] bg-black/[0.04] dark:bg-white/[0.07] border border-black/[0.08] dark:border-white/[0.10] text-sm font-medium text-[#0F172A] dark:text-[#F5F7FA] inline-flex items-center gap-1.5 hover:bg-black/[0.07] dark:hover:bg-white/[0.11] transition-colors cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Сменить узел</span>
              </button>
            )}
          </div>
        </div>

        {/* Hairline Technical Footer */}
        <div className="px-6 py-3.5 border-t border-black/[0.07] dark:border-white/[0.08] bg-black/[0.015] dark:bg-white/[0.02] flex flex-wrap items-center justify-between gap-2 text-xs text-[#5C6672] dark:text-[#9CA3AF]">
          <span className="font-mono tabular-nums">
            Прокси: 127.0.0.1:{DEFAULT_LOCAL_PROXY_PORT} · PAC :{DEFAULT_LOCAL_PAC_PORT}
          </span>
          <span className="font-mono tabular-nums">
            {tunnel.active
              ? `Локальный DNS: ${tunnel.listenAddress} · Запросов: ${tunnel.queriesHandled}`
              : 'Режим: Smart-DNS + Anti-Direct-IP + SNI 443'}
          </span>
        </div>
      </section>

      {/* 4-Column AI Services Live Readiness Strip */}
      <section
        aria-label="Готовность ИИ-сервисов"
        className="glass-surface rounded-[20px] overflow-hidden"
      >
        <div className="px-5 py-3.5 border-b border-black/[0.07] dark:border-white/[0.08] flex items-center justify-between gap-3">
          <h2 className="text-[13px] font-semibold text-[#0F172A] dark:text-[#F5F7FA]">
            Готовность ИИ-сервисов
          </h2>
          <button
            type="button"
            onClick={onVerifyAllServices}
            disabled={checkingServices}
            className="text-xs font-semibold text-[#007AFF] dark:text-[#0A84FF] hover:opacity-80 inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            {checkingServices && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            <span>{checkingServices ? 'Проверка...' : 'Проверить все'}</span>
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-black/[0.07] dark:divide-white/[0.08]">
          {AI_READINESS_SERVICES.map((svc) => {
            const state = serviceChecks[svc.id];
            const dotClass =
              state.status === 'ok'
                ? 'bg-[#34C759] dark:bg-[#30D158]'
                : state.status === 'direct'
                  ? 'bg-[#FF9500] dark:bg-[#FF9F0A]'
                  : state.status === 'error'
                    ? 'bg-[#FF3B30] dark:bg-[#FF453A]'
                    : state.status === 'checking'
                      ? 'bg-[#007AFF] dark:bg-[#0A84FF] animate-pulse'
                      : 'bg-[#94A3B8]/60';

            const statusColor =
              state.status === 'ok'
                ? 'text-[#1E8E3E] dark:text-[#30D158]'
                : state.status === 'direct'
                  ? 'text-[#C27803] dark:text-[#FF9F0A]'
                  : state.status === 'error'
                    ? 'text-[#D70015] dark:text-[#FF6961]'
                    : 'text-[#5C6672] dark:text-[#9CA3AF]';

            return (
              <button
                key={svc.id}
                type="button"
                onClick={() => onOpenTesterForDomain(svc.domain)}
                aria-label={`Открыть проверку ${svc.name} (${svc.domain}) в тестере`}
                className="p-4 text-left hover:bg-black/[0.025] dark:hover:bg-white/[0.03] transition-colors cursor-pointer min-w-0"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${dotClass}`} aria-hidden="true" />
                  <span className="text-[13px] font-semibold text-[#0F172A] dark:text-[#F5F7FA] truncate">
                    {svc.name}
                  </span>
                </div>
                <div className="mt-1 font-mono text-[11px] text-[#6E7781] dark:text-[#8E96A3] truncate">
                  {svc.domain}
                </div>
                <div className={`mt-2 font-mono text-[11px] font-medium truncate tabular-nums ${statusColor}`}>
                  {state.status === 'checking'
                    ? 'Проверка...'
                    : state.latencyMs !== null && state.status === 'ok'
                      ? `${Math.round(state.latencyMs)} мс${state.resolvedIp ? ` · ${state.resolvedIp}` : ''}`
                      : state.detail}
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {/* iOS Grouped Inset List: Desktop & CLI AI Applications */}
      <section
        aria-label="Программы и CLI для ИИ"
        className="glass-surface rounded-[20px] overflow-hidden"
      >
        <div className="px-5 py-3.5 border-b border-black/[0.07] dark:border-white/[0.08] flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[13px] font-semibold text-[#0F172A] dark:text-[#F5F7FA]">
            Программы и CLI для ИИ
          </h2>
          <span className="font-mono text-[11px] text-[#6E7781] dark:text-[#8E96A3]">
            Запуск через 127.0.0.1:{DEFAULT_LOCAL_PROXY_PORT} (защита loopback IPC)
          </span>
        </div>

        <ul className="divide-y divide-black/[0.07] dark:divide-white/[0.08]">
          {DESKTOP_AI_APPS.map((app) => {
            const cmd = buildPowerShellLaunchCommand(app, DEFAULT_LOCAL_PROXY_PORT);
            const isCopied = copiedAppId === app.id;
            return (
              <li
                key={app.id}
                className="px-5 py-3.5 flex items-center justify-between gap-3 hover:bg-black/[0.02] dark:hover:bg-white/[0.025] transition-colors"
              >
                <div className="flex items-center gap-3.5 min-w-0">
                  <div
                    className="w-9 h-9 rounded-[10px] bg-black/[0.045] dark:bg-white/[0.07] border border-black/[0.06] dark:border-white/[0.08] flex items-center justify-center shrink-0 text-[#0F172A] dark:text-[#F5F7FA]"
                    aria-hidden="true"
                  >
                    {app.kind === 'cli' ? (
                      <Terminal className="w-4 h-4" />
                    ) : (
                      <AppWindow className="w-4 h-4" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="text-[13.5px] font-semibold text-[#0F172A] dark:text-[#F5F7FA] truncate">
                      {app.name}
                    </div>
                    <div className="text-xs text-[#6E7781] dark:text-[#8E96A3] truncate">
                      {app.subtitle}
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleCopyCommand(app.id, cmd)}
                  aria-label={`Скопировать команду PowerShell для ${app.name}`}
                  className={`min-h-[34px] px-3 py-1.5 rounded-[10px] text-xs font-medium inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors cursor-pointer border ${
                    isCopied
                      ? 'bg-[#34C759]/14 dark:bg-[#30D158]/18 border-[#34C759]/35 text-[#1E8E3E] dark:text-[#30D158]'
                      : 'bg-black/[0.04] dark:bg-white/[0.07] border-black/[0.08] dark:border-white/[0.10] text-[#0F172A] dark:text-[#F5F7FA] hover:bg-black/[0.07] dark:hover:bg-white/[0.11]'
                  }`}
                >
                  {isCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{isCopied ? 'Скопировано' : 'Скопировать PS'}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
};
