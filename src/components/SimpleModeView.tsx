import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Loader2,
  Power,
  RefreshCw,
  ShieldCheck,
  Square,
  XCircle,
} from 'lucide-react';
import { AutopilotState, TunnelState } from '../core/types';
import { AiAppsCaptureCard } from './AiAppsCaptureCard';

interface SimpleModeViewProps {
  autopilot: AutopilotState;
  tunnel: TunnelState;
  busy: boolean;
  onStartAutopilot: () => Promise<void>;
  onStopAutopilot: () => Promise<void>;
  onRotateAutopilot: () => Promise<void>;
  onSwitchToExpert: () => void;
}

export const SimpleModeView: React.FC<SimpleModeViewProps> = ({
  autopilot,
  tunnel,
  busy,
  onStartAutopilot,
  onStopAutopilot,
  onRotateAutopilot,
  onSwitchToExpert,
}) => {
  const isRunning = busy || autopilot.phase === 'running';
  const isActive = autopilot.phase === 'active' || autopilot.phase === 'degraded' || tunnel.active;

  const handleMainButtonClick = () => {
    if (isRunning) return;
    if (isActive) {
      onStopAutopilot();
    } else {
      onStartAutopilot();
    }
  };

  return (
    <div className="space-y-5">
      {/* Single-Button Bypass Control */}
      <section
        aria-label="Обход блокировок ИИ"
        className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-6 sm:p-7"
      >
        <div className="max-w-xl mx-auto text-center space-y-4">
          <div className="space-y-1.5">
            <div className="inline-flex items-center justify-center w-11 h-11 rounded-full bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36]">
              {isRunning ? (
                <Loader2 className="w-5 h-5 text-[#22C55E] animate-spin" />
              ) : isActive ? (
                <ShieldCheck className="w-5 h-5 text-[#16A34A] dark:text-[#22C55E]" />
              ) : (
                <Power className="w-5 h-5 text-[#64748B] dark:text-[#94A3B8]" />
              )}
            </div>

            <h1 className="text-2xl font-bold tracking-tight text-[#0F172A] dark:text-[#F1F5F9]">
              Обход блокировок ИИ
            </h1>
          </div>

          {/* Primary Action Button */}
          <div className="flex flex-wrap items-center justify-center gap-3">
            <button
              type="button"
              onClick={handleMainButtonClick}
              disabled={isRunning}
              data-testid="autopilot-main-button"
              className={`min-h-[52px] min-w-[240px] px-7 py-3 rounded-lg text-base font-semibold inline-flex items-center justify-center gap-2.5 transition-colors cursor-pointer disabled:opacity-70 ${
                isActive
                  ? 'bg-[#EF4444] hover:bg-[#DC2626] text-[#FFFFFF]'
                  : 'bg-[#22C55E] hover:bg-[#16A34A] text-[#0B0D10]'
              }`}
            >
              {isRunning ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Подбор узла...</span>
                </>
              ) : isActive ? (
                <>
                  <Square className="w-4 h-4 fill-current" />
                  <span>Отключить обход</span>
                </>
              ) : (
                <>
                  <Power className="w-5 h-5" />
                  <span>Включить обход</span>
                </>
              )}
            </button>

            {isActive && !isRunning && (
              <button
                type="button"
                onClick={onRotateAutopilot}
                className="min-h-[52px] px-5 py-3 rounded-lg bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-2 cursor-pointer hover:border-[#94A3B8]"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Сменить узел</span>
              </button>
            )}
          </div>

          {/* Compact Technical Status Line */}
          {autopilot.phase !== 'idle' || isActive ? (
            <p className="text-xs font-medium text-[#64748B] dark:text-[#94A3B8]">
              {autopilot.summary}
            </p>
          ) : (
            <p className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8]">
              DNS {autopilot.localDnsAddress} · Proxy http://{autopilot.localProxyAddress}
            </p>
          )}
        </div>

        {/* Active Node Metrics */}
        {isActive && (
          <div className="mt-6 pt-5 border-t border-[#DCE1E8] dark:border-[#262C36] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-0.5">
              <div className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
                Узел
              </div>
              <div className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
                {autopilot.activeServerName || tunnel.serverName || '—'}
              </div>
              <div className="font-mono text-xs text-[#16A34A] dark:text-[#22C55E] tabular-nums">
                {autopilot.activeProtocol || tunnel.protocol || 'DoH'} ·{' '}
                {autopilot.activeLatencyMs !== null
                  ? `${Math.round(autopilot.activeLatencyMs)} мс`
                  : '—'}
              </div>
            </div>

            <div className="space-y-0.5">
              <div className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
                Локальный прокси
              </div>
              <div className="font-mono text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] tabular-nums">
                http://{autopilot.localProxyAddress}
              </div>
              <div className="font-mono text-xs text-[#64748B] dark:text-[#94A3B8] tabular-nums">
                DNS: {autopilot.localDnsAddress}
              </div>
            </div>

            <div className="space-y-0.5">
              <div className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
                Автопереключение
              </div>
              <div className="text-sm font-semibold text-[#16A34A] dark:text-[#22C55E]">
                Активно
              </div>
              <div className="font-mono text-xs text-[#64748B] dark:text-[#94A3B8] tabular-nums">
                Резерв: {autopilot.standbyCount} · смен: {autopilot.switchHistory.length}
              </div>
            </div>

            <div className="space-y-0.5">
              <div className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
                Трафик
              </div>
              <div className="font-mono text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] tabular-nums">
                DNS: {tunnel.queriesHandled} · Proxy: {tunnel.proxyConnectionsHandled}
              </div>
              <button
                type="button"
                onClick={onSwitchToExpert}
                className="text-xs font-medium text-[#16A34A] dark:text-[#22C55E] hover:underline cursor-pointer"
              >
                Эксперт →
              </button>
            </div>
          </div>
        )}

        {/* 4-Step Pipeline Progress */}
        <div className="mt-5 pt-4 border-t border-[#DCE1E8] dark:border-[#262C36] grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {autopilot.steps.map((step, idx) => (
            <div
              key={step.id}
              className="rounded-md bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] p-3 space-y-1"
            >
              <div className="flex items-center gap-2">
                {step.status === 'done' ? (
                  <CheckCircle2 className="w-4 h-4 text-[#16A34A] dark:text-[#22C55E] shrink-0" />
                ) : step.status === 'active' ? (
                  <Loader2 className="w-4 h-4 text-[#22C55E] animate-spin shrink-0" />
                ) : step.status === 'warn' ? (
                  <AlertTriangle className="w-4 h-4 text-[#D97706] dark:text-[#F59E0B] shrink-0" />
                ) : step.status === 'error' ? (
                  <XCircle className="w-4 h-4 text-[#DC2626] dark:text-[#EF4444] shrink-0" />
                ) : (
                  <Circle className="w-4 h-4 text-[#94A3B8] shrink-0" />
                )}
                <span className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8]">
                  0{idx + 1}
                </span>
              </div>
              <div className="text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] leading-snug">
                {step.label}
              </div>
              {step.detail && (
                <div className="text-[11px] text-[#64748B] dark:text-[#94A3B8] leading-snug">
                  {step.detail}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Service Verification Matrix */}
        {autopilot.serviceChecks.length > 0 && (
          <div className="mt-4 pt-4 border-t border-[#DCE1E8] dark:border-[#262C36] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
            {autopilot.serviceChecks.map((check) => (
              <div
                key={check.id}
                className="rounded-md bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] px-3 py-2.5 space-y-0.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
                    {check.label}
                  </span>
                  {check.ok ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#16A34A] dark:text-[#22C55E] shrink-0" />
                  ) : (
                    <AlertTriangle className="w-3.5 h-3.5 text-[#D97706] dark:text-[#F59E0B] shrink-0" />
                  )}
                </div>
                <div className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] truncate">
                  {check.domain}
                </div>
                <div className="font-mono text-[11px] tabular-nums text-[#0F172A] dark:text-[#F1F5F9]">
                  {check.latencyMs !== null ? `${Math.round(check.latencyMs)} мс` : '—'}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Auto-Switch Log */}
        {autopilot.switchHistory.length > 0 && (
          <div className="mt-4 pt-3 border-t border-[#DCE1E8] dark:border-[#262C36] space-y-1">
            {autopilot.switchHistory.slice(0, 4).map((ev, idx) => (
              <div
                key={`${ev.at}-${idx}`}
                className="text-xs font-mono text-[#64748B] dark:text-[#94A3B8]"
              >
                {new Date(ev.at).toLocaleTimeString('ru-RU')} ·{' '}
                {ev.fromServerName ? `${ev.fromServerName} → ` : ''}
                <span className="text-[#0F172A] dark:text-[#F1F5F9] font-semibold">
                  {ev.toServerName}
                </span>{' '}
                ({ev.reason})
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Desktop & CLI AI Apps Capture Section */}
      <AiAppsCaptureCard
        proxyAddress={autopilot.localProxyAddress}
        tunnelActive={isActive}
        compact
      />
    </div>
  );
};
