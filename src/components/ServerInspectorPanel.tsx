import React, { useState } from 'react';
import { Check, Copy, ExternalLink, Play, RefreshCw, Square, Trash2, X } from 'lucide-react';
import { DnsServer } from '../core/types';
import { getEndpointLabel } from './ServerCard';
import { Sparkline } from './Sparkline';

interface ServerInspectorPanelProps {
  server: DnsServer | null;
  isActive: boolean;
  isProbing: boolean;
  onProbe: (server: DnsServer) => void;
  onToggleStart: (server: DnsServer) => void;
  onDeleteCustom: (server: DnsServer) => void;
  onClose: () => void;
}

export const ServerInspectorPanel: React.FC<ServerInspectorPanelProps> = ({
  server,
  isActive,
  isProbing,
  onProbe,
  onToggleStart,
  onDeleteCustom,
  onClose,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyText = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1500);
    } catch {
      // ignore
    }
  };

  if (!server) {
    return (
      <aside
        aria-label="Инспектор DNS"
        className="hidden xl:flex flex-col justify-center items-center text-center rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-8 min-h-[320px] sticky top-20"
      >
        <div className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
          Выберите узел для инспекции
        </div>
        <p className="text-xs text-[#64748B] dark:text-[#94A3B8] mt-1.5 max-w-[240px] leading-relaxed">
          Кликните по любому DNS в списке, чтобы увидеть детали 4 этапов, историю задержек и команду PowerShell для Windows 11.
        </p>
      </aside>
    );
  }

  const endpoint = getEndpointLabel(server);
  const win11Cmd = server.dohUrl
    ? `Add-DnsClientDohServerAddress -ServerAddress "${server.primaryIp || '1.1.1.1'}" -DohTemplate "${server.dohUrl}" -AllowFallbackToUdp $True -AutoUpgrade $True`
    : `Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "${server.primaryIp || server.smartProxyIp || '1.1.1.1'}"`;

  return (
    <aside
      aria-label={`Инспектор ${server.name}`}
      className="hidden xl:flex flex-col gap-4 rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-5 sticky top-20 max-h-[calc(100vh-6rem)] overflow-y-auto"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
            {server.name}
          </h2>
          <p className="font-mono text-xs text-[#64748B] dark:text-[#94A3B8] mt-0.5 truncate">
            {server.provider} · {server.protocol} · {server.country}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Скрыть инспектор"
          className="p-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] text-[#64748B] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] cursor-pointer shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <p className="text-xs text-[#64748B] dark:text-[#94A3B8] leading-relaxed">
        {server.description || 'Публичный DNS-резолвер.'}
      </p>

      {/* Primary Action Row */}
      <div className="grid grid-cols-2 gap-2">
        <button
          type="button"
          onClick={() => onProbe(server)}
          disabled={isProbing}
          className="min-h-[36px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-60"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isProbing ? 'animate-spin' : ''}`} />
          <span>Проверить</span>
        </button>

        <button
          type="button"
          onClick={() => onToggleStart(server)}
          className={`min-h-[36px] px-3 py-1.5 rounded-md text-xs font-semibold inline-flex items-center justify-center gap-1.5 cursor-pointer ${
            isActive
              ? 'bg-[#22C55E] text-[#0B0D10] hover:bg-[#16A34A]'
              : 'bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10]'
          }`}
        >
          {isActive ? (
            <>
              <Square className="w-3 h-3 fill-current" />
              <span>Остановить</span>
            </>
          ) : (
            <>
              <Play className="w-3 h-3 fill-current" />
              <span>Запустить</span>
            </>
          )}
        </button>
      </div>

      {/* Endpoint Copy Box */}
      <div className="p-3 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] space-y-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
            Адрес подключения
          </span>
          <button
            type="button"
            onClick={() => copyText('endpoint', endpoint)}
            className="text-[11px] font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1 cursor-pointer hover:underline"
          >
            {copiedKey === 'endpoint' ? (
              <>
                <Check className="w-3 h-3 text-[#22C55E]" />
                <span>Скопировано</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Копировать</span>
              </>
            )}
          </button>
        </div>
        <div className="font-mono text-xs text-[#0F172A] dark:text-[#F1F5F9] break-all">
          {endpoint}
        </div>
        {server.secondaryIp && (
          <div className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8]">
            Резервный IP: {server.secondaryIp}
          </div>
        )}
      </div>

      {/* 4-Stage Telemetry Breakdown */}
      <div className="p-3 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] space-y-2.5">
        <div className="text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
          Телеметрия 4 этапов
        </div>
        <div className="grid grid-cols-2 gap-2 font-mono text-[11px] tabular-nums">
          <div>
            <div className="text-[#64748B] dark:text-[#94A3B8]">Пинг / Avg</div>
            <div className="text-[#0F172A] dark:text-[#F1F5F9] font-semibold">
              {server.lastLatencyMs ?? '—'} / {server.avgLatencyMs ?? '—'} мс
            </div>
          </div>
          <div>
            <div className="text-[#64748B] dark:text-[#94A3B8]">Джиттер / TPS</div>
            <div className="text-[#0F172A] dark:text-[#F1F5F9] font-semibold">
              ±{server.jitterMs ?? '—'} · {server.lastTps ?? '—'}
            </div>
          </div>
          <div>
            <div className="text-[#64748B] dark:text-[#94A3B8]">Порт 443 / HTTP</div>
            <div className="text-[#0F172A] dark:text-[#F1F5F9] font-semibold">
              {server.port443Ok === null ? '—' : server.port443Ok ? 'OK' : 'FAIL'} ({server.httpStatus ?? '—'})
            </div>
          </div>
          <div>
            <div className="text-[#64748B] dark:text-[#94A3B8]">API-домены</div>
            <div className="text-[#0F172A] dark:text-[#F1F5F9] font-semibold">
              {server.companionPassed === null ? 'N/A' : server.companionPassed ? 'OK' : 'DIRECT'}
            </div>
          </div>
        </div>
        {server.resolvedIps.length > 0 && (
          <div className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] break-all">
            IP ответа: {server.resolvedIps.join(', ')}
          </div>
        )}
        <Sparkline values={server.historyMs} verdict={server.verdict} compact={false} />
      </div>

      {/* Windows 11 PowerShell Command */}
      <div className="p-3 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] space-y-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
            PowerShell (Windows 11)
          </span>
          <button
            type="button"
            onClick={() => copyText('ps', win11Cmd)}
            className="text-[11px] font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1 cursor-pointer hover:underline"
          >
            {copiedKey === 'ps' ? (
              <>
                <Check className="w-3 h-3 text-[#22C55E]" />
                <span>Скопировано</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Копировать</span>
              </>
            )}
          </button>
        </div>
        <pre className="font-mono text-[10.5px] text-[#64748B] dark:text-[#94A3B8] whitespace-pre-wrap break-all bg-[#FFFFFF] dark:bg-[#0B0D10] p-2 rounded border border-[#DCE1E8] dark:border-[#262C36]">
          {win11Cmd}
        </pre>
        <a
          href="ms-settings:network-status"
          className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] inline-flex items-center gap-1"
        >
          <ExternalLink className="w-3 h-3" />
          <span>Параметры сети Windows</span>
        </a>
      </div>

      {!server.isBuiltin && (
        <button
          type="button"
          onClick={() => onDeleteCustom(server)}
          className="min-h-[36px] px-3 py-1.5 rounded-md border border-[#EF4444]/40 text-[#EF4444] text-xs font-semibold inline-flex items-center justify-center gap-1.5 cursor-pointer hover:bg-[#EF4444]/10"
        >
          <Trash2 className="w-3.5 h-3.5" />
          <span>Удалить пользовательский сервер</span>
        </button>
      )}
    </aside>
  );
};
