import React, { useState } from 'react';
import { Check, Copy, ExternalLink, Trash2, X } from 'lucide-react';
import { DnsServer } from '../core/types';

interface ServerDetailsDrawerProps {
  server: DnsServer | null;
  onClose: () => void;
  onProbe: (server: DnsServer) => void;
  onDeleteCustom: (server: DnsServer) => void;
}

export const ServerDetailsDrawer: React.FC<ServerDetailsDrawerProps> = ({
  server,
  onClose,
  onProbe,
  onDeleteCustom,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!server) return null;

  const copyText = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1600);
    } catch {
      // Ignore clipboard failure
    }
  };

  const fields = [
    { key: 'doh', label: 'DoH URL (RFC 8484)', value: server.dohUrl || '—' },
    { key: 'dot', label: 'DoT Host (порт 853)', value: server.dotHost || '—' },
    { key: 'ip1', label: 'Primary IP', value: server.primaryIp || server.smartProxyIp || '—' },
    { key: 'ip2', label: 'Secondary IP', value: server.secondaryIp || '—' },
  ];

  const win11Cmd = server.dohUrl
    ? `Add-DnsClientDohServerAddress -ServerAddress "${server.primaryIp || '1.1.1.1'}" -DohTemplate "${server.dohUrl}" -AllowFallbackToUdp $True -AutoUpgrade $True`
    : null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-[1px]"
      role="dialog"
      aria-modal="true"
      aria-label={`Детали сервера ${server.name}`}
    >
      <div className="w-full max-w-lg bg-[#FFFFFF] dark:bg-[#13161B] border-l border-[#DCE1E8] dark:border-[#262C36] h-full overflow-y-auto p-6 flex flex-col gap-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
              {server.name}
            </h2>
            <p className="text-xs text-[#64748B] dark:text-[#94A3B8] mt-1">
              {server.provider} · {server.category} · {server.country}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть детали"
            className="p-2 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-sm text-[#64748B] dark:text-[#94A3B8] leading-relaxed">
          {server.description || 'Публичный DNS-резолвер.'}
        </p>

        {/* Copyable Endpoints */}
        <div className="space-y-2.5">
          {fields.map((f) => (
            <div
              key={f.key}
              className="flex items-center justify-between gap-3 p-3 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36]"
            >
              <div className="min-w-0">
                <div className="text-[11px] font-medium text-[#64748B] dark:text-[#94A3B8]">
                  {f.label}
                </div>
                <div className="font-mono text-xs text-[#0F172A] dark:text-[#F1F5F9] truncate mt-0.5">
                  {f.value}
                </div>
              </div>
              {f.value !== '—' && (
                <button
                  type="button"
                  onClick={() => copyText(f.key, f.value)}
                  className="min-h-[34px] px-3 py-1.5 rounded bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                >
                  {copiedKey === f.key ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                      <span>Скопировано</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Копировать</span>
                    </>
                  )}
                </button>
              )}
            </div>
          ))}
        </div>

        {/* Windows 11 Native DoH */}
        <div className="p-4 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] space-y-3">
          <div className="text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
            Нативный DoH для Windows 11
          </div>
          {win11Cmd && (
            <pre className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] whitespace-pre-wrap break-all bg-[#FFFFFF] dark:bg-[#0B0D10] p-2.5 rounded border border-[#DCE1E8] dark:border-[#262C36]">
              {win11Cmd}
            </pre>
          )}
          <div className="flex flex-wrap gap-2">
            {win11Cmd && (
              <button
                type="button"
                onClick={() => copyText('win11', win11Cmd)}
                className="min-h-[36px] px-3 py-1.5 rounded bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copiedKey === 'win11' ? 'Команда скопирована' : 'Копировать команду PowerShell'}</span>
              </button>
            )}
            <a
              href="ms-settings:network-status"
              className="min-h-[36px] px-3 py-1.5 rounded bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Параметры сети Windows</span>
            </a>
          </div>
        </div>

        {/* 4-Stage Diagnostic Report */}
        <div className="p-4 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] space-y-2">
          <div className="text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
            Диагностика 4 этапов
          </div>
          <div className="grid grid-cols-2 gap-2 font-mono text-xs tabular-nums">
            <div>
              <span className="text-[#64748B] dark:text-[#94A3B8]">Пинг / Min / Avg: </span>
              <span>
                {server.lastLatencyMs ?? '—'} / {server.minLatencyMs ?? '—'} / {server.avgLatencyMs ?? '—'} мс
              </span>
            </div>
            <div>
              <span className="text-[#64748B] dark:text-[#94A3B8]">Джиттер / TPS: </span>
              <span>
                ±{server.jitterMs ?? '—'} мс · {server.lastTps ?? '—'}
              </span>
            </div>
            <div>
              <span className="text-[#64748B] dark:text-[#94A3B8]">Порт 443 / HTTP: </span>
              <span>
                {server.port443Ok === null ? '—' : server.port443Ok ? 'OK' : 'FAIL'} ({server.httpStatus ?? '—'})
              </span>
            </div>
            <div>
              <span className="text-[#64748B] dark:text-[#94A3B8]">API-домены: </span>
              <span>
                {server.companionPassed === null ? 'N/A' : server.companionPassed ? 'OK' : 'DIRECT'}
              </span>
            </div>
          </div>
          {server.resolvedIps.length > 0 && (
            <div className="font-mono text-xs text-[#64748B] dark:text-[#94A3B8] pt-1">
              Возвращённый IP: {server.resolvedIps.join(', ')}
            </div>
          )}
        </div>

        <div className="mt-auto pt-4 border-t border-[#DCE1E8] dark:border-[#262C36] flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={() => onProbe(server)}
            className="min-h-[40px] px-4 py-2 rounded-md bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold cursor-pointer"
          >
            Проверить сейчас
          </button>

          {!server.isBuiltin && (
            <button
              type="button"
              onClick={() => onDeleteCustom(server)}
              className="min-h-[40px] px-4 py-2 rounded-md border border-[#EF4444]/40 text-[#EF4444] text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer hover:bg-[#EF4444]/10"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Удалить сервер</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
