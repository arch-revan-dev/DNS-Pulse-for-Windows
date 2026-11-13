import React from 'react';
import { Info, Loader2, Play, Square, Star } from 'lucide-react';
import { DnsServer } from '../core/types';
import { Sparkline } from './Sparkline';

interface ServerCardProps {
  server: DnsServer;
  isActive: boolean;
  isBest: boolean;
  isProbing: boolean;
  onProbeSingle: (server: DnsServer) => void;
  onToggleStart: (server: DnsServer) => void;
  onToggleFavorite: (server: DnsServer) => void;
  onOpenDetails: (server: DnsServer) => void;
}

function getEndpointLabel(s: DnsServer): string {
  if (s.protocol === 'DoH' && s.dohUrl) return s.dohUrl;
  if (s.protocol === 'DoT' && s.dotHost) return `tls://${s.dotHost}:853`;
  if (s.protocol === 'SNI443') return `smartproxy://${s.smartProxyIp || s.primaryIp}:443`;
  return s.primaryIp || s.dotHost || s.dohUrl || '—';
}

function getStatusDotColor(server: DnsServer, isActive: boolean): string {
  if (isActive) return 'bg-[#22C55E]';
  switch (server.verdict) {
    case 'VERIFIED_PROXY_OK':
      return 'bg-[#22C55E]';
    case 'DIRECT_NO_PROXY':
      return 'bg-[#F59E0B]';
    case 'GEO_REDIRECT_BLOCKED':
    case 'PROXY_PORT_DEAD':
    case 'DNS_TIMEOUT':
      return 'bg-[#EF4444]';
    default:
      return 'bg-[#64748B]';
  }
}

function getVerdictTextColor(server: DnsServer): string {
  switch (server.verdict) {
    case 'VERIFIED_PROXY_OK':
      return 'text-[#16A34A] dark:text-[#22C55E]';
    case 'DIRECT_NO_PROXY':
      return 'text-[#D97706] dark:text-[#F59E0B]';
    case 'GEO_REDIRECT_BLOCKED':
    case 'PROXY_PORT_DEAD':
    case 'DNS_TIMEOUT':
      return 'text-[#DC2626] dark:text-[#EF4444]';
    default:
      return 'text-[#64748B] dark:text-[#94A3B8]';
  }
}

export const ServerCard: React.FC<ServerCardProps> = ({
  server,
  isActive,
  isBest,
  isProbing,
  onProbeSingle,
  onToggleStart,
  onToggleFavorite,
  onOpenDetails,
}) => {
  const endpoint = getEndpointLabel(server);
  const protoLabel = server.protocol === 'SNI443' ? '443' : server.protocol;

  return (
    <article
      data-testid={`server-card-${server.id}`}
      className={`rounded-lg border transition-colors p-4 ${
        isActive
          ? 'bg-[#FFFFFF] dark:bg-[#13161B] border-[#22C55E]/70'
          : 'bg-[#FFFFFF] dark:bg-[#13161B] border-[#DCE1E8] dark:border-[#262C36] hover:border-[#94A3B8]/50 dark:hover:border-[#3A4352]'
      }`}
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Left column: indicator, name, metadata, verdict */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${getStatusDotColor(server, isActive)}`}
              aria-hidden="true"
            />
            <h3 className="text-[15px] font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
              {server.name}
            </h3>

            <span className="font-mono text-[11px] font-medium px-1.5 py-0.5 rounded bg-[#EEF1F5] dark:bg-[#1B2028] text-[#0F172A] dark:text-[#F1F5F9] shrink-0">
              {protoLabel}
            </span>

            {server.isSubscription && (
              <span className="font-mono text-[11px] font-medium px-1.5 py-0.5 rounded bg-[#F59E0B]/15 text-[#D97706] dark:text-[#F59E0B] shrink-0">
                ЛИЧНЫЙ
              </span>
            )}

            {isBest && !server.isSubscription && (
              <span className="font-mono text-[11px] font-medium px-1.5 py-0.5 rounded bg-[#22C55E]/15 text-[#16A34A] dark:text-[#22C55E] shrink-0">
                ЛУЧШИЙ
              </span>
            )}

            <button
              type="button"
              onClick={() => onToggleFavorite(server)}
              aria-label={`Избранное ${server.name}`}
              aria-pressed={server.isFavorite}
              className={`p-1 rounded transition-colors shrink-0 ${
                server.isFavorite
                  ? 'text-[#F59E0B]'
                  : 'text-[#64748B] hover:text-[#0F172A] dark:hover:text-[#F1F5F9]'
              }`}
              title={server.isFavorite ? 'Убрать из избранного' : 'В избранное'}
            >
              <Star className="w-3.5 h-3.5" fill={server.isFavorite ? 'currentColor' : 'none'} />
            </button>
          </div>

          <div className="mt-1 font-mono text-xs text-[#64748B] dark:text-[#94A3B8] truncate">
            {server.category} · {endpoint}
          </div>

          <div className={`mt-1 text-xs font-medium flex items-center gap-1.5 ${getVerdictTextColor(server)}`}>
            <span>{isProbing ? 'Выполняется 4-этапная проверка...' : server.verdictReason}</span>
            {server.jitterMs !== null && server.lastLatencyMs !== null && !isProbing && (
              <span className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] tabular-nums">
                · ±{Math.round(server.jitterMs)} мс
              </span>
            )}
          </div>
        </div>

        {/* Right column: clickable latency + TPS, Start/Active button, details button */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => onProbeSingle(server)}
            disabled={isProbing}
            aria-label={`Проверить ${server.name}`}
            className="min-h-[38px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] hover:bg-[#E2E8F0] dark:hover:bg-[#242B35] border border-[#DCE1E8] dark:border-[#262C36] text-right transition-colors cursor-pointer disabled:opacity-60"
            title="Нажмите для одиночного 4-этапного теста"
          >
            <div className="font-mono text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] tabular-nums whitespace-nowrap flex items-center justify-end gap-1.5">
              {isProbing && <Loader2 className="w-3.5 h-3.5 animate-spin text-[#64748B]" />}
              <span>{server.lastLatencyMs !== null ? `${Math.round(server.lastLatencyMs)} мс` : 'Тест'}</span>
            </div>
            <div className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] tabular-nums whitespace-nowrap">
              {server.lastTps !== null ? `${server.lastTps} TPS` : '4 этапа'}
            </div>
          </button>

          <button
            type="button"
            onClick={() => onToggleStart(server)}
            aria-label={isActive ? `Остановить ${server.name}` : `Запустить ${server.name}`}
            className={`min-h-[38px] px-4 py-2 rounded-md text-xs font-semibold whitespace-nowrap shrink-0 inline-flex items-center gap-1.5 transition-colors cursor-pointer ${
              isActive
                ? 'bg-[#22C55E] text-[#0B0D10] hover:bg-[#16A34A]'
                : 'bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] hover:opacity-90'
            }`}
          >
            {isActive ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Активен</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Старт</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => onOpenDetails(server)}
            aria-label={`Детали ${server.name}`}
            className="min-h-[38px] w-[38px] rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] hover:bg-[#E2E8F0] dark:hover:bg-[#242B35] border border-[#DCE1E8] dark:border-[#262C36] inline-flex items-center justify-center text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] transition-colors shrink-0 cursor-pointer"
            title="Детали и настройка Windows 11 DoH"
          >
            <Info className="w-4 h-4" />
          </button>
        </div>
      </div>

      <Sparkline values={server.historyMs} verdict={server.verdict} />
    </article>
  );
};
