import React, { useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  CircleDashed,
  Copy,
  Info,
  Loader2,
  Play,
  Square,
  Star,
  XCircle,
} from 'lucide-react';
import { DnsServer } from '../core/types';
import { Sparkline } from './Sparkline';

interface ServerCardProps {
  server: DnsServer;
  isActive: boolean;
  isSelected: boolean;
  isBest: boolean;
  isProbing: boolean;
  onSelect: (server: DnsServer) => void;
  onProbeSingle: (server: DnsServer) => void;
  onToggleStart: (server: DnsServer) => void;
  onToggleFavorite: (server: DnsServer) => void;
  onOpenDetails: (server: DnsServer) => void;
}

export function getEndpointLabel(s: DnsServer): string {
  if (s.protocol === 'DoH' && s.dohUrl) return s.dohUrl;
  if (s.protocol === 'DoT' && s.dotHost) return `tls://${s.dotHost}:853`;
  if (s.protocol === 'SNI443') return `smartproxy://${s.smartProxyIp || s.primaryIp}:443`;
  return s.primaryIp || s.dotHost || s.dohUrl || '—';
}

function StatusIcon({ server, isActive, isProbing }: { server: DnsServer; isActive: boolean; isProbing: boolean }) {
  if (isProbing) {
    return <Loader2 className="w-4 h-4 animate-spin text-[#64748B] shrink-0" aria-hidden="true" />;
  }
  if (isActive || server.verdict === 'VERIFIED_PROXY_OK') {
    return <CheckCircle2 className="w-4 h-4 text-[#16A34A] dark:text-[#22C55E] shrink-0" aria-hidden="true" />;
  }
  if (server.verdict === 'DIRECT_NO_PROXY') {
    return <AlertTriangle className="w-4 h-4 text-[#D97706] dark:text-[#F59E0B] shrink-0" aria-hidden="true" />;
  }
  if (
    server.verdict === 'GEO_REDIRECT_BLOCKED' ||
    server.verdict === 'PROXY_PORT_DEAD' ||
    server.verdict === 'DNS_TIMEOUT'
  ) {
    return <XCircle className="w-4 h-4 text-[#DC2626] dark:text-[#EF4444] shrink-0" aria-hidden="true" />;
  }
  return <CircleDashed className="w-4 h-4 text-[#64748B] shrink-0" aria-hidden="true" />;
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
  isSelected,
  isBest,
  isProbing,
  onSelect,
  onProbeSingle,
  onToggleStart,
  onToggleFavorite,
  onOpenDetails,
}) => {
  const [copied, setCopied] = useState(false);
  const endpoint = getEndpointLabel(server);
  const protoLabel = server.protocol === 'SNI443' ? 'SNI 443' : server.protocol;

  const handleCopyEndpoint = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(endpoint);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      // ignore clipboard errors
    }
  };

  return (
    <article
      data-testid={`server-card-${server.id}`}
      onClick={() => onSelect(server)}
      className={`rounded-lg border transition-colors px-4 py-3 cursor-pointer ${
        isActive
          ? 'bg-[#FFFFFF] dark:bg-[#13161B] border-[#22C55E]'
          : isSelected
            ? 'bg-[#FFFFFF] dark:bg-[#17201B] border-[#22C55E]/60'
            : 'bg-[#FFFFFF] dark:bg-[#13161B] border-[#DCE1E8] dark:border-[#262C36] hover:border-[#94A3B8]/60 dark:hover:border-[#3A4352]'
      }`}
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Left: Status Icon, Clean Title + Quiet Typographic Metadata */}
        <div className="min-w-0 flex-1 space-y-0.5">
          <div className="flex items-center gap-2 min-w-0">
            <StatusIcon server={server} isActive={isActive} isProbing={isProbing} />
            <h3 className="text-[14px] font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
              {server.name}
            </h3>
            <span className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] whitespace-nowrap shrink-0">
              · {protoLabel} · {server.country}
            </span>
            {isBest && !server.isSubscription && (
              <span className="text-[11px] font-semibold text-[#16A34A] dark:text-[#22C55E] whitespace-nowrap shrink-0">
                · Лучший
              </span>
            )}
            {server.isSubscription && (
              <span className="text-[11px] font-semibold text-[#D97706] dark:text-[#F59E0B] whitespace-nowrap shrink-0">
                · Личный
              </span>
            )}
          </div>

          <div className="flex items-center gap-1.5 min-w-0 pl-6">
            <span className="font-mono text-xs text-[#64748B] dark:text-[#94A3B8] truncate">
              {server.category} · {endpoint}
            </span>
            <button
              type="button"
              onClick={handleCopyEndpoint}
              aria-label={`Копировать адрес ${server.name}`}
              title="Копировать адрес"
              className="p-0.5 rounded text-[#64748B] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] shrink-0 cursor-pointer"
            >
              {copied ? (
                <Check className="w-3.5 h-3.5 text-[#22C55E]" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
            </button>
          </div>

          <div className={`pl-6 text-xs font-medium flex items-center gap-1.5 ${getVerdictTextColor(server)}`}>
            <span className="truncate">
              {isProbing ? 'Выполняется 4-этапная проверка...' : server.verdictReason}
            </span>
            {server.jitterMs !== null && server.lastLatencyMs !== null && !isProbing && (
              <span className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] tabular-nums shrink-0">
                · ±{Math.round(server.jitterMs)} мс
              </span>
            )}
          </div>
        </div>

        {/* Right: Compact Sparkline + Latency Probe + Favorite + Start + Mobile Details */}
        <div
          className="flex items-center justify-end gap-2 shrink-0 pl-6 sm:pl-0"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="hidden md:block">
            <Sparkline values={server.historyMs} verdict={server.verdict} compact />
          </div>

          <button
            type="button"
            onClick={() => onProbeSingle(server)}
            disabled={isProbing}
            aria-label={`Проверить ${server.name}`}
            className="min-h-[36px] min-w-[82px] px-2.5 py-1 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] hover:bg-[#E2E8F0] dark:hover:bg-[#242B35] border border-[#DCE1E8] dark:border-[#262C36] text-right transition-colors cursor-pointer disabled:opacity-60"
            title="Нажмите для 4-этапной проверки"
          >
            <div className="font-mono text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] tabular-nums whitespace-nowrap flex items-center justify-end gap-1">
              {isProbing && <Loader2 className="w-3 h-3 animate-spin text-[#64748B]" />}
              <span>{server.lastLatencyMs !== null ? `${Math.round(server.lastLatencyMs)} мс` : 'Тест'}</span>
            </div>
            <div className="font-mono text-[10px] text-[#64748B] dark:text-[#94A3B8] tabular-nums whitespace-nowrap">
              {server.lastTps !== null ? `${server.lastTps} TPS` : '4 этапа'}
            </div>
          </button>

          <button
            type="button"
            onClick={() => onToggleFavorite(server)}
            aria-label={`Избранное ${server.name}`}
            aria-pressed={server.isFavorite}
            className={`min-h-[36px] w-[36px] rounded-md border border-[#DCE1E8] dark:border-[#262C36] bg-[#F7F8FA] dark:bg-[#0B0D10] inline-flex items-center justify-center transition-colors shrink-0 cursor-pointer ${
              server.isFavorite
                ? 'text-[#F59E0B] border-[#F59E0B]/50'
                : 'text-[#64748B] hover:text-[#0F172A] dark:hover:text-[#F1F5F9]'
            }`}
            title={server.isFavorite ? 'Убрать из избранного' : 'В избранное'}
          >
            <Star className="w-3.5 h-3.5" fill={server.isFavorite ? 'currentColor' : 'none'} />
          </button>

          <button
            type="button"
            onClick={() => onToggleStart(server)}
            aria-label={isActive ? `Остановить ${server.name}` : `Запустить ${server.name}`}
            className={`min-h-[36px] min-w-[90px] px-3.5 py-1.5 rounded-md text-xs font-semibold whitespace-nowrap shrink-0 inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${
              isActive
                ? 'bg-[#22C55E] text-[#0B0D10] hover:bg-[#16A34A]'
                : 'bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] hover:opacity-90'
            }`}
          >
            {isActive ? (
              <>
                <Square className="w-3 h-3 fill-current" />
                <span>Активен</span>
              </>
            ) : (
              <>
                <Play className="w-3 h-3 fill-current" />
                <span>Старт</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => onOpenDetails(server)}
            aria-label={`Детали ${server.name}`}
            className="xl:hidden min-h-[36px] w-[36px] rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] inline-flex items-center justify-center text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] shrink-0 cursor-pointer"
            title="Детали и настройка Windows 11"
          >
            <Info className="w-4 h-4" />
          </button>
        </div>
      </div>
    </article>
  );
};
