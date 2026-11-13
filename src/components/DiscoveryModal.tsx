import React, { useState } from 'react';
import { Loader2, Radar, SearchCheck, X } from 'lucide-react';
import { DOMAIN_PRESETS } from '../core/presets';
import { DiscoveryNode, DnsServer, SyncStatus } from '../core/types';

interface DiscoveryModalProps {
  open: boolean;
  initialDomain: string;
  onClose: () => void;
  onServersUpdated: (servers: DnsServer[], syncStatus?: SyncStatus) => void;
}

const MODAL_PRESET_IDS = [
  'gemini',
  'aistudio',
  'chatgpt',
  'claude',
  'spotify',
  'xbox',
  'brawlstars',
];

export const DiscoveryModal: React.FC<DiscoveryModalProps> = ({
  open,
  initialDomain,
  onClose,
  onServersUpdated,
}) => {
  const [targetDomain, setTargetDomain] = useState(initialDomain || 'gemini.google.com');
  const [subnet, setSubnet] = useState('AUTO');
  const [scanUdp53, setScanUdp53] = useState(true);
  const [checkPort443, setCheckPort443] = useState(true);
  const [isParsing, setIsParsing] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [nodes, setNodes] = useState<DiscoveryNode[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!open) return null;

  const modalPresets = DOMAIN_PRESETS.filter((p) => MODAL_PRESET_IDS.includes(p.id));

  const handleParserAndCheck = async () => {
    setIsParsing(true);
    setErrorMessage(null);
    setStatusMessage(`Синхронизация онлайн-источников и 4-этапная проверка для ${targetDomain}...`);
    try {
      const res = await fetch('/api/discovery/parse-and-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetDomain: targetDomain.trim() || 'gemini.google.com',
          requiresBypass: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Ошибка парсера');
      setNodes(data.liveNodes || []);
      onServersUpdated(data.servers || [], data.syncStatus);
      setStatusMessage(
        `Готово: проверено ${data.liveNodes?.length ?? 0} узлов, кэш доменов: ${data.syncStatus?.cachedHostsCount ?? 0}`
      );
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Ошибка парсинга');
    } finally {
      setIsParsing(false);
    }
  };

  const handleSubnetScan = async () => {
    setIsScanning(true);
    setErrorMessage(null);
    setProgress(18);
    setStatusMessage(`Сканирование ${subnet} для ${targetDomain}...`);

    const timer = setInterval(() => {
      setProgress((prev) => (prev < 88 ? prev + 12 : prev));
    }, 450);

    try {
      const res = await fetch('/api/discovery/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subnet: subnet.trim() || 'AUTO',
          targetDomain: targetDomain.trim() || 'gemini.google.com',
          requiresBypass: true,
          scanUdp53,
          checkPort443,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Ошибка сканера');
      setProgress(100);
      setNodes(data.foundNodes || []);
      onServersUpdated(data.servers || []);
      setStatusMessage(
        `Проверено адресов: ${data.scannedCount}. Найдено рабочих узлов: ${data.foundNodes?.length ?? 0} (сохранены в SQLite + JSON-сейф)`
      );
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Ошибка сканирования');
    } finally {
      clearInterval(timer);
      setIsScanning(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
      role="dialog"
      aria-modal="true"
      aria-label="Подбор и сканер DNS"
    >
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-6 space-y-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
              Подбор рабочих DNS и SNI-прокси
            </h2>
            <p className="text-xs text-[#64748B] dark:text-[#94A3B8] mt-0.5">
              Онлайн-парсер и сканер подсетей /24 с проверкой порта 443 и анти-Direct-IP фильтром
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть подбор"
            className="p-2 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] text-[#64748B] dark:text-[#94A3B8] hover:text-[#0F172A] dark:hover:text-[#F1F5F9] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Target domain presets inside modal */}
        <div className="space-y-2.5">
          <div className="text-xs font-medium text-[#64748B] dark:text-[#94A3B8]">
            Целевой сервис / домен проверки
          </div>
          <div className="flex flex-wrap gap-1.5">
            {modalPresets.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => setTargetDomain(preset.domain)}
                className={`min-h-[34px] px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  targetDomain === preset.domain
                    ? 'bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10]'
                    : 'bg-[#EEF1F5] dark:bg-[#1B2028] text-[#0F172A] dark:text-[#F1F5F9] hover:bg-[#E2E8F0] dark:hover:bg-[#242B35]'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={targetDomain}
            onChange={(e) => setTargetDomain(e.target.value)}
            aria-label="Домен для проверки обхода"
            placeholder="gemini.google.com"
            className="w-full min-h-[38px] px-3 py-2 rounded-md font-mono text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9] focus:outline-none focus:border-[#22C55E]"
          />
        </div>

        {/* Mode 1: Online parser + bypass check */}
        <div className="p-4 rounded-lg bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
              Онлайн-источники (malw.link, QuickDNS, GitHub)
            </div>
            <div className="text-xs text-[#64748B] dark:text-[#94A3B8] mt-0.5">
              Загружает свежие списки и сразу проверяет 443/SNI для {targetDomain}
            </div>
          </div>
          <button
            type="button"
            onClick={handleParserAndCheck}
            disabled={isParsing || isScanning}
            className="min-h-[40px] px-4 py-2 rounded-md bg-[#22C55E] hover:bg-[#16A34A] text-[#0B0D10] text-xs font-semibold whitespace-nowrap shrink-0 inline-flex items-center gap-2 cursor-pointer disabled:opacity-60"
          >
            {isParsing ? <Loader2 className="w-4 h-4 animate-spin" /> : <SearchCheck className="w-4 h-4" />}
            <span>Парсер + проверка обхода</span>
          </button>
        </div>

        {/* Mode 2: /24 Subnet & SNI Scanner */}
        <div className="p-4 rounded-lg bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] space-y-3">
          <div className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
            Сканер подсетей /24 и открытых SNI-прокси
          </div>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <input
              type="text"
              value={subnet}
              onChange={(e) => setSubnet(e.target.value)}
              aria-label="Подсеть или AUTO"
              placeholder="AUTO или 192.255.159.0/24"
              className="flex-1 min-h-[38px] px-3 py-2 rounded-md font-mono text-xs bg-[#FFFFFF] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]"
            />
            <button
              type="button"
              onClick={handleSubnetScan}
              disabled={isScanning || isParsing}
              className="min-h-[38px] px-4 py-2 rounded-md bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold whitespace-nowrap shrink-0 inline-flex items-center gap-2 cursor-pointer disabled:opacity-60"
            >
              {isScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
              <span>Сканировать</span>
            </button>
          </div>

          <div className="flex flex-wrap gap-4 text-xs text-[#0F172A] dark:text-[#F1F5F9]">
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={scanUdp53}
                onChange={(e) => setScanUdp53(e.target.checked)}
                className="accent-[#22C55E]"
              />
              <span>Сканировать UDP 53 (Smart-DNS)</span>
            </label>
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={checkPort443}
                onChange={(e) => setCheckPort443(e.target.checked)}
                className="accent-[#22C55E]"
              />
              <span>Проверять порт 443 (SNI-прокси)</span>
            </label>
          </div>

          {(isScanning || progress > 0) && (
            <div className="w-full h-1.5 rounded-full bg-[#DCE1E8] dark:bg-[#262C36] overflow-hidden">
              <div
                className="h-full bg-[#22C55E] transition-all duration-200"
                style={{ width: `${progress}%` }}
              />
            </div>
          )}
        </div>

        {statusMessage && (
          <div className="text-xs text-[#64748B] dark:text-[#94A3B8]">{statusMessage}</div>
        )}
        {errorMessage && (
          <div className="text-xs text-[#EF4444] font-medium">{errorMessage}</div>
        )}

        {/* Live results list */}
        {nodes.length > 0 && (
          <div className="space-y-2 max-h-[240px] overflow-y-auto pr-1">
            {nodes.map((n) => (
              <div
                key={n.id}
                className="flex items-center justify-between gap-3 px-3 py-2 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36]"
              >
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
                    {n.verdict === 'VERIFIED_PROXY_OK' ? '✓ ' : '• '}
                    {n.name} ({n.latencyMs} мс)
                  </div>
                  <div className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] truncate">
                    {n.ipOrEndpoint} · {n.verdictReason}
                  </div>
                </div>
                <span
                  className={`font-mono text-[11px] font-medium whitespace-nowrap shrink-0 ${
                    n.verdict === 'VERIFIED_PROXY_OK'
                      ? 'text-[#16A34A] dark:text-[#22C55E]'
                      : n.verdict === 'DIRECT_NO_PROXY'
                        ? 'text-[#D97706] dark:text-[#F59E0B]'
                        : 'text-[#64748B] dark:text-[#94A3B8]'
                  }`}
                >
                  {n.port443Ok ? '443 OK' : n.protocol}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
