import React, { useRef, useState } from 'react';
import {
  Check,
  Copy,
  Download,
  FileUp,
  Moon,
  Plus,
  RefreshCw,
  RotateCcw,
  Sun,
} from 'lucide-react';
import { exportServersToCsv } from '../core/filterSort';
import { DnsServer, SyncStatus } from '../core/types';

interface AppSettings {
  theme: 'dark' | 'light';
  autoConnectBestOnRotate: boolean;
  freeOnly: boolean;
  hotkeyRotate: string;
}

interface ConfigsTabProps {
  servers: DnsServer[];
  syncStatus: SyncStatus;
  settings: AppSettings;
  onOpenManualAdd: () => void;
  onOpenDiscovery: () => void;
  onServersImported: (allServers: DnsServer[]) => void;
  onSyncHosts: () => Promise<void>;
  onUpdateSettings: (patch: Partial<AppSettings>) => Promise<void>;
  onRestoreBuiltins: () => Promise<void>;
}

const SMART_DNS_TEMPLATE = `https://dns.bezmezhau.com/dns-query Bezmezhau Public
https://gemini1.bezmezhau.com/dns-query Bezmezhau Gemini-1
https://dns.magicdns.ru/dns-query MagicDNS
https://us.geohide.ru/dns-query GeoHide US
https://dns.malw.link/dns-query Malw.link
https://dns.comss.one/dns-query Comss.one
176.99.11.77 Xbox-DNS`;

const JSON_TEMPLATE = `[
  {
    "name": "Custom Bezmezhau Node",
    "dohUrl": "https://dns.bezmezhau.com/dns-query",
    "supportsBypass": true
  }
]`;

const CSV_TEMPLATE = `name,endpoint,provider,supportsBypass
Bezmezhau Public,https://dns.bezmezhau.com/dns-query,Bezmezhau,true
MagicDNS,https://dns.magicdns.ru/dns-query,MagicDNS,true`;

export const ConfigsTab: React.FC<ConfigsTabProps> = ({
  servers,
  syncStatus,
  settings,
  onOpenManualAdd,
  onOpenDiscovery,
  onServersImported,
  onSyncHosts,
  onUpdateSettings,
  onRestoreBuiltins,
}) => {
  const [editorText, setEditorText] = useState(SMART_DNS_TEMPLATE);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const importRawText = async (rawText: string) => {
    setFeedback(null);
    const res = await fetch('/api/servers/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawText }),
    });
    const data = await res.json();
    if (!res.ok) {
      setFeedback(data.error || 'Ошибка импорта');
      return;
    }
    const listRes = await fetch('/api/servers');
    const listData = await listRes.json();
    onServersImported(listData.servers || []);
    setFeedback(`Импортировано в базу: ${data.importedCount} серверов (сохранено в SQLite + JSON-сейф)`);
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setEditorText(text);
    await importRawText(text);
    e.target.value = '';
  };

  const downloadBlob = (filename: string, content: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyJson = async () => {
    const json = JSON.stringify(servers, null, 2);
    await navigator.clipboard.writeText(json);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1800);
  };

  const handleSyncClick = async () => {
    setSyncing(true);
    try {
      await onSyncHosts();
      setFeedback('Списки доменов и комьюнити-DNS синхронизированы');
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Action Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
                Импорт и редактор конфигов
              </h2>
              <p className="text-xs text-[#64748B] dark:text-[#94A3B8] mt-0.5">
                Поддержка JSON, CSV, plain-text списков DoH/DoT/IP и резервный JSON-сейф
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.csv,.txt"
                onChange={handleFileChange}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="min-h-[38px] px-4 py-2 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] whitespace-nowrap shrink-0 inline-flex items-center gap-1.5 cursor-pointer"
              >
                <FileUp className="w-3.5 h-3.5" />
                <span>Загрузить файл</span>
              </button>
              <button
                type="button"
                onClick={onOpenManualAdd}
                className="min-h-[38px] px-4 py-2 rounded-md bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold whitespace-nowrap shrink-0 inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Добавить вручную</span>
              </button>
            </div>
          </div>

          {/* Quick templates */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-[#64748B] dark:text-[#94A3B8]">Шаблоны:</span>
            <button
              type="button"
              onClick={() => setEditorText(SMART_DNS_TEMPLATE)}
              className="min-h-[32px] px-3 py-1 rounded bg-[#EEF1F5] dark:bg-[#1B2028] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer whitespace-nowrap shrink-0"
            >
              Список Smart-DNS
            </button>
            <button
              type="button"
              onClick={() => setEditorText(JSON_TEMPLATE)}
              className="min-h-[32px] px-3 py-1 rounded bg-[#EEF1F5] dark:bg-[#1B2028] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer whitespace-nowrap shrink-0"
            >
              JSON
            </button>
            <button
              type="button"
              onClick={() => setEditorText(CSV_TEMPLATE)}
              className="min-h-[32px] px-3 py-1 rounded bg-[#EEF1F5] dark:bg-[#1B2028] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer whitespace-nowrap shrink-0"
            >
              CSV
            </button>
            <button
              type="button"
              onClick={onOpenDiscovery}
              className="min-h-[32px] px-3 py-1 rounded bg-[#EEF1F5] dark:bg-[#1B2028] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer whitespace-nowrap shrink-0 ml-auto"
            >
              Открыть Подбор / Сканер
            </button>
          </div>

          <textarea
            value={editorText}
            onChange={(e) => setEditorText(e.target.value)}
            rows={7}
            aria-label="Редактор импорта DNS"
            className="w-full p-3 rounded-md font-mono text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9] focus:outline-none focus:border-[#22C55E]"
          />

          <div className="flex flex-wrap items-center justify-between gap-3">
            <button
              type="button"
              onClick={() => importRawText(editorText)}
              className="min-h-[40px] px-5 py-2 rounded-md bg-[#22C55E] hover:bg-[#16A34A] text-[#0B0D10] text-xs font-semibold whitespace-nowrap shrink-0 cursor-pointer"
            >
              Импортировать в базу
            </button>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() =>
                  downloadBlob('dns-pulse-export.json', JSON.stringify(servers, null, 2), 'application/json')
                }
                className="min-h-[36px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Сохранить .json</span>
              </button>
              <button
                type="button"
                onClick={() =>
                  downloadBlob('dns-pulse-export.csv', exportServersToCsv(servers), 'text/csv;charset=utf-8')
                }
                className="min-h-[36px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Сохранить .csv</span>
              </button>
              <button
                type="button"
                onClick={handleCopyJson}
                className="min-h-[36px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {copiedJson ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedJson ? 'Скопировано' : 'Копировать JSON'}</span>
              </button>
            </div>
          </div>

          {feedback && (
            <div className="text-xs font-medium text-[#16A34A] dark:text-[#22C55E]">{feedback}</div>
          )}
        </div>

        {/* Right Column: Settings, Sync, Restore & Windows .NET 8 WPF Bundle */}
        <div className="space-y-4">
          <div className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-5 space-y-4">
            <h3 className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
              Синхронизация и настройки
            </h3>

            <div className="p-3 rounded-md bg-[#F7F8FA] dark:bg-[#1B2028] space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-[#64748B] dark:text-[#94A3B8]">Офлайн-кэш доменов:</span>
                <span className="font-mono font-semibold text-[#0F172A] dark:text-[#F1F5F9] tabular-nums">
                  {syncStatus.cachedHostsCount} хостов
                </span>
              </div>
              <button
                type="button"
                onClick={handleSyncClick}
                disabled={syncing}
                className="w-full min-h-[36px] px-3 py-1.5 rounded-md bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
                <span>Синхронизировать списки</span>
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between gap-3">
                <span className="text-[#0F172A] dark:text-[#F1F5F9]">Тема оформления</span>
                <button
                  type="button"
                  onClick={() =>
                    onUpdateSettings({ theme: settings.theme === 'dark' ? 'light' : 'dark' })
                  }
                  className="min-h-[34px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] inline-flex items-center gap-1.5 font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer whitespace-nowrap shrink-0"
                >
                  {settings.theme === 'dark' ? (
                    <>
                      <Moon className="w-3.5 h-3.5" />
                      <span>Тёмная</span>
                    </>
                  ) : (
                    <>
                      <Sun className="w-3.5 h-3.5" />
                      <span>Светлая</span>
                    </>
                  )}
                </button>
              </div>

              <label className="flex items-center justify-between gap-3 cursor-pointer">
                <span className="text-[#0F172A] dark:text-[#F1F5F9]">
                  Автоподключение лучшего при ротации
                </span>
                <input
                  type="checkbox"
                  checked={settings.autoConnectBestOnRotate}
                  onChange={(e) => onUpdateSettings({ autoConnectBestOnRotate: e.target.checked })}
                  className="accent-[#22C55E]"
                />
              </label>

              <label className="flex items-center justify-between gap-3 cursor-pointer">
                <span className="text-[#0F172A] dark:text-[#F1F5F9]">
                  Только бесплатные безлимитные
                </span>
                <input
                  type="checkbox"
                  checked={settings.freeOnly}
                  onChange={(e) => onUpdateSettings({ freeOnly: e.target.checked })}
                  className="accent-[#22C55E]"
                />
              </label>
            </div>

            <button
              type="button"
              onClick={onRestoreBuiltins}
              className="w-full min-h-[38px] px-4 py-2 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center justify-center gap-2 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Восстановить встроенную базу (1050+ DNS)</span>
            </button>
          </div>

          {/* Windows 10/11 .NET 8 WPF Source Bundle */}
          <div className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-5 space-y-3">
            <h3 className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
              Windows 10/11 Десктоп (.NET 8 WPF)
            </h3>
            <p className="text-xs text-[#64748B] dark:text-[#94A3B8] leading-relaxed">
              Исходный код MVVM-клиента с локальным туннелем 127.0.0.1:53, NRPT, треем, xUnit-тестами и GitHub Actions сборкой x64 .exe.
            </p>
            <a
              href="/api/export/windows-wpf.zip"
              download="DNS-Pulse-Windows-WPF-net8.zip"
              className="w-full min-h-[38px] px-4 py-2 rounded-md bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold inline-flex items-center justify-center gap-2 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Скачать .NET 8 WPF проект (.zip)</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};
