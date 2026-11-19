import React, { useState } from 'react';
import { Check, Copy, Download, Terminal } from 'lucide-react';
import {
  AI_DESKTOP_APPS,
  AiAppProfile,
  buildGlobalWindowsEnvCaptureScript,
  buildPowerShellCaptureCommand,
  buildWindowsBatLauncher,
  LOOPBACK_SAFE_NO_PROXY,
} from '../core/aiApps';

interface AiAppsCaptureCardProps {
  proxyAddress: string;
  tunnelActive: boolean;
  compact?: boolean;
}

export const AiAppsCaptureCard: React.FC<AiAppsCaptureCardProps> = ({
  proxyAddress,
  tunnelActive,
  compact = false,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedGlobal, setCopiedGlobal] = useState(false);

  const proxyUrl = proxyAddress.startsWith('http') ? proxyAddress : `http://${proxyAddress}`;

  const copyText = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
    } catch {
      // Clipboard fallback unavailable
    }
  };

  const handleCopyGlobal = async () => {
    try {
      await navigator.clipboard.writeText(buildGlobalWindowsEnvCaptureScript(proxyAddress));
      setCopiedGlobal(true);
      setTimeout(() => setCopiedGlobal(false), 1800);
    } catch {
      // ignore
    }
  };

  const handleDownloadBat = (app: AiAppProfile) => {
    const content = buildWindowsBatLauncher(app, proxyAddress);
    const blob = new Blob([content], { type: 'application/x-bat;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-pulse-${app.id}.bat`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const visibleApps = compact ? AI_DESKTOP_APPS.slice(0, 6) : AI_DESKTOP_APPS;

  return (
    <section
      aria-label="Программы и CLI через локальный прокси"
      className="rounded-lg bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-5 space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
          <h2 className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
            Программы и CLI
          </h2>
          <span
            className={`font-mono text-xs ${
              tunnelActive
                ? 'text-[#16A34A] dark:text-[#22C55E]'
                : 'text-[#64748B] dark:text-[#94A3B8]'
            }`}
          >
            {proxyUrl}
          </span>
        </div>

        <button
          type="button"
          onClick={handleCopyGlobal}
          className="min-h-[34px] px-3 py-1.5 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer hover:border-[#94A3B8] shrink-0"
        >
          {copiedGlobal ? (
            <Check className="w-3.5 h-3.5 text-[#22C55E]" />
          ) : (
            <Terminal className="w-3.5 h-3.5" />
          )}
          <span>{copiedGlobal ? 'Скопировано' : 'PowerShell (HKCU)'}</span>
        </button>
      </div>

      {/* App Rows */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {visibleApps.map((app) => {
          const copied = copiedId === app.id;
          return (
            <div
              key={app.id}
              className="rounded-md bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] p-3.5 flex flex-col justify-between gap-2.5"
            >
              <div className="space-y-0.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-[#0F172A] dark:text-[#F1F5F9] truncate">
                    {app.name}
                  </span>
                  <span className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] shrink-0">
                    {app.category}
                  </span>
                </div>
                <div className="font-mono text-[11px] text-[#16A34A] dark:text-[#22C55E] truncate">
                  {app.primaryDomain}
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t border-[#DCE1E8]/70 dark:border-[#262C36]/70">
                <button
                  type="button"
                  onClick={() => copyText(buildPowerShellCaptureCommand(app, proxyAddress), app.id)}
                  className="flex-1 min-h-[32px] px-2.5 py-1 rounded bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] inline-flex items-center justify-center gap-1.5 cursor-pointer hover:border-[#94A3B8]"
                >
                  {copied ? (
                    <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  <span>{copied ? 'Скопировано' : 'Команда'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadBat(app)}
                  className="min-h-[32px] px-2.5 py-1 rounded bg-[#0F172A] dark:bg-[#F1F5F9] text-[#FFFFFF] dark:text-[#0B0D10] text-xs font-semibold inline-flex items-center gap-1 cursor-pointer whitespace-nowrap"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>.bat</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Loopback Safety Footer Note */}
      <div className="text-[11px] text-[#64748B] dark:text-[#94A3B8] font-mono break-all pt-1 border-t border-[#DCE1E8] dark:border-[#262C36]">
        NO_PROXY={LOOPBACK_SAFE_NO_PROXY}
      </div>
    </section>
  );
};
