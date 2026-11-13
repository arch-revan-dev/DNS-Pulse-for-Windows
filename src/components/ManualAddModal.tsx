import React, { useState } from 'react';
import { Plus, X } from 'lucide-react';
import { CATEGORY_LIST, detectProtocolFromEndpoint } from '../core/filterSort';
import { DnsCategory, DnsServer } from '../core/types';

interface ManualAddModalProps {
  open: boolean;
  onClose: () => void;
  onCreated: (server: DnsServer) => void;
}

export const ManualAddModal: React.FC<ManualAddModalProps> = ({
  open,
  onClose,
  onCreated,
}) => {
  const [name, setName] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [secondaryIp, setSecondaryIp] = useState('');
  const [category, setCategory] = useState<DnsCategory>('Свои / Найденные');
  const [supportsBypass, setSupportsBypass] = useState(true);
  const [isSubscription, setIsSubscription] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!open) return null;

  const detectedProto = endpoint.trim() ? detectProtocolFromEndpoint(endpoint) : 'UDP';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanEndpoint = endpoint.trim();
    const cleanName = name.trim() || cleanEndpoint;
    if (!cleanEndpoint) {
      setError('Укажите IP, DoH URL или DoT-хост');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const proto = detectProtocolFromEndpoint(cleanEndpoint);
      const payload = {
        name: cleanName,
        protocol: proto,
        primaryIp: proto === 'UDP' ? cleanEndpoint : '',
        secondaryIp: secondaryIp.trim() || undefined,
        dohUrl: proto === 'DoH' ? cleanEndpoint : undefined,
        dotHost: proto === 'DoT' ? cleanEndpoint.replace(/^tls:\/\//i, '') : undefined,
        smartProxyIp: proto === 'SNI443' ? cleanEndpoint.replace(/^smartproxy:\/\//i, '').split(':')[0] : undefined,
        category: isSubscription ? 'Личные токены' : category,
        supportsBypass,
        isSubscription,
      };
      const res = await fetch('/api/servers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Ошибка добавления');
      onCreated(data.server);
      setName('');
      setEndpoint('');
      setSecondaryIp('');
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка сохранения');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
      role="dialog"
      aria-modal="true"
      aria-label="Добавить DNS вручную"
    >
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-xl bg-[#FFFFFF] dark:bg-[#13161B] border border-[#DCE1E8] dark:border-[#262C36] p-6 space-y-4"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-[#0F172A] dark:text-[#F1F5F9]">
            Добавить DNS вручную
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть окно добавления"
            className="p-1.5 rounded bg-[#EEF1F5] dark:bg-[#1B2028] text-[#64748B] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-[#64748B] dark:text-[#94A3B8]">
            Эндпоинт (DoH URL, DoT хост, IP или smartproxy://IP)
          </label>
          <input
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://dns.bezmezhau.com/dns-query"
            className="w-full min-h-[38px] px-3 py-2 rounded-md font-mono text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]"
          />
          <div className="text-[11px] font-mono text-[#64748B] dark:text-[#94A3B8]">
            Автоопределение протокола: {detectedProto}
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-[#64748B] dark:text-[#94A3B8]">
            Название
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Мой Smart-DNS"
            className="w-full min-h-[38px] px-3 py-2 rounded-md text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#64748B] dark:text-[#94A3B8]">
              Категория
            </label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value as DnsCategory)}
              className="w-full min-h-[38px] px-2.5 py-2 rounded-md text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]"
            >
              {CATEGORY_LIST.filter((c) => c !== 'Все').map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#64748B] dark:text-[#94A3B8]">
              Secondary IP (опц.)
            </label>
            <input
              type="text"
              value={secondaryIp}
              onChange={(e) => setSecondaryIp(e.target.value)}
              placeholder="1.0.0.1"
              className="w-full min-h-[38px] px-3 py-2 rounded-md font-mono text-xs bg-[#F7F8FA] dark:bg-[#0B0D10] border border-[#DCE1E8] dark:border-[#262C36] text-[#0F172A] dark:text-[#F1F5F9]"
            />
          </div>
        </div>

        <div className="flex flex-col gap-2 text-xs text-[#0F172A] dark:text-[#F1F5F9]">
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={supportsBypass}
              onChange={(e) => setSupportsBypass(e.target.checked)}
              className="accent-[#22C55E]"
            />
            <span>Smart-DNS (поддержка обхода)</span>
          </label>
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={isSubscription}
              onChange={(e) => setIsSubscription(e.target.checked)}
              className="accent-[#F59E0B]"
            />
            <span>Личный токен / приватная подписка</span>
          </label>
        </div>

        {error && <div className="text-xs text-[#EF4444]">{error}</div>}

        <div className="pt-2 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="min-h-[38px] px-4 py-2 rounded-md bg-[#EEF1F5] dark:bg-[#1B2028] text-xs font-medium text-[#0F172A] dark:text-[#F1F5F9] cursor-pointer"
          >
            Отмена
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="min-h-[38px] px-4 py-2 rounded-md bg-[#22C55E] text-[#0B0D10] text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Сохранить</span>
          </button>
        </div>
      </form>
    </div>
  );
};
