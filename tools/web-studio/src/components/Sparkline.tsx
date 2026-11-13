import React from 'react';
import { BypassVerdict } from '../core/types';

interface SparklineProps {
  values: number[];
  verdict: BypassVerdict;
  compact?: boolean;
}

export const Sparkline: React.FC<SparklineProps> = ({ values, verdict, compact = true }) => {
  if (!values || values.length === 0) return null;

  const width = compact ? 68 : 220;
  const height = compact ? 20 : 28;
  const pad = 2;

  const pts = values.length === 1 ? [values[0], values[0]] : values;
  const min = Math.min(...pts);
  const max = Math.max(...pts);
  const span = Math.max(1, max - min);

  const coords = pts.map((v, i) => {
    const x = pad + (i / (pts.length - 1)) * (width - pad * 2);
    const y = height - pad - ((v - min) / span) * (height - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const strokeColor =
    verdict === 'VERIFIED_PROXY_OK'
      ? '#22C55E'
      : verdict === 'DIRECT_NO_PROXY'
        ? '#F59E0B'
        : verdict === 'DNS_TIMEOUT' || verdict === 'GEO_REDIRECT_BLOCKED' || verdict === 'PROXY_PORT_DEAD'
          ? '#EF4444'
          : '#64748B';

  if (compact) {
    return (
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="shrink-0 overflow-visible"
        aria-label={`История задержек: ${values.join(', ')} мс`}
      >
        <polyline
          fill="none"
          stroke={strokeColor}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={coords.join(' ')}
        />
      </svg>
    );
  }

  return (
    <div className="pt-2 border-t border-[#DCE1E8] dark:border-[#262C36] flex items-center justify-between gap-3">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="flex-1 min-w-0 h-[28px] overflow-visible"
        aria-label={`История задержек: ${values.join(', ')} мс`}
      >
        <polyline
          fill="none"
          stroke={strokeColor}
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={coords.join(' ')}
        />
      </svg>
      <span className="font-mono text-[11px] text-[#64748B] dark:text-[#94A3B8] tabular-nums whitespace-nowrap shrink-0">
        {values.length} зам. · {min}–{max} мс
      </span>
    </div>
  );
};
