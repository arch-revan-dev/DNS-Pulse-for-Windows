import { DnsServer, ProbeResult } from './types';

const GAMING_ONLY_TOKENS = [
  'xbox',
  'brawl',
  'gaming',
  'playstation',
  'radar',
  'electro',
  'spotify',
  'steam',
];

const EXPLICIT_AI_TAGS = new Set([
  'ai',
  'aistudio',
  'gemini',
  'chatgpt',
  'claude',
  'openai',
  'copilot',
  'grok',
  'perplexity',
  'antigravity',
  'anti-sanction',
]);

export function hasExplicitAiTag(server: DnsServer): boolean {
  return server.tags.some((t) => EXPLICIT_AI_TAGS.has(t.trim().toLowerCase()));
}

export function isGamingOnlyNode(server: DnsServer): boolean {
  if (!server.supportsBypass) return false;
  if (hasExplicitAiTag(server)) return false;
  if (server.category === 'Игры и Регионы') return true;
  const hay = `${server.id} ${server.name} ${server.tags.join(' ')}`.toLowerCase();
  return GAMING_ONLY_TOKENS.some((tok) => hay.includes(tok));
}

export function isAiEligibleServer(server: DnsServer): boolean {
  if (!server.supportsBypass) return false;
  if (server.isSubscription) return false;
  if (isGamingOnlyNode(server)) return false;
  return true;
}

/**
 * Deterministic quality score (higher = better) for selecting the optimal AI unblocker node.
 */
export function scoreAiAutopilotCandidate(server: DnsServer): number {
  if (!isAiEligibleServer(server)) return -10_000;

  let score = 0;

  switch (server.verdict) {
    case 'VERIFIED_PROXY_OK':
      score += 5000;
      break;
    case 'UNCHECKED':
      score += 1200;
      break;
    case 'DIRECT_NO_PROXY':
      score -= 2000;
      break;
    case 'GEO_REDIRECT_BLOCKED':
      score -= 3000;
      break;
    case 'PROXY_PORT_DEAD':
    case 'DNS_TIMEOUT':
      score -= 4000;
      break;
    default:
      break;
  }

  if (server.protocol === 'DoH' || server.protocol === 'DoT') {
    score += 400;
  } else if (server.protocol === 'SNI443') {
    score += 250;
  }

  if (hasExplicitAiTag(server)) {
    score += 220;
  }

  if (server.companionPassed === true) {
    score += 250;
  } else if (server.companionPassed === false) {
    score -= 400;
  }

  if (server.port443Ok === true) {
    score += 200;
  } else if (server.port443Ok === false) {
    score -= 500;
  }

  const latency = server.avgLatencyMs ?? server.lastLatencyMs;
  if (latency !== null && Number.isFinite(latency)) {
    score -= Math.min(1500, Math.round(latency));
  }

  if (server.jitterMs !== null && Number.isFinite(server.jitterMs)) {
    score -= Math.min(400, Math.round(server.jitterMs * 2));
  }

  return score;
}

export function rankAiAutopilotCandidates(servers: DnsServer[]): DnsServer[] {
  return servers
    .filter(isAiEligibleServer)
    .slice()
    .sort((a, b) => {
      const diff = scoreAiAutopilotCandidate(b) - scoreAiAutopilotCandidate(a);
      if (diff !== 0) return diff;
      const la = a.lastLatencyMs ?? Number.POSITIVE_INFINITY;
      const lb = b.lastLatencyMs ?? Number.POSITIVE_INFINITY;
      if (la !== lb) return la - lb;
      return a.name.localeCompare(b.name, 'ru');
    });
}

export function selectNextFailoverNode(
  rankedPool: DnsServer[],
  currentServerId: string | null,
  recentlyFailedIds: ReadonlySet<string> = new Set()
): DnsServer | null {
  const candidates = rankedPool.filter(isAiEligibleServer);
  if (candidates.length === 0) return null;

  // Prefer verified healthy candidates that are neither current nor recently failed
  const freshVerified = candidates.find(
    (s) =>
      s.id !== currentServerId &&
      !recentlyFailedIds.has(s.id) &&
      s.verdict === 'VERIFIED_PROXY_OK'
  );
  if (freshVerified) return freshVerified;

  // Otherwise any eligible non-current, non-failed node
  const freshAny = candidates.find(
    (s) => s.id !== currentServerId && !recentlyFailedIds.has(s.id)
  );
  if (freshAny) return freshAny;

  // Wrap around to best non-current candidate if all were tried
  const nonCurrent = candidates.find((s) => s.id !== currentServerId);
  return nonCurrent ?? candidates[0];
}

export function shouldTriggerWatchdogFailover(
  probe: Pick<ProbeResult, 'verdict' | 'port443Ok' | 'latencyMs'>,
  latencyThresholdMs = 2500
): { shouldSwitch: boolean; reason: string } {
  if (probe.verdict !== 'VERIFIED_PROXY_OK') {
    return {
      shouldSwitch: true,
      reason: `Вердикт ухудшился: ${probe.verdict}`,
    };
  }

  if (probe.port443Ok === false) {
    return {
      shouldSwitch: true,
      reason: 'Порт 443 перестал отвечать на TLS',
    };
  }

  if (probe.latencyMs !== null && probe.latencyMs > latencyThresholdMs) {
    return {
      shouldSwitch: true,
      reason: `Высокая задержка (${Math.round(probe.latencyMs)} мс > ${latencyThresholdMs} мс)`,
    };
  }

  return { shouldSwitch: false, reason: 'Канал стабилен' };
}
