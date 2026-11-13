import { BypassVerdict } from './types';

/**
 * Known direct infrastructure prefixes that indicate a DNS server returned
 * the unproxied official CDN/service IP instead of a Smart-DNS bypass relay.
 */
const GOOGLE_DIRECT_PREFIXES = [
  '142.250.',
  '142.251.',
  '172.217.',
  '172.253.',
  '216.58.',
  '192.178.',
  '74.125.',
  '64.233.',
  '108.177.',
  '209.85.',
  '216.239.',
  '66.102.',
  '66.249.',
  '72.14.',
];

// Cloudflare / OpenAI / Anthropic direct ranges
const AI_OTHER_DIRECT_CIDR_PREFIXES = [
  '104.18.',
  '172.64.',
  '162.159.',
  '160.79.', // Anthropic direct
  '13.107.', // Microsoft Copilot direct
  '204.79.',
];

const SPOTIFY_DIRECT_PREFIXES = ['35.186.', '104.199.', '34.117.'];

export function isBogonOrLoopbackIp(ip: string): boolean {
  const s = ip.trim();
  if (!s) return true;
  if (s === '0.0.0.0' || s === '127.0.0.1' || s === '::1' || s === '::') return true;
  if (s.startsWith('127.') || s.startsWith('10.') || s.startsWith('169.254.')) return true;
  if (s.startsWith('192.168.')) return true;
  const parts = s.split('.').map(Number);
  if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  return false;
}

export function isDirectServiceIp(ip: string, domain: string): boolean {
  const cleanIp = ip.trim();
  const cleanDomain = domain.trim().toLowerCase();

  if (
    cleanDomain.includes('google.com') ||
    cleanDomain.includes('googleapis.com') ||
    cleanDomain.includes('clients6.google.com')
  ) {
    return GOOGLE_DIRECT_PREFIXES.some((prefix) => cleanIp.startsWith(prefix));
  }

  if (
    cleanDomain.includes('chatgpt.com') ||
    cleanDomain.includes('openai.com') ||
    cleanDomain.includes('claude.ai') ||
    cleanDomain.includes('anthropic.com') ||
    cleanDomain.includes('copilot.microsoft.com')
  ) {
    return AI_OTHER_DIRECT_CIDR_PREFIXES.some((prefix) => cleanIp.startsWith(prefix));
  }

  if (cleanDomain.includes('spotify.com')) {
    return SPOTIFY_DIRECT_PREFIXES.some((prefix) => cleanIp.startsWith(prefix));
  }

  return false;
}

export function isGeoBlockedRedirect(statusCode: number | null, locationHeader: string | null): boolean {
  if (statusCode === 403 || statusCode === 451) return true;
  if (locationHeader) {
    const loc = locationHeader.toLowerCase();
    if (
      loc.includes('/docs/available-regions') ||
      loc.includes('/sorry/index') ||
      loc.includes('unsupported-region') ||
      loc.includes('country-not-supported')
    ) {
      return true;
    }
  }
  return false;
}

export function classifyFourStageVerdict(input: {
  requiresBypass: boolean;
  resolvedIps: string[];
  companionPassed: boolean | null;
  port443Ok: boolean | null;
  httpStatus: number | null;
  redirectLocation: string | null;
  targetDomain: string;
  timedOut: boolean;
}): { verdict: BypassVerdict; reason: string } {
  if (input.timedOut || input.resolvedIps.length === 0) {
    return {
      verdict: 'DNS_TIMEOUT',
      reason: 'Таймаут DNS или пустой ответ',
    };
  }

  const validIps = input.resolvedIps.filter((ip) => !isBogonOrLoopbackIp(ip));
  if (validIps.length === 0) {
    return {
      verdict: 'DNS_TIMEOUT',
      reason: `Заглушка / Bogon IP (${input.resolvedIps[0]})`,
    };
  }

  if (input.requiresBypass) {
    const allDirect = validIps.every((ip) => isDirectServiceIp(ip, input.targetDomain));
    if (allDirect) {
      return {
        verdict: 'DIRECT_NO_PROXY',
        reason: `Прямой DNS (без обхода) • ${validIps[0]}`,
      };
    }

    if (input.companionPassed === false) {
      return {
        verdict: 'DIRECT_NO_PROXY',
        reason: 'API-домен пошёл напрямую (риск /available-regions)',
      };
    }
  }

  if (isGeoBlockedRedirect(input.httpStatus, input.redirectLocation)) {
    return {
      verdict: 'GEO_REDIRECT_BLOCKED',
      reason: `Геоблок / редирект ${input.httpStatus ?? ''} ${input.redirectLocation ?? ''}`.trim(),
    };
  }

  if (input.port443Ok === false || input.httpStatus === 502 || input.httpStatus === 504) {
    return {
      verdict: 'PROXY_PORT_DEAD',
      reason: `Порт 443 / TLS недоступен (${input.httpStatus ?? 'reset'})`,
    };
  }

  if (!input.requiresBypass) {
    return {
      verdict: 'VERIFIED_PROXY_OK',
      reason: `Резолв OK • 443 OK (${validIps[0]})`,
    };
  }

  return {
    verdict: 'VERIFIED_PROXY_OK',
    reason: `Доступ открыт • 443 OK (${validIps[0]})`,
  };
}
