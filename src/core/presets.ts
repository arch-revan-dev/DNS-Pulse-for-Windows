import { DomainPreset, PresetGroupId } from './types';

export const PRESET_GROUPS: Array<{ id: PresetGroupId; label: string }> = [
  { id: 'ai', label: 'ИИ' },
  { id: 'streaming', label: 'Стриминг' },
  { id: 'gaming', label: 'Игры' },
  { id: 'all', label: 'Всё' },
  { id: 'custom', label: 'Свой' },
];

// Gemini MUST be the very first preset in ИИ and Всё!
export const DOMAIN_PRESETS: DomainPreset[] = [
  {
    id: 'gemini',
    label: 'Gemini',
    domain: 'gemini.google.com',
    group: 'ai',
    requiresBypass: true,
    companionDomains: [
      'alkalimakersuite-pa.clients6.google.com',
      'generativelanguage.googleapis.com',
    ],
  },
  {
    id: 'aistudio',
    label: 'AI Studio',
    domain: 'aistudio.google.com',
    group: 'ai',
    requiresBypass: true,
    companionDomains: [
      'alkalimakersuite-pa.clients6.google.com',
      'generativelanguage.googleapis.com',
      'gemini.google.com',
    ],
  },
  {
    id: 'chatgpt',
    label: 'ChatGPT',
    domain: 'chatgpt.com',
    group: 'ai',
    requiresBypass: true,
    companionDomains: ['api.openai.com', 'auth.openai.com'],
  },
  {
    id: 'claude',
    label: 'Claude',
    domain: 'claude.ai',
    group: 'ai',
    requiresBypass: true,
    companionDomains: ['api.anthropic.com'],
  },
  {
    id: 'copilot',
    label: 'Copilot',
    domain: 'copilot.microsoft.com',
    group: 'ai',
    requiresBypass: true,
    companionDomains: ['sydney.bing.com'],
  },
  {
    id: 'spotify',
    label: 'Spotify',
    domain: 'open.spotify.com',
    group: 'streaming',
    requiresBypass: true,
    companionDomains: ['spclient.wg.spotify.com', 'apresolve.spotify.com'],
  },
  {
    id: 'soundcloud',
    label: 'SoundCloud',
    domain: 'soundcloud.com',
    group: 'streaming',
    requiresBypass: true,
    companionDomains: ['api-v2.soundcloud.com'],
  },
  {
    id: 'twitch',
    label: 'Twitch',
    domain: 'twitch.tv',
    group: 'streaming',
    requiresBypass: false,
    companionDomains: ['gql.twitch.tv'],
  },
  {
    id: 'xbox',
    label: 'Xbox Live',
    domain: 'xboxlive.com',
    group: 'gaming',
    requiresBypass: true,
    companionDomains: ['user.auth.xboxlive.com', 'xsts.auth.xboxlive.com'],
  },
  {
    id: 'brawlstars',
    label: 'Brawl Stars',
    domain: 'brawlstars.com',
    group: 'gaming',
    requiresBypass: true,
    companionDomains: ['game.brawlstarsgame.com'],
  },
  {
    id: 'gfn',
    label: 'GeForce NOW',
    domain: 'play.geforcenow.com',
    group: 'gaming',
    requiresBypass: true,
    companionDomains: ['nvidiagrid.net'],
  },
  {
    id: 'clean_ping',
    label: 'Чистый пинг',
    domain: 'google.com',
    group: 'all',
    requiresBypass: false,
    companionDomains: [],
  },
];

export function getPresetsForGroup(group: PresetGroupId): DomainPreset[] {
  if (group === 'all') return DOMAIN_PRESETS;
  if (group === 'custom') return [];
  return DOMAIN_PRESETS.filter((p) => p.group === group);
}

export function getCompanionDomainsForHost(domain: string): string[] {
  const normalized = domain.trim().toLowerCase();
  const matched = DOMAIN_PRESETS.find((p) => p.domain.toLowerCase() === normalized);
  if (matched) return matched.companionDomains;
  if (normalized.includes('gemini.google.com') || normalized.includes('aistudio.google.com')) {
    return ['alkalimakersuite-pa.clients6.google.com', 'generativelanguage.googleapis.com'];
  }
  if (normalized.includes('spotify.com')) {
    return ['spclient.wg.spotify.com', 'apresolve.spotify.com'];
  }
  if (normalized.includes('xboxlive.com') || normalized.includes('xbox.com')) {
    return ['user.auth.xboxlive.com', 'xsts.auth.xboxlive.com'];
  }
  return [];
}
