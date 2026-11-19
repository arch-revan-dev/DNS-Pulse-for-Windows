import { DomainPreset, PresetGroupId } from './types';

export const PRESET_GROUPS: Array<{ id: PresetGroupId; label: string }> = [
  { id: 'ai', label: 'Веб-ИИ' },
  { id: 'ai_apps', label: 'Программы и CLI' },
  { id: 'all', label: 'Все ИИ' },
  { id: 'custom', label: 'Свой домен' },
];

// Gemini MUST remain the very first preset in AI and All groups
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
    id: 'grok',
    label: 'Grok',
    domain: 'grok.com',
    group: 'ai',
    requiresBypass: true,
    companionDomains: ['api.x.ai'],
  },
  {
    id: 'perplexity',
    label: 'Perplexity',
    domain: 'perplexity.ai',
    group: 'ai',
    requiresBypass: true,
    companionDomains: ['api.perplexity.ai'],
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    domain: 'deepseek.com',
    group: 'ai',
    requiresBypass: true,
    companionDomains: ['api.deepseek.com'],
  },
  // Desktop & CLI AI Applications
  {
    id: 'antigravity',
    label: 'Antigravity IDE',
    domain: 'cloudcode-pa.googleapis.com',
    group: 'ai_apps',
    requiresBypass: true,
    companionDomains: ['antigravity.google', 'generativelanguage.googleapis.com'],
  },
  {
    id: 'claude_code',
    label: 'Claude Code CLI',
    domain: 'api.anthropic.com',
    group: 'ai_apps',
    requiresBypass: true,
    companionDomains: ['claude.ai', 'console.anthropic.com', 'mcp-proxy.anthropic.com'],
  },
  {
    id: 'cursor',
    label: 'Cursor IDE',
    domain: 'api2.cursor.sh',
    group: 'ai_apps',
    requiresBypass: true,
    companionDomains: ['cursor.sh', 'cursor.com'],
  },
  {
    id: 'windsurf',
    label: 'Windsurf IDE',
    domain: 'server.codeium.com',
    group: 'ai_apps',
    requiresBypass: true,
    companionDomains: ['windsurf.com', 'codeium.com'],
  },
  {
    id: 'codex_cli',
    label: 'Codex CLI',
    domain: 'api.openai.com',
    group: 'ai_apps',
    requiresBypass: true,
    companionDomains: ['chatgpt.com', 'auth.openai.com'],
  },
  {
    id: 'copilot',
    label: 'VS Code Copilot',
    domain: 'api.githubcopilot.com',
    group: 'ai_apps',
    requiresBypass: true,
    companionDomains: ['copilot-proxy.githubusercontent.com'],
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
  if (
    normalized.includes('gemini.google.com') ||
    normalized.includes('aistudio.google.com') ||
    normalized.includes('cloudcode-pa.googleapis.com') ||
    normalized.includes('antigravity.google')
  ) {
    return ['alkalimakersuite-pa.clients6.google.com', 'generativelanguage.googleapis.com'];
  }
  if (normalized.includes('anthropic.com') || normalized.includes('claude.ai')) {
    return ['api.anthropic.com', 'console.anthropic.com'];
  }
  if (normalized.includes('openai.com') || normalized.includes('chatgpt.com')) {
    return ['api.openai.com', 'auth.openai.com'];
  }
  return [];
}
