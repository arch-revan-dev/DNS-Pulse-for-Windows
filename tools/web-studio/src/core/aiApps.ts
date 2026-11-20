export const DEFAULT_LOCAL_PROXY_PORT = 18753;
export const DEFAULT_LOCAL_PAC_PORT = 18754;
export const LOOPBACK_SAFE_NO_PROXY = 'localhost,127.0.0.1,::1,*.local,10.0.0.0/8,192.168.0.0/16';
export const CHROMIUM_BYPASS_LIST = '<-loopback>;localhost;127.0.0.1;[::1];*.local';

export interface AiReadinessService {
  id: 'antigravity' | 'gemini' | 'chatgpt' | 'claude';
  name: string;
  domain: string;
  requiresBypass: boolean;
}

export const AI_READINESS_SERVICES: AiReadinessService[] = [
  { id: 'antigravity', name: 'Antigravity', domain: 'cloudcode-pa.googleapis.com', requiresBypass: true },
  { id: 'gemini', name: 'Gemini', domain: 'aistudio.google.com', requiresBypass: true },
  { id: 'chatgpt', name: 'ChatGPT', domain: 'chatgpt.com', requiresBypass: true },
  { id: 'claude', name: 'Claude', domain: 'claude.ai', requiresBypass: true },
];

export type DesktopAiAppKind = 'electron' | 'cli';

export interface DesktopAiAppProfile {
  id: string;
  name: string;
  subtitle: string;
  kind: DesktopAiAppKind;
  commandHint: string;
  primaryDomains: string[];
}

export const DESKTOP_AI_APPS: DesktopAiAppProfile[] = [
  {
    id: 'antigravity',
    name: 'Google Antigravity',
    subtitle: 'Electron IDE · gRPC + Cloud Code + Loopback IPC',
    kind: 'electron',
    commandHint: '& "$env:LOCALAPPDATA\\Programs\\Antigravity\\Antigravity.exe"',
    primaryDomains: ['cloudcode-pa.googleapis.com', 'antigravity-pa.googleapis.com', 'antigravity.google'],
  },
  {
    id: 'claude_code',
    name: 'Claude Code CLI',
    subtitle: 'Терминальный агент · HTTP_PROXY + NODE_USE_ENV_PROXY',
    kind: 'cli',
    commandHint: 'claude',
    primaryDomains: ['api.anthropic.com', 'claude.ai', 'console.anthropic.com'],
  },
  {
    id: 'claude_desktop',
    name: 'Claude Desktop',
    subtitle: 'Electron приложение · Перезапуск с локальным прокси',
    kind: 'electron',
    commandHint: '& "$env:LOCALAPPDATA\\AnthropicClaude\\claude.exe"',
    primaryDomains: ['claude.ai', 'api.anthropic.com'],
  },
  {
    id: 'cursor',
    name: 'Cursor IDE',
    subtitle: 'AI редактор кода · Chromium proxy + gRPC',
    kind: 'electron',
    commandHint: '& "$env:LOCALAPPDATA\\Programs\\cursor\\Cursor.exe"',
    primaryDomains: ['api2.cursor.sh', 'api3.cursor.sh', 'cursor.com'],
  },
  {
    id: 'windsurf',
    name: 'Windsurf IDE',
    subtitle: 'Codeium IDE · Loopback-safe прокси-захват',
    kind: 'electron',
    commandHint: '& "$env:LOCALAPPDATA\\Programs\\Windsurf\\Windsurf.exe"',
    primaryDomains: ['server.codeium.com', 'windsurf.com'],
  },
  {
    id: 'gemini_cli',
    name: 'Gemini CLI',
    subtitle: 'Консольный клиент Google · Generative Language API',
    kind: 'cli',
    commandHint: 'gemini',
    primaryDomains: ['generativelanguage.googleapis.com', 'cloudcode-pa.googleapis.com'],
  },
  {
    id: 'codex_cli',
    name: 'OpenAI Codex CLI',
    subtitle: 'Консольный агент OpenAI · Node/Rust HTTPS прокси',
    kind: 'cli',
    commandHint: 'codex',
    primaryDomains: ['api.openai.com', 'chatgpt.com'],
  },
  {
    id: 'chatgpt_desktop',
    name: 'ChatGPT Desktop',
    subtitle: 'Официальный клиент Windows · HTTPS_PROXY',
    kind: 'electron',
    commandHint: '& "$env:LOCALAPPDATA\\Programs\\ChatGPT\\ChatGPT.exe"',
    primaryDomains: ['chatgpt.com', 'api.openai.com'],
  },
];

export function buildPowerShellLaunchCommand(
  app: DesktopAiAppProfile,
  proxyPort: number = DEFAULT_LOCAL_PROXY_PORT
): string {
  const proxyUrl = `http://127.0.0.1:${proxyPort}`;
  const envBlock = [
    `$env:HTTP_PROXY='${proxyUrl}'`,
    `$env:HTTPS_PROXY='${proxyUrl}'`,
    `$env:ALL_PROXY='${proxyUrl}'`,
    `$env:GRPC_PROXY_EXP='${proxyUrl}'`,
    `$env:NO_PROXY='${LOOPBACK_SAFE_NO_PROXY}'`,
    `$env:NODE_USE_ENV_PROXY='1'`,
  ].join('; ');

  if (app.kind === 'electron') {
    return `${envBlock}; ${app.commandHint} --proxy-server="${proxyUrl}" --proxy-bypass-list="${CHROMIUM_BYPASS_LIST}"`;
  }

  return `${envBlock}; ${app.commandHint}`;
}
