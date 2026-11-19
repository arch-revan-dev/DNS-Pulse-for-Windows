export interface AiAppProfile {
  id: string;
  name: string;
  category: 'AI IDE' | 'AI CLI' | 'AI App';
  primaryDomain: string;
  domains: string[];
  processNames: string[];
  defaultWindowsExe: string;
  supportsChromiumProxyFlag: boolean;
  description: string;
}

export const LOOPBACK_SAFE_NO_PROXY =
  'localhost,127.0.0.1,::1,127.0.53.1,.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';

export const CHROMIUM_PROXY_BYPASS_LIST =
  '<-loopback>;localhost;127.0.0.1;::1;127.0.53.1;*.local';

export const AI_DESKTOP_APPS: AiAppProfile[] = [
  {
    id: 'antigravity',
    name: 'Google Antigravity',
    category: 'AI IDE',
    primaryDomain: 'cloudcode-pa.googleapis.com',
    domains: [
      'antigravity.google',
      'cloudcode-pa.googleapis.com',
      'daily-cloudcode-pa.sandbox.googleapis.com',
      'autopush-cloudcode-pa.sandbox.googleapis.com',
      'generativelanguage.googleapis.com',
      'aistudio.google.com',
      'aiplatform.googleapis.com',
      'oauth2.googleapis.com',
      'accounts.google.com',
    ],
    processNames: ['Antigravity.exe', 'language_server_windows_x64.exe'],
    defaultWindowsExe: '%LOCALAPPDATA%\\Programs\\Antigravity\\Antigravity.exe',
    supportsChromiumProxyFlag: true,
    description:
      'Захватывает Electron-оболочку и локальный Go/gRPC language server через 127.0.0.1 без поломки локального IPC.',
  },
  {
    id: 'claude_code',
    name: 'Claude Code CLI',
    category: 'AI CLI',
    primaryDomain: 'api.anthropic.com',
    domains: [
      'api.anthropic.com',
      'claude.ai',
      'console.anthropic.com',
      'statsig.anthropic.com',
      'mcp-proxy.anthropic.com',
      'a-cdn.anthropic.com',
    ],
    processNames: ['claude.exe', 'claude.cmd'],
    defaultWindowsExe: 'claude',
    supportsChromiumProxyFlag: false,
    description:
      'Передаёт HTTPS_PROXY + NODE_USE_ENV_PROXY=1, чтобы Node.js undici/fetch шёл напрямую через локальный туннель.',
  },
  {
    id: 'claude_desktop',
    name: 'Claude Desktop',
    category: 'AI App',
    primaryDomain: 'claude.ai',
    domains: ['claude.ai', 'api.anthropic.com', 'a-cdn.anthropic.com', 'statsig.anthropic.com'],
    processNames: ['Claude.exe'],
    defaultWindowsExe: '%LOCALAPPDATA%\\AnthropicClaude\\Claude.exe',
    supportsChromiumProxyFlag: true,
    description:
      'Запускает десктопный Electron-клиент Claude с флагом --proxy-server и переменными окружения.',
  },
  {
    id: 'cursor',
    name: 'Cursor IDE',
    category: 'AI IDE',
    primaryDomain: 'api2.cursor.sh',
    domains: [
      'cursor.sh',
      'cursor.com',
      'api2.cursor.sh',
      'api3.cursor.sh',
      'repo42.cursor.sh',
      'api.openai.com',
      'api.anthropic.com',
    ],
    processNames: ['Cursor.exe'],
    defaultWindowsExe: '%LOCALAPPDATA%\\Programs\\cursor\\Cursor.exe',
    supportsChromiumProxyFlag: true,
    description: 'Туннелирует API Cursor, Tab-автодополнение и запросы к моделям OpenAI/Anthropic.',
  },
  {
    id: 'windsurf',
    name: 'Windsurf IDE',
    category: 'AI IDE',
    primaryDomain: 'server.codeium.com',
    domains: ['windsurf.com', 'codeium.com', 'server.codeium.com', 'web-backend.windsurf.com'],
    processNames: ['Windsurf.exe'],
    defaultWindowsExe: '%LOCALAPPDATA%\\Programs\\Windsurf\\Windsurf.exe',
    supportsChromiumProxyFlag: true,
    description: 'Захватывает Windsurf Cascade и бэкенды Codeium с безопасным исключением 127.0.0.1.',
  },
  {
    id: 'gemini_cli',
    name: 'Gemini CLI',
    category: 'AI CLI',
    primaryDomain: 'generativelanguage.googleapis.com',
    domains: [
      'generativelanguage.googleapis.com',
      'cloudcode-pa.googleapis.com',
      'ai.google.dev',
      'oauth2.googleapis.com',
    ],
    processNames: ['gemini.cmd'],
    defaultWindowsExe: 'gemini',
    supportsChromiumProxyFlag: false,
    description: 'Проксирует консольный Gemini CLI и OAuth-авторизацию Google через локальный узел.',
  },
  {
    id: 'codex_cli',
    name: 'OpenAI Codex CLI',
    category: 'AI CLI',
    primaryDomain: 'api.openai.com',
    domains: ['api.openai.com', 'chatgpt.com', 'auth.openai.com', 'ab.chatgpt.com'],
    processNames: ['codex.cmd'],
    defaultWindowsExe: 'codex',
    supportsChromiumProxyFlag: false,
    description: 'Туннелирует CLI-агент OpenAI Codex и API-запросы через локальный HTTP/CONNECT прокси.',
  },
  {
    id: 'chatgpt_desktop',
    name: 'ChatGPT Desktop',
    category: 'AI App',
    primaryDomain: 'chatgpt.com',
    domains: [
      'chatgpt.com',
      'ab.chatgpt.com',
      'api.openai.com',
      'auth.openai.com',
      'cdn.oaistatic.com',
      'oaiusercontent.com',
    ],
    processNames: ['ChatGPT.exe'],
    defaultWindowsExe: '%LOCALAPPDATA%\\Programs\\ChatGPT\\ChatGPT.exe',
    supportsChromiumProxyFlag: true,
    description: 'Захватывает десктопный клиент ChatGPT и загрузку медиа/скриптов oaistatic.',
  },
  {
    id: 'vscode_copilot',
    name: 'VS Code Copilot',
    category: 'AI IDE',
    primaryDomain: 'api.githubcopilot.com',
    domains: [
      'api.githubcopilot.com',
      'copilot-proxy.githubusercontent.com',
      'copilot-telemetry.githubusercontent.com',
    ],
    processNames: ['Code.exe'],
    defaultWindowsExe: '%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe',
    supportsChromiumProxyFlag: true,
    description: 'Направляет GitHub Copilot Chat и автодополнение кода через локальный прокси.',
  },
];

export const ALL_AI_AND_APP_DOMAINS: string[] = Array.from(
  new Set([
    'gemini.google.com',
    'aistudio.google.com',
    'ai.studio',
    'alkalimakersuite-pa.clients6.google.com',
    'alkalicore-pa.clients6.google.com',
    'webchannel-alkalimakersuite-pa.clients6.google.com',
    'generativelanguage.googleapis.com',
    'geller-pa.googleapis.com',
    'generativeai.google',
    'makersuite.google.com',
    'ai.google.dev',
    'gemini.gstatic.com',
    'notebooklm.google.com',
    'labs.google',
    'aisandbox-pa.googleapis.com',
    'chatgpt.com',
    'openai.com',
    'api.openai.com',
    'auth.openai.com',
    'oaistatic.com',
    'oaiusercontent.com',
    'claude.ai',
    'anthropic.com',
    'api.anthropic.com',
    'grok.com',
    'x.ai',
    'api.x.ai',
    'perplexity.ai',
    'api.perplexity.ai',
    'deepseek.com',
    'api.deepseek.com',
    'mistral.ai',
    'api.mistral.ai',
    'api.groq.com',
    'openrouter.ai',
    'copilot.microsoft.com',
    'sydney.bing.com',
    'huggingface.co',
    ...AI_DESKTOP_APPS.flatMap((app) => app.domains),
  ])
);

export function buildPowerShellCaptureCommand(app: AiAppProfile, proxyAddress: string): string {
  const proxyUrl = proxyAddress.startsWith('http') ? proxyAddress : `http://${proxyAddress}`;
  const envBlock = [
    `$env:HTTP_PROXY='${proxyUrl}'`,
    `$env:HTTPS_PROXY='${proxyUrl}'`,
    `$env:ALL_PROXY='${proxyUrl}'`,
    `$env:NO_PROXY='${LOOPBACK_SAFE_NO_PROXY}'`,
    `$env:NODE_USE_ENV_PROXY='1'`,
    `$env:GRPC_PROXY_EXP='${proxyUrl}'`,
  ].join('; ');

  if (app.supportsChromiumProxyFlag) {
    const psExe = app.defaultWindowsExe
      .replace('%LOCALAPPDATA%', '$env:LOCALAPPDATA')
      .replace('%APPDATA%', '$env:APPDATA');
    return `${envBlock}; & "${psExe}" --proxy-server=${proxyUrl} --proxy-bypass-list="${CHROMIUM_PROXY_BYPASS_LIST}"`;
  }

  return `${envBlock}; ${app.defaultWindowsExe}`;
}

export function buildWindowsBatLauncher(app: AiAppProfile, proxyAddress: string): string {
  const proxyUrl = proxyAddress.startsWith('http') ? proxyAddress : `http://${proxyAddress}`;
  const lines = [
    '@echo off',
    `title DNS Pulse AI Tunnel - ${app.name}`,
    `set HTTP_PROXY=${proxyUrl}`,
    `set HTTPS_PROXY=${proxyUrl}`,
    `set ALL_PROXY=${proxyUrl}`,
    `set NO_PROXY=${LOOPBACK_SAFE_NO_PROXY}`,
    'set NODE_USE_ENV_PROXY=1',
    `set GRPC_PROXY_EXP=${proxyUrl}`,
    `echo [DNS Pulse] Local AI proxy active: ${proxyUrl}`,
    `echo [DNS Pulse] Loopback IPC bypassed via NO_PROXY`,
  ];

  if (app.supportsChromiumProxyFlag) {
    lines.push(
      `start "" "${app.defaultWindowsExe}" --proxy-server=${proxyUrl} --proxy-bypass-list="${CHROMIUM_PROXY_BYPASS_LIST}"`
    );
  } else {
    lines.push(`cmd /k "${app.defaultWindowsExe}"`);
  }

  return lines.join('\r\n') + '\r\n';
}

export function buildGlobalWindowsEnvCaptureScript(proxyAddress: string): string {
  const proxyUrl = proxyAddress.startsWith('http') ? proxyAddress : `http://${proxyAddress}`;
  return [
    '# Включает локальный прокси DNS Pulse для всех AI-приложений (Antigravity, Claude Code, Cursor, Windsurf)',
    `[Environment]::SetEnvironmentVariable('HTTP_PROXY', '${proxyUrl}', 'User')`,
    `[Environment]::SetEnvironmentVariable('HTTPS_PROXY', '${proxyUrl}', 'User')`,
    `[Environment]::SetEnvironmentVariable('ALL_PROXY', '${proxyUrl}', 'User')`,
    `[Environment]::SetEnvironmentVariable('NO_PROXY', '${LOOPBACK_SAFE_NO_PROXY}', 'User')`,
    `[Environment]::SetEnvironmentVariable('NODE_USE_ENV_PROXY', '1', 'User')`,
    `[Environment]::SetEnvironmentVariable('GRPC_PROXY_EXP', '${proxyUrl}', 'User')`,
    'Write-Host "Готово! Перезапустите терминал, Antigravity или Claude Code." -ForegroundColor Green',
  ].join('\n');
}
