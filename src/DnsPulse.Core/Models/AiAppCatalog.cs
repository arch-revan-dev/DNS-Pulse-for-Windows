namespace DnsPulse.Core.Models;

/// <summary>
/// Metadata describing a desktop or CLI AI application whose traffic can be routed
/// through DNS Pulse's local loopback DNS and HTTP/SOCKS5 proxy tunnel.
/// </summary>
public sealed record AiAppProfile(
    string Id,
    string DisplayName,
    string Category,
    IReadOnlyList<string> ProcessNames,
    IReadOnlyList<string> ExecutableProbePaths,
    IReadOnlyList<string> Domains,
    bool SupportsChromiumProxyFlag,
    bool SupportsEnvProxy,
    string Notes);

/// <summary>
/// Curated catalog of AI desktop and CLI applications (Antigravity, Claude Code, Cursor, Windsurf,
/// Codex CLI, Gemini CLI, ChatGPT Desktop, VS Code Copilot) and their required API/auth endpoints.
/// </summary>
public static class AiAppCatalog
{
    /// <summary>
    /// Loopback-safe <c>NO_PROXY</c> exclusion list that prevents local IPC deadlocks
    /// (such as Antigravity's local language server on <c>127.0.0.1</c> or local DNS listeners).
    /// </summary>
    public const string LoopbackSafeNoProxy =
        "localhost,127.0.0.1,::1,127.0.53.1,.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

    /// <summary>
    /// Built-in profiles for popular Windows desktop and CLI AI tools.
    /// </summary>
    public static IReadOnlyList<AiAppProfile> DesktopApps { get; } =
    [
        new AiAppProfile(
            Id: "antigravity",
            DisplayName: "Google Antigravity",
            Category: "AI IDE",
            ProcessNames: ["Antigravity", "antigravity", "agy", "language_server_windows_x64"],
            ExecutableProbePaths:
            [
                @"%LOCALAPPDATA%\Programs\Antigravity\Antigravity.exe",
                @"%ProgramFiles%\Antigravity\Antigravity.exe"
            ],
            Domains:
            [
                "antigravity.google",
                "antigravity-pa.googleapis.com",
                "antigravity.googleapis.com",
                "antigravity-unleash.goog",
                "cloudcode-pa.googleapis.com",
                "daily-cloudcode-pa.googleapis.com",
                "daily-cloudcode-pa.sandbox.googleapis.com",
                "autopush-cloudcode-pa.sandbox.googleapis.com",
                "cloudaicompanion.googleapis.com",
                "cloudaicompanion.sandbox.googleapis.com",
                "aicode.googleapis.com",
                "aida.googleapis.com",
                "optimizationguide-pa.googleapis.com",
                "developerprofiles-pa.googleapis.com",
                "generativelanguage.googleapis.com",
                "alkalimakersuite-pa.googleapis.com",
                "aistudio.google.com",
                "aiplatform.googleapis.com",
                "oauth2.googleapis.com",
                "accounts.google.com",
                "play.googleapis.com",
                "www.googleapis.com"
            ],
            SupportsChromiumProxyFlag: true,
            SupportsEnvProxy: true,
            Notes: "Routes Electron shell and local Go/gRPC language server through 127.0.0.1 while keeping loopback IPC bypassed."),

        new AiAppProfile(
            Id: "claude_code",
            DisplayName: "Claude Code CLI",
            Category: "AI CLI",
            ProcessNames: ["claude"],
            ExecutableProbePaths:
            [
                @"%APPDATA%\npm\claude.cmd",
                @"%USERPROFILE%\.local\bin\claude.exe",
                @"%LOCALAPPDATA%\Programs\claude-code\claude.exe"
            ],
            Domains:
            [
                "api.anthropic.com",
                "claude.ai",
                "console.anthropic.com",
                "statsig.anthropic.com",
                "mcp-proxy.anthropic.com",
                "a-cdn.anthropic.com",
                "anthropic.com"
            ],
            SupportsChromiumProxyFlag: false,
            SupportsEnvProxy: true,
            Notes: "Uses HTTPS_PROXY and NODE_USE_ENV_PROXY=1 so Node.js undici/fetch routes directly via local tunnel."),

        new AiAppProfile(
            Id: "claude_desktop",
            DisplayName: "Claude Desktop",
            Category: "AI App",
            ProcessNames: ["Claude"],
            ExecutableProbePaths:
            [
                @"%LOCALAPPDATA%\AnthropicClaude\Claude.exe",
                @"%LOCALAPPDATA%\Programs\claude-desktop\Claude.exe"
            ],
            Domains:
            [
                "claude.ai",
                "api.anthropic.com",
                "a-cdn.anthropic.com",
                "statsig.anthropic.com",
                "anthropic.com"
            ],
            SupportsChromiumProxyFlag: true,
            SupportsEnvProxy: true,
            Notes: "Electron desktop client with Chromium proxy flag and environment variable capture."),

        new AiAppProfile(
            Id: "cursor",
            DisplayName: "Cursor IDE",
            Category: "AI IDE",
            ProcessNames: ["Cursor"],
            ExecutableProbePaths:
            [
                @"%LOCALAPPDATA%\Programs\cursor\Cursor.exe",
                @"%ProgramFiles%\Cursor\Cursor.exe"
            ],
            Domains:
            [
                "cursor.sh",
                "cursor.com",
                "api2.cursor.sh",
                "api3.cursor.sh",
                "repo42.cursor.sh",
                "api.openai.com",
                "api.anthropic.com"
            ],
            SupportsChromiumProxyFlag: true,
            SupportsEnvProxy: true,
            Notes: "Captures Cursor API endpoints and upstream model APIs over local tunnel."),

        new AiAppProfile(
            Id: "windsurf",
            DisplayName: "Windsurf IDE",
            Category: "AI IDE",
            ProcessNames: ["Windsurf"],
            ExecutableProbePaths:
            [
                @"%LOCALAPPDATA%\Programs\Windsurf\Windsurf.exe",
                @"%ProgramFiles%\Windsurf\Windsurf.exe"
            ],
            Domains:
            [
                "windsurf.com",
                "codeium.com",
                "server.codeium.com",
                "web-backend.windsurf.com"
            ],
            SupportsChromiumProxyFlag: true,
            SupportsEnvProxy: true,
            Notes: "Captures Windsurf Cascade and Codeium backends with loopback-safe NO_PROXY."),

        new AiAppProfile(
            Id: "gemini_cli",
            DisplayName: "Gemini CLI",
            Category: "AI CLI",
            ProcessNames: ["gemini"],
            ExecutableProbePaths:
            [
                @"%APPDATA%\npm\gemini.cmd"
            ],
            Domains:
            [
                "generativelanguage.googleapis.com",
                "cloudcode-pa.googleapis.com",
                "ai.google.dev",
                "oauth2.googleapis.com"
            ],
            SupportsChromiumProxyFlag: false,
            SupportsEnvProxy: true,
            Notes: "Routes Google Gemini CLI API and OAuth traffic through local proxy."),

        new AiAppProfile(
            Id: "codex_cli",
            DisplayName: "OpenAI Codex CLI",
            Category: "AI CLI",
            ProcessNames: ["codex"],
            ExecutableProbePaths:
            [
                @"%APPDATA%\npm\codex.cmd"
            ],
            Domains:
            [
                "api.openai.com",
                "chatgpt.com",
                "auth.openai.com",
                "ab.chatgpt.com"
            ],
            SupportsChromiumProxyFlag: false,
            SupportsEnvProxy: true,
            Notes: "Routes OpenAI Codex CLI API and authentication requests through local proxy."),

        new AiAppProfile(
            Id: "chatgpt_desktop",
            DisplayName: "ChatGPT Desktop",
            Category: "AI App",
            ProcessNames: ["ChatGPT"],
            ExecutableProbePaths:
            [
                @"%LOCALAPPDATA%\Programs\ChatGPT\ChatGPT.exe"
            ],
            Domains:
            [
                "chatgpt.com",
                "ab.chatgpt.com",
                "api.openai.com",
                "auth.openai.com",
                "cdn.oaistatic.com",
                "oaiusercontent.com"
            ],
            SupportsChromiumProxyFlag: true,
            SupportsEnvProxy: true,
            Notes: "Routes ChatGPT desktop traffic and static assets via Smart-DNS + local proxy."),

        new AiAppProfile(
            Id: "vscode_copilot",
            DisplayName: "VS Code Copilot",
            Category: "AI IDE",
            ProcessNames: ["Code"],
            ExecutableProbePaths:
            [
                @"%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe",
                @"%ProgramFiles%\Microsoft VS Code\Code.exe"
            ],
            Domains:
            [
                "api.githubcopilot.com",
                "copilot-proxy.githubusercontent.com",
                "copilot-telemetry.githubusercontent.com"
            ],
            SupportsChromiumProxyFlag: true,
            SupportsEnvProxy: true,
            Notes: "Routes GitHub Copilot completions and chat endpoints via local proxy.")
    ];

    /// <summary>
    /// Additional desktop AI application and API domains beyond the legacy 52-entry <see cref="BuiltInCatalogPresets.BuiltinAiDomains"/> list.
    /// </summary>
    public static IReadOnlyList<string> ExtraDesktopAiDomains { get; } =
    [
        "antigravity.google",
        "antigravity-pa.googleapis.com",
        "antigravity.googleapis.com",
        "antigravity-unleash.goog",
        "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.sandbox.googleapis.com",
        "autopush-cloudcode-pa.sandbox.googleapis.com",
        "cloudaicompanion.googleapis.com",
        "cloudaicompanion.sandbox.googleapis.com",
        "aicode.googleapis.com",
        "aida.googleapis.com",
        "optimizationguide-pa.googleapis.com",
        "developerprofiles-pa.googleapis.com",
        "alkalimakersuite-pa.googleapis.com",
        "notebooklm-pa.googleapis.com",
        "notebooklm.googleapis.com",
        "flow.google.com",
        "geller-pa.googleapis.com",
        "aiplatform.googleapis.com",
        "console.anthropic.com",
        "statsig.anthropic.com",
        "mcp-proxy.anthropic.com",
        "a-cdn.anthropic.com",
        "api2.cursor.sh",
        "api3.cursor.sh",
        "repo42.cursor.sh",
        "windsurf.com",
        "server.codeium.com",
        "web-backend.windsurf.com",
        "ab.chatgpt.com",
        "cdn.oaistatic.com",
        "api.x.ai",
        "api.perplexity.ai",
        "deepseek.com",
        "api.deepseek.com",
        "mistral.ai",
        "api.mistral.ai",
        "api.groq.com",
        "openrouter.ai",
        "api.githubcopilot.com",
        "copilot-telemetry.githubusercontent.com"
    ];

    /// <summary>
    /// Full deduplicated union of built-in AI web domains and desktop/CLI AI application domains.
    /// </summary>
    public static IReadOnlyList<string> AllAiAndAppDomains { get; } =
    [
        .. BuiltInCatalogPresets.BuiltinAiDomains
            .Concat(ExtraDesktopAiDomains)
            .Distinct(StringComparer.OrdinalIgnoreCase)
    ];

    /// <summary>
    /// Returns the Chromium/Electron <c>--proxy-bypass-list</c> argument value that always excludes loopback IPC.
    /// </summary>
    public static string ChromiumProxyBypassList => "<-loopback>;localhost;127.0.0.1;::1;127.0.53.1;*.local";
}
