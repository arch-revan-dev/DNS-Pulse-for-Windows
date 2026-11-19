using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Updates;

namespace DnsPulse.Platform.Windows.Autostart;

/// <summary>
/// Persisted user and PulseCore runtime settings stored at <c>%APPDATA%\DnsPulse\settings.json</c>.
/// Preserves full schema compatibility with v1.5.3 <c>AppSettings</c> files.
/// </summary>
public sealed class PulseAppSettings
{
    // Legacy v1.5.3 properties
    public bool IsDarkTheme { get; set; } = true;

    public string AccentPreset { get; set; } = "Emerald";

    public bool CompactMode { get; set; }

    public bool StartWithWindows { get; set; }

    public bool StartMinimizedToTray { get; set; } = true;

    public bool MinimizeToTrayOnClose { get; set; } = true;

    public bool AutoModeEnabled { get; set; }

    public bool AutoFailoverOnDrop { get; set; } = true;

    public bool AutoCheckUpdates { get; set; } = true;

    public string GitHubToken { get; set; } = string.Empty;

    public bool AutoSyncFeedsOnStartup { get; set; } = true;

    public bool SplitTunnelEnabled { get; set; } = true;

    public bool BlockIpv6OnBypass { get; set; } = true;

    public string BootstrapDnsProvider { get; set; } = "Auto";

    public int ProbeTimeoutMs { get; set; } = 2600;

    public int BenchmarkConcurrency { get; set; } = 6;

    // PulseCore v2.0 properties
    public InterceptionMode InterceptionMode { get; set; } = InterceptionMode.AdapterDns;

    public bool EnableLocalTlsSplitPac { get; set; } = true;

    public bool ZeroDiskQueryLogging { get; set; } = true;

    public string UiLanguage { get; set; } = "en-US";

    public UpdateChannel UpdateChannel { get; set; } = UpdateChannel.Stable;

    public PoolSelectionStrategy PoolStrategy { get; set; } = PoolSelectionStrategy.Fastest;

    public bool DnsRebindingProtectionEnabled { get; set; } = true;

    public bool LanGatewayEnabled { get; set; }

    public bool UseLocalDohEndpoint { get; set; }

    public bool DismissedBrowserDohBanner { get; set; }

    public bool DismissedPort53Banner { get; set; }

    public bool DismissedVpnBanner { get; set; }

    public bool DismissedAntiCheatBanner { get; set; }

    public string SelectedQuickServiceId { get; set; } = "google_ai_studio";

    public string LastVerifiedTargetDomain { get; set; } = "aistudio.google.com";

    /// <summary>
    /// Local DNS listener port (<c>53</c> default, or <c>0</c> for Auto ephemeral port selection).
    /// </summary>
    public int LocalDnsPort { get; set; } = 53;

    /// <summary>
    /// Local DoH listener port (<c>0</c> for Auto ephemeral port selection, or custom <c>1..65535</c>).
    /// </summary>
    public int LocalDohPort { get; set; }

    /// <summary>
    /// Local TLS-fragmentation HTTP/SOCKS5 proxy port (<c>0</c> for Auto, or custom <c>1..65535</c>).
    /// </summary>
    public int LocalProxyPort { get; set; }

    /// <summary>
    /// Local PAC HTTP server port (<c>0</c> for Auto, or custom <c>1..65535</c>).
    /// </summary>
    public int LocalPacPort { get; set; }

    public string StrategyProfile { get; set; } = "SmartSplitDnsGeo";

    public string? SelectedTrustedUpstreamId { get; set; }

    public string? SelectedGeoUnlockUpstreamId { get; set; }

    /// <summary>
    /// Exact IDs of enabled Zone 3 Geo-Unlock presets (<see langword="null"/> retains built-in defaults).
    /// </summary>
    public IReadOnlyList<string>? EnabledRoutingPresetIds { get; set; }

    public IReadOnlyList<string> CustomGeoUnlockDomains { get; set; } = [];

    public IReadOnlyList<string> CustomBlockRules { get; set; } = [];

    public IReadOnlyList<string> CustomAllowRules { get; set; } = [];

    // PulseCore v2.1 AI-Only Autopilot & Desktop AI App Capture properties
    public bool SimpleModeEnabled { get; set; } = true;

    public bool EnableAiAppEnvProxyCapture { get; set; } = true;

    public bool EnableDynamicAiWatchdog { get; set; } = true;

    /// <summary>
    /// Creates a deep copy of the settings instance.
    /// </summary>
    public PulseAppSettings Clone()
    {
        return new PulseAppSettings
        {
            IsDarkTheme = IsDarkTheme,
            AccentPreset = AccentPreset,
            CompactMode = CompactMode,
            StartWithWindows = StartWithWindows,
            StartMinimizedToTray = StartMinimizedToTray,
            MinimizeToTrayOnClose = MinimizeToTrayOnClose,
            AutoModeEnabled = AutoModeEnabled,
            AutoFailoverOnDrop = AutoFailoverOnDrop,
            AutoCheckUpdates = AutoCheckUpdates,
            GitHubToken = GitHubToken,
            AutoSyncFeedsOnStartup = AutoSyncFeedsOnStartup,
            SplitTunnelEnabled = SplitTunnelEnabled,
            BlockIpv6OnBypass = BlockIpv6OnBypass,
            BootstrapDnsProvider = BootstrapDnsProvider,
            ProbeTimeoutMs = ProbeTimeoutMs,
            BenchmarkConcurrency = BenchmarkConcurrency,
            InterceptionMode = InterceptionMode,
            EnableLocalTlsSplitPac = EnableLocalTlsSplitPac,
            ZeroDiskQueryLogging = ZeroDiskQueryLogging,
            UiLanguage = UiLanguage,
            UpdateChannel = UpdateChannel,
            PoolStrategy = PoolStrategy,
            DnsRebindingProtectionEnabled = DnsRebindingProtectionEnabled,
            LanGatewayEnabled = LanGatewayEnabled,
            UseLocalDohEndpoint = UseLocalDohEndpoint,
            DismissedBrowserDohBanner = DismissedBrowserDohBanner,
            DismissedPort53Banner = DismissedPort53Banner,
            DismissedVpnBanner = DismissedVpnBanner,
            DismissedAntiCheatBanner = DismissedAntiCheatBanner,
            SelectedQuickServiceId = SelectedQuickServiceId,
            LastVerifiedTargetDomain = LastVerifiedTargetDomain,
            LocalDnsPort = LocalDnsPort,
            LocalDohPort = LocalDohPort,
            LocalProxyPort = LocalProxyPort,
            LocalPacPort = LocalPacPort,
            StrategyProfile = StrategyProfile,
            SelectedTrustedUpstreamId = SelectedTrustedUpstreamId,
            SelectedGeoUnlockUpstreamId = SelectedGeoUnlockUpstreamId,
            EnabledRoutingPresetIds = EnabledRoutingPresetIds is null ? null : [.. EnabledRoutingPresetIds],
            CustomGeoUnlockDomains = [.. CustomGeoUnlockDomains],
            CustomBlockRules = [.. CustomBlockRules],
            CustomAllowRules = [.. CustomAllowRules],
            SimpleModeEnabled = SimpleModeEnabled,
            EnableAiAppEnvProxyCapture = EnableAiAppEnvProxyCapture,
            EnableDynamicAiWatchdog = EnableDynamicAiWatchdog
        };
    }
}
