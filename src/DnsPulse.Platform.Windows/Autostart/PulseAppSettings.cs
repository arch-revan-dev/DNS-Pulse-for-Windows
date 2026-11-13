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
            UseLocalDohEndpoint = UseLocalDohEndpoint
        };
    }
}
