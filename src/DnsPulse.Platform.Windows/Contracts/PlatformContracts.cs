using System.Diagnostics.CodeAnalysis;
using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Pipeline;

namespace DnsPulse.Platform.Windows.Contracts;

/// <summary>
/// Windows DNS interception modes supported by PulseCore.
/// </summary>
public enum InterceptionMode
{
    None = 0,
    AdapterDns = 1,
    SplitNrpt = 2,
    LocalProxyPacOnly = 3,
    WfpDivertPlugin = 4
}

/// <summary>
/// Captured per-adapter DNS configuration prior to Pulse activation.
/// </summary>
public sealed record AdapterDnsConfiguration
{
    public string InterfaceGuid { get; init; } = string.Empty;

    public string InterfaceName { get; init; } = string.Empty;

    public string InterfaceDescription { get; init; } = string.Empty;

    public IReadOnlyList<string> OriginalIpv4Dns { get; init; } = [];

    public IReadOnlyList<string> OriginalIpv6Dns { get; init; } = [];

    public bool WasDhcpIpv4 { get; init; }

    public bool WasDhcpIpv6 { get; init; }

    public bool IsPhysicalUp { get; init; }
}

/// <summary>
/// Crash-safe, integrity-checksummed snapshot of pre-Pulse Windows networking state.
/// </summary>
public sealed record PrePulseNetworkSnapshot
{
    public int SnapshotVersion { get; init; } = 1;

    public DateTimeOffset CapturedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public bool DirtyShutdown { get; init; }

    public InterceptionMode ActiveMode { get; init; }

    public string? LoopbackIpUsed { get; init; }

    public IReadOnlyList<AdapterDnsConfiguration> AdapterStates { get; init; } = [];

    public bool PriorSmhnrDisabled { get; init; }

    public IReadOnlyList<string> PriorNrptRuleNames { get; init; } = [];

    public string Sha256Checksum { get; init; } = string.Empty;
}

/// <summary>
/// Windows-specific DNS traffic interception mechanism.
/// </summary>
public interface IDnsInterceptor
{
    InterceptionMode Mode { get; }

    Task ActivateAsync(
        IPAddress localDnsIp,
        int dnsPort,
        IReadOnlyList<string> splitDomains,
        CancellationToken ct = default);

    Task DeactivateAsync(CancellationToken ct = default);
}

/// <summary>
/// Summary returned after restoring original Windows network settings or recovering from a dirty shutdown.
/// </summary>
public sealed record NetworkRestoredResult(
    bool HadDirtyState,
    int AdaptersRestored,
    bool PoliciesCleaned,
    string Summary);

/// <summary>
/// Length-prefixed JSON-RPC request sent over the hardened Named Pipe.
/// </summary>
public sealed record PipeRpcRequest(
    string RequestId,
    string Command,
    string? PayloadJson = null);

/// <summary>
/// Length-prefixed JSON-RPC response returned over the hardened Named Pipe.
/// </summary>
public sealed record PipeRpcResponse(
    string RequestId,
    bool Success,
    string? ErrorCode = null,
    string? ErrorMessage = null,
    string? PayloadJson = null);

/// <summary>
/// Canonical Named Pipe RPC command names between the WPF UI and <c>DnsPulse.Service</c>.
/// </summary>
public static class PipeCommandNames
{
    public const string GetStatus = nameof(GetStatus);
    public const string Connect = nameof(Connect);
    public const string Disconnect = nameof(Disconnect);
    public const string EmergencyRestore = nameof(EmergencyRestore);
    public const string ApplyProfile = nameof(ApplyProfile);
    public const string RunDiagnostics = nameof(RunDiagnostics);
    public const string UpdateBlocklist = nameof(UpdateBlocklist);
    public const string GetRecentTelemetry = nameof(GetRecentTelemetry);
    public const string ExportBundle = nameof(ExportBundle);
    public const string ShutdownService = nameof(ShutdownService);
    public const string UpdateRoutingConfig = nameof(UpdateRoutingConfig);
    public const string UpdatePool = nameof(UpdatePool);
    public const string ConfigureEngine = nameof(ConfigureEngine);
}

/// <summary>
/// Runtime status snapshot reported by <c>DnsPulse.Service</c> to UI clients.
/// </summary>
public sealed record ServiceStatusSnapshot
{
    public bool IsConnected { get; init; }

    public bool IsHealthy { get; init; }

    public InterceptionMode ActiveMode { get; init; }

    public string? ActiveLoopbackIp { get; init; }

    public int BoundDnsPort { get; init; }

    public int BoundDoHPort { get; init; }

    public int BoundProxyPort { get; init; }

    public int BoundPacPort { get; init; }

    public double CacheHitRatePercent { get; init; }

    public double QueriesPerMinute { get; init; }

    public int ActiveUpstreamsCount { get; init; }

    public bool DirtyRecoveryPending { get; init; }

    public string? LastErrorMessage { get; init; }

    public double? LatencyP50Ms { get; init; }

    public string? ActiveGeoUnlockUpstreamId { get; init; }

    public InterceptionMode RequestedMode { get; init; }

    public bool InterceptionActive { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Matches AutoPacServer.PacUrl and WinINet AutoConfigURL string format.")]
    public string? PacUrl { get; init; }

    public string? ActiveTrustedUpstreamId { get; init; }

    public int ActiveGeoUnlockRulesCount { get; init; }

    public string? InterceptionStatusDetail { get; init; }
}

/// <summary>
/// Optional payload for <see cref="PipeCommandNames.Connect"/> allowing atomic port, interception, routing, and pool configuration.
/// </summary>
public sealed record ServiceConnectRequest(
    int? DnsPort = null,
    int? DohPort = null,
    int? ProxyPort = null,
    int? PacPort = null,
    InterceptionMode? InterceptionMode = null,
    bool? BlockIpv6OnBypass = null,
    bool? EnableSidecarProxy = null,
    bool? EnableDohListener = null,
    bool? AutoFallbackToPacOnPort53Conflict = null,
    string? StrategyProfile = null,
    string? ActiveTrustedUpstreamId = null,
    string? ActiveGeoUnlockUpstreamId = null,
    SplitNamespaceRouterConfig? RoutingConfig = null,
    IReadOnlyList<string>? SplitDomains = null,
    IReadOnlyList<DnsServerEntry>? Zone4Servers = null,
    IReadOnlyList<DnsServerEntry>? GeoUnlockUpstreams = null,
    IReadOnlyList<DnsServerEntry>? LocalBypassUpstreams = null,
    PoolSelectionStrategy? Zone1Strategy = null,
    PoolSelectionStrategy? Zone3Strategy = null,
    PoolSelectionStrategy? Zone4Strategy = null,
    BlockResponseMode? BlockMode = null,
    bool? AllowCarrierAnycastExceptions = null,
    string? NamedCarrierEndpointId = null,
    bool ClearCache = true);

/// <summary>
/// Payload for <see cref="PipeCommandNames.UpdateRoutingConfig"/>.
/// </summary>
public sealed record ServiceRoutingConfigRequest(
    SplitNamespaceRouterConfig? RoutingConfig = null,
    IReadOnlyList<string>? SplitDomains = null,
    bool ClearCache = true);

/// <summary>
/// Payload for <see cref="PipeCommandNames.UpdatePool"/>.
/// </summary>
public sealed record ServicePoolUpdateRequest(
    IReadOnlyList<DnsServerEntry>? Zone4Servers = null,
    IReadOnlyList<DnsServerEntry>? GeoUnlockUpstreams = null,
    IReadOnlyList<DnsServerEntry>? LocalBypassUpstreams = null,
    string? ActiveTrustedUpstreamId = null,
    string? ActiveGeoUnlockUpstreamId = null,
    PoolSelectionStrategy? Zone1Strategy = null,
    PoolSelectionStrategy? Zone3Strategy = null,
    PoolSelectionStrategy? Zone4Strategy = null,
    bool ClearCache = true);

/// <summary>
/// Payload for <see cref="PipeCommandNames.ConfigureEngine"/> and <see cref="PipeCommandNames.ApplyProfile"/>.
/// </summary>
public sealed record ServiceEngineConfigRequest(
    int? DnsPort = null,
    int? DohPort = null,
    int? ProxyPort = null,
    int? PacPort = null,
    InterceptionMode? InterceptionMode = null,
    bool? BlockIpv6OnBypass = null,
    bool? EnableSidecarProxy = null,
    bool? EnableDohListener = null,
    bool? AutoFallbackToPacOnPort53Conflict = null,
    string? StrategyProfile = null,
    string? ActiveTrustedUpstreamId = null,
    string? ActiveGeoUnlockUpstreamId = null,
    SplitNamespaceRouterConfig? RoutingConfig = null,
    IReadOnlyList<string>? SplitDomains = null,
    IReadOnlyList<DnsServerEntry>? Zone4Servers = null,
    IReadOnlyList<DnsServerEntry>? GeoUnlockUpstreams = null,
    IReadOnlyList<DnsServerEntry>? LocalBypassUpstreams = null,
    PoolSelectionStrategy? Zone1Strategy = null,
    PoolSelectionStrategy? Zone3Strategy = null,
    PoolSelectionStrategy? Zone4Strategy = null,
    BlockResponseMode? BlockMode = null,
    bool? AllowCarrierAnycastExceptions = null,
    string? NamedCarrierEndpointId = null,
    bool ClearCache = true,
    bool ReconnectIfNeeded = false);

/// <summary>
/// Payload for <see cref="PipeCommandNames.UpdateBlocklist"/>.
/// </summary>
public sealed record ServiceBlocklistUpdateRequest(
    IReadOnlyList<string>? BlockRules = null,
    IReadOnlyList<string>? AllowExceptionRules = null,
    bool ClearCache = true);

/// <summary>
/// Payload for <see cref="PipeCommandNames.RunDiagnostics"/>.
/// </summary>
public sealed record ServiceDiagnosticsRequest(
    string? TargetDomain = null,
    DnsServerEntry? Upstream = null,
    int? TimeoutMs = null);

/// <summary>
/// Response returned by <see cref="PipeCommandNames.RunDiagnostics"/>.
/// </summary>
public sealed record ServiceDiagnosticsResponse(
    ServiceStatusSnapshot Status,
    HostNetworkHealthSnapshot HostHealth,
    DiagnosticReport? Report = null);

/// <summary>
/// Payload for <see cref="PipeCommandNames.ExportBundle"/>.
/// </summary>
public sealed record ServiceExportBundleRequest(
    string? OutputZipPath = null);

/// <summary>
/// Response returned by <see cref="PipeCommandNames.ExportBundle"/>.
/// </summary>
public sealed record ServiceExportBundleResponse(
    string OutputZipPath);
