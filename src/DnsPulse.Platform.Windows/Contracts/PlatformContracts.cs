using System.Net;

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
}
