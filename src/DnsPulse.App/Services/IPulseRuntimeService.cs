using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.App.Services;

/// <summary>
/// Event arguments carrying the updated runtime <see cref="ServiceStatusSnapshot"/>.
/// </summary>
public sealed class RuntimeStatusChangedEventArgs(ServiceStatusSnapshot snapshot) : EventArgs
{
    public ServiceStatusSnapshot Snapshot { get; } = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
}

/// <summary>
/// Abstraction over PulseCore's hybrid execution runtime (Windows Service via Named Pipe IPC
/// with automatic unprivileged in-process Portable Mode fallback).
/// </summary>
public interface IPulseRuntimeService : IAsyncDisposable
{
    ServiceStatusSnapshot CurrentStatus { get; }

    bool IsServiceMode { get; }

    bool IsElevated { get; }

    DnsServerEntry? ActiveTrustedUpstream { get; }

    DnsServerEntry? ActiveGeoUnlockUpstream { get; }

    SplitNamespaceRouter Router { get; }

    IBootstrapResolver BootstrapResolver { get; }

    Func<DnsProtocol, IDnsUpstreamClient> ClientFactory { get; }

    IHostNetworkHealthProvider HostHealthProvider { get; }

    event EventHandler<RuntimeStatusChangedEventArgs>? StatusChanged;

    event EventHandler<DnsQueryTelemetryEventArgs>? TelemetryReceived;

    Task<ServiceStatusSnapshot> RefreshStatusAsync(CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> ConnectAsync(
        DnsServerEntry? trustedUpstream,
        DnsServerEntry? geoUnlockUpstream = null,
        IReadOnlyList<DnsServerEntry>? fallbackTrustedPool = null,
        PulseAppSettings? settings = null,
        CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> DisconnectAsync(CancellationToken cancellationToken = default);

    Task<DnsServerEntry?> RotateUpstreamAsync(
        IReadOnlyList<DnsServerEntry> candidates,
        CancellationToken cancellationToken = default);

    Task<NetworkRestoredResult> EmergencyRestoreAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DnsQueryTelemetryEvent>> GetRecentTelemetryAsync(
        int maxCount = 200,
        CancellationToken cancellationToken = default);

    Task UpdateRoutingConfigAsync(
        SplitNamespaceRouterConfig config,
        CancellationToken cancellationToken = default);

    Task UpdateEngineOptionsAsync(
        PulseAppSettings settings,
        CancellationToken cancellationToken = default);

    Task<HostNetworkHealthSnapshot> InspectHostHealthAsync(CancellationToken cancellationToken = default);

    SixLayerDiagnosticEngine CreateDiagnosticEngine();

    BenchmarkRunner CreateBenchmarkRunner();
}
