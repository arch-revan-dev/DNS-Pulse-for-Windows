using System.Diagnostics.CodeAnalysis;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.Service;

/// <summary>
/// Platform-decoupled runtime backend controlled by <see cref="DnsPulseWorkerService"/> over IPC
/// and monitored by the Dead-Man's Switch watchdog.
/// </summary>
public interface IPulseRuntimeBackend
{
    [SuppressMessage("Design", "CA1024:Use properties where appropriate", Justification = "Maps directly to RPC GetStatus operation.")]
    ServiceStatusSnapshot GetStatus();

    Task<ServiceStatusSnapshot> ConnectAsync(CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> DisconnectAsync(CancellationToken cancellationToken = default);

    Task<NetworkRestoredResult> EmergencyRestoreAsync(CancellationToken cancellationToken = default);

    IReadOnlyList<DnsQueryTelemetryEvent> GetRecentTelemetry(int maxCount = 100);

    Task<bool> ProbeListenerHealthAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Extended runtime backend contract supporting full routing, upstream pool, blocklist, and engine configuration over IPC.
/// </summary>
public interface IConfigurablePulseRuntimeBackend
{
    Task<ServiceStatusSnapshot> ApplyConnectConfigurationAsync(
        ServiceConnectRequest request,
        CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> UpdateRoutingConfigAsync(
        ServiceRoutingConfigRequest request,
        CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> UpdatePoolAsync(
        ServicePoolUpdateRequest request,
        CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> ConfigureEngineAsync(
        ServiceEngineConfigRequest request,
        CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot> UpdateBlocklistAsync(
        ServiceBlocklistUpdateRequest request,
        CancellationToken cancellationToken = default);
}
