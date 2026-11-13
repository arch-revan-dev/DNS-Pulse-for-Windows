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
