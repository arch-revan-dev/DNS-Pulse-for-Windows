using System.Net;
using DnsPulse.Engine.Sidecar;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Ipc;

namespace DnsPulse.Service;

/// <summary>
/// Configuration options governing <see cref="DnsPulseWorkerService"/> and <see cref="DefaultPulseRuntimeBackend"/>.
/// </summary>
public sealed record PulseServiceOptions
{
    public string PipeName { get; init; } = PipeSecurityBuilder.DefaultPipeName;

    public IPAddress PreferredLoopbackAddress { get; init; } = IPAddress.Loopback;

    public IPAddress SidecarLoopbackAddress { get; init; } = TlsFragmentationProxyOptions.DefaultBindAddress;

    public int DnsPort { get; init; } = 53;

    public int DohPort { get; init; } = 5343;

    public int ProxyPort { get; init; } = 10808;

    public int PacPort { get; init; } = 10809;

    public InterceptionMode InterceptionMode { get; init; } = InterceptionMode.AdapterDns;

    public TimeSpan HealthCheckInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Continuous unhealthy listener duration before the Dead-Man's Switch triggers automatic emergency rollback.
    /// </summary>
    public TimeSpan UnhealthyRollbackThreshold { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan ShutdownOperationTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public bool EnableSidecarProxy { get; init; } = true;

    public bool EnableDohListener { get; init; } = true;

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
