using System.Net;

namespace DnsPulse.Engine.Hosting;

/// <summary>
/// Configuration options for <see cref="LocalDnsServer"/>.
/// </summary>
public sealed record LocalDnsServerOptions
{
    public IPAddress ListenAddress { get; init; } = IPAddress.Loopback;

    public int Port { get; init; } = 53;

    public int MaxConcurrentRequests { get; init; } = 1024;

    public TimeSpan TcpIdleTimeout { get; init; } = TimeSpan.FromSeconds(10);
}
