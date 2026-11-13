using System.Net;

namespace DnsPulse.Engine.Hosting;

/// <summary>
/// Configuration options for <see cref="LocalDohHttpListener"/>.
/// </summary>
public sealed record LocalDohServerOptions
{
    public IPAddress ListenAddress { get; init; } = IPAddress.Loopback;

    public int Port { get; init; } = 5343;

    public string Path { get; init; } = "/dns-query";

    public int MaxRequestBodyBytes { get; init; } = 65535;

    public int MaxConcurrentConnections { get; init; } = 512;

    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(10);
}
