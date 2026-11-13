using System.Net;

namespace DnsPulse.Engine.Sidecar;

/// <summary>
/// Configuration options for <see cref="TlsFragmentationProxyServer"/>.
/// </summary>
public sealed record TlsFragmentationProxyOptions
{
    /// <summary>
    /// Default local loopback bind address (<c>127.0.53.1</c>) isolating DNS Pulse sidecar traffic.
    /// </summary>
    public static IPAddress DefaultBindAddress { get; } = IPAddress.Parse("127.0.53.1");

    /// <summary>
    /// Local IP address to bind the proxy listener on (<c>127.0.53.1</c> by default, or LAN gateway IP).
    /// </summary>
    public IPAddress BindAddress { get; init; } = DefaultBindAddress;

    /// <summary>
    /// TCP port to listen on (0 selects an ephemeral OS-assigned port).
    /// </summary>
    public int Port { get; init; }

    /// <summary>
    /// When <c>true</c>, splits the initial TLS <c>ClientHello</c> directly across the SNI extension boundary.
    /// </summary>
    public bool SplitAtSni { get; init; } = true;

    /// <summary>
    /// Maximum chunk size in bytes when fragmenting the initial TLS <c>ClientHello</c> (0 disables fixed-size chunking beyond the SNI split).
    /// </summary>
    public int FragmentChunkSize { get; init; } = 32;

    /// <summary>
    /// Delay in milliseconds between fragmented TCP sends to prevent Nagle/kernel coalescing across DPI windows.
    /// </summary>
    public int InterFragmentDelayMs { get; init; } = 2;

    /// <summary>
    /// When <c>true</c>, normalizes the plain-HTTP <c>Host:</c> header casing to <see cref="NormalizedHostHeaderName"/>.
    /// </summary>
    public bool NormalizePlainHttpHostHeader { get; init; } = true;

    /// <summary>
    /// Header name emitted when <see cref="NormalizePlainHttpHostHeader"/> is enabled (defaults to lowercase <c>host</c>).
    /// </summary>
    public string NormalizedHostHeaderName { get; init; } = "host";

    /// <summary>
    /// Enforces SSRF protection via <see cref="Core.Security.IpSafetyInspector"/>, blocking private, loopback, link-local, CGNAT, and bogon destination IPs.
    /// </summary>
    public bool BlockPrivateDestinationIps { get; init; } = true;

    /// <summary>
    /// Timeout applied when connecting to upstream targets.
    /// </summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Maximum number of concurrent active proxy tunnel connections.
    /// </summary>
    public int MaxConcurrentConnections { get; init; } = 256;

    /// <summary>
    /// Maximum buffer size in bytes for initial protocol handshake/header inspection.
    /// </summary>
    public int MaxInitialPayloadBytes { get; init; } = 16 * 1024;
}
