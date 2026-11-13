using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// HTTP method used for RFC 8484 DNS-over-HTTPS requests.
/// </summary>
public enum DohHttpMethod
{
    Post = 0,
    Get = 1
}

/// <summary>
/// Shared configuration options for upstream DNS transport clients.
/// </summary>
public sealed record TransportOptions
{
    /// <summary>Gets the default connect/query timeout applied to upstream sockets and HTTP requests.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Gets whether TLS ClientHello fragmentation is enabled by default for TCP-based TLS transports.</summary>
    public bool EnableTlsFragmentation { get; init; }

    /// <summary>Gets the chunk size in bytes used when fragmenting the initial TLS ClientHello record.</summary>
    public int TlsFragmentChunkSize { get; init; } = 40;

    /// <summary>Gets an optional delay between fragmented ClientHello TCP writes.</summary>
    public TimeSpan? TlsFragmentInterChunkDelay { get; init; }

    /// <summary>Gets the preferred HTTP method for DoH queries.</summary>
    public DohHttpMethod DohMethod { get; init; } = DohHttpMethod.Post;

    /// <summary>Gets the allowed TLS protocol versions. Defaults to OS-negotiated best version (TLS 1.3).</summary>
    public SslProtocols EnabledSslProtocols { get; init; } = SslProtocols.None;

    /// <summary>Gets optional custom trust anchors used for X.509 chain validation (e.g., private or test CAs).</summary>
    public X509Certificate2Collection? CustomTrustAnchors { get; init; }

    /// <summary>Gets the maximum idle lifetime for pooled DoT/DoQ connections.</summary>
    public TimeSpan ConnectionIdleTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Gets the maximum number of pooled idle connections retained per upstream endpoint.</summary>
    public int MaxIdleConnectionsPerEndpoint { get; init; } = 4;
}
