using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;

namespace DnsPulse.Engine.Contracts;

/// <summary>
/// Result returned by an upstream DNS transport client for a single query.
/// </summary>
public sealed record UpstreamQueryResult(
    DnsMessage Response,
    TimeSpan Latency,
    string EndpointUsed,
    DnsProtocol ProtocolUsed);

/// <summary>
/// Transport client capable of sending a DNS query to an upstream resolver over a specific protocol.
/// </summary>
public interface IDnsUpstreamClient
{
    DnsProtocol Protocol { get; }

    Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Central split-DNS resolution pipeline executing routing, caching, upstream transport, and post-processing.
/// </summary>
public interface IPulseDnsResolver
{
    Task<DnsMessage> ResolveAsync(
        DnsMessage query,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Bootstrap resolver used to resolve DoH/DoT/DoQ hostnames and baseline queries without circular dependency on the local proxy.
/// </summary>
public interface IBootstrapResolver
{
    Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        CancellationToken cancellationToken = default);

    Task<DnsMessage> QueryBaselineAsync(
        string domain,
        DnsRecordType recordType,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Upstream selection strategy for multi-resolver pools.
/// </summary>
public enum PoolSelectionStrategy
{
    None = 0,
    Fastest = 1,
    Parallel = 2,
    Failover = 3,
    LoadBalance = 4
}

/// <summary>
/// Per-query telemetry event emitted by the resolution pipeline for diagnostics and live UI inspection.
/// </summary>
public sealed record DnsQueryTelemetryEvent(
    DateTimeOffset TimestampUtc,
    string Domain,
    DnsRecordType RecordType,
    RouteZone Zone,
    string UpstreamName,
    DnsProtocol Protocol,
    double LatencyMs,
    bool CacheHit,
    bool RewrittenSvcb,
    DnsResponseCode ResponseCode,
    string DecisionNote);

/// <summary>
/// Point-in-time snapshot of host networking posture, Port 53 conflicts, SMHNR state, and browser DoH bypasses.
/// </summary>
public sealed record HostNetworkHealthSnapshot
{
    public DateTimeOffset CapturedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public IReadOnlyList<string> ActiveInterfaceNames { get; init; } = [];

    public bool HasIpv4Connectivity { get; init; }

    public bool HasIpv6Connectivity { get; init; }

    public bool IsCaptivePortalDetected { get; init; }

    public string? Port53OccupantName { get; init; }

    public int? Port53OccupantProcessId { get; init; }

    public bool IsSmhnrDisabled { get; init; }

    public IReadOnlyList<string> DetectedBrowserDohBypassBrowsers { get; init; } = [];
}

/// <summary>
/// Platform-abstracted inspector producing <see cref="HostNetworkHealthSnapshot"/> diagnostics.
/// </summary>
public interface IHostNetworkHealthProvider
{
    Task<HostNetworkHealthSnapshot> InspectAsync(CancellationToken cancellationToken = default);
}
