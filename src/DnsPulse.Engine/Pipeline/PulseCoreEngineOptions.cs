using DnsPulse.Core.Models;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Pipeline;

/// <summary>
/// Response mode applied to domains blocked in Zone 2 (<see cref="Core.Routing.RouteZone.Zone2BlockOrProtect"/>).
/// </summary>
public enum BlockResponseMode
{
    NxDomain = 0,
    NullIp = 1
}

/// <summary>
/// Runtime configuration for <see cref="PulseCoreDnsEngine"/> upstream pools, routing strategies, and security policy.
/// </summary>
public sealed record PulseCoreEngineOptions
{
    public IReadOnlyList<DnsServerEntry> LocalBypassUpstreams { get; init; } = [];

    public IReadOnlyList<DnsServerEntry> GeoUnlockUpstreams { get; init; } = [];

    public PoolSelectionStrategy Zone1Strategy { get; init; } = PoolSelectionStrategy.Failover;

    public PoolSelectionStrategy Zone3Strategy { get; init; } = PoolSelectionStrategy.Failover;

    public PoolSelectionStrategy Zone4Strategy { get; init; } = PoolSelectionStrategy.Fastest;

    public BlockResponseMode BlockMode { get; init; } = BlockResponseMode.NxDomain;

    public uint BlockNullIpTtlSeconds { get; init; } = 60;

    public uint SniProxySyntheticTtlSeconds { get; init; } = 45;

    /// <summary>Gets whether Zone 3 Geo-Unlock enforces IPv4-only routing (synthesizing empty NOERROR for AAAA and stripping IPv6/H3 hints from HTTPS/SVCB).</summary>
    public bool GeoUnlockIpv4Only { get; init; } = true;

    /// <summary>Gets whether Zone 3 Geo-Unlock immediately strips HTTPS (65) and SVCB (64) queries to empty NOERROR NODATA even for Smart-DNS upstreams.</summary>
    public bool DropHttpsSvcbOnGeoUnlock { get; init; }

    /// <summary>Gets whether Zone 3 Smart-DNS may fall back to the last verified non-direct SmartProxy IPv4 learned in this session on transient upstream failure.</summary>
    public bool EnableLearnedSmartProxyFallback { get; init; } = true;

    public bool AllowCarrierAnycastExceptions { get; init; }

    public string? NamedCarrierEndpointId { get; init; }

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
