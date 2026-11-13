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

    public uint SniProxySyntheticTtlSeconds { get; init; } = 60;

    public bool AllowCarrierAnycastExceptions { get; init; }

    public string? NamedCarrierEndpointId { get; init; }

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
