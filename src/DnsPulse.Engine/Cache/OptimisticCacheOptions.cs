namespace DnsPulse.Engine.Cache;

/// <summary>
/// Configuration options governing <see cref="OptimisticDnsCache"/> TTL clamping, LRU capacity, and RFC 8767 serve-stale grace.
/// </summary>
public sealed record OptimisticCacheOptions
{
    public int MaxEntries { get; init; } = 10_000;

    public TimeSpan MinTtl { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan MaxTtl { get; init; } = TimeSpan.FromHours(24);

    public TimeSpan ServeStaleGrace { get; init; } = TimeSpan.FromHours(24);

    public TimeSpan NegativeCacheTtl { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan StaleRefreshTimeout { get; init; } = TimeSpan.FromSeconds(10);

    public uint StaleResponseTtlSeconds { get; init; } = 30;

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
