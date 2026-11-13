using DnsPulse.Core.Wire;

namespace DnsPulse.Engine.Cache;

/// <summary>
/// Outcome of an optimistic cache lookup.
/// </summary>
public enum CacheLookupStatus
{
    Miss = 0,
    FreshHit = 1,
    StaleHit = 2
}

/// <summary>
/// Result returned by <see cref="OptimisticDnsCache"/> lookups.
/// </summary>
/// <param name="Status">Whether the entry was a fresh hit, stale hit, or miss.</param>
/// <param name="Message">Cached DNS response with remaining TTL adjusted, or <see langword="null"/> on miss.</param>
/// <param name="RefreshTriggered">True when a stale hit initiated a new background single-flight refresh.</param>
public sealed record CacheLookupResult(
    CacheLookupStatus Status,
    DnsMessage? Message,
    bool RefreshTriggered = false);
