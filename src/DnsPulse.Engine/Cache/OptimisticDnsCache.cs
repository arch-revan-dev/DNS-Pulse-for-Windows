using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using DnsPulse.Core.Wire;

namespace DnsPulse.Engine.Cache;

/// <summary>
/// RFC 8767-compliant thread-safe bounded LRU DNS cache with TTL clamping,
/// serve-stale grace window, and single-flight asynchronous background stale refresh.
/// </summary>
public sealed class OptimisticDnsCache : IDisposable
{
    private readonly OptimisticCacheOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly Lock _gate = new();
    private readonly Dictionary<DnsCacheKey, LinkedListNode<CacheEntry>> _entries;
    private readonly LinkedList<CacheEntry> _lruList = new();
    private readonly ConcurrentDictionary<DnsCacheKey, Task> _inFlightRefreshes = new();
    private readonly CancellationTokenSource _disposeCts = new();

    private long _totalHits;
    private long _staleHits;
    private long _totalMisses;
    private int _disposed;

    public OptimisticDnsCache(OptimisticCacheOptions? options = null)
    {
        _options = options ?? new OptimisticCacheOptions();

        ArgumentOutOfRangeException.ThrowIfLessThan(_options.MaxEntries, 1, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.MinTtl, TimeSpan.Zero, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.MaxTtl, _options.MinTtl, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.ServeStaleGrace, TimeSpan.Zero, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.NegativeCacheTtl, TimeSpan.Zero, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(_options.StaleRefreshTimeout, TimeSpan.Zero, nameof(options));
        ArgumentNullException.ThrowIfNull(_options.TimeProvider);

        _timeProvider = _options.TimeProvider;
        _entries = new Dictionary<DnsCacheKey, LinkedListNode<CacheEntry>>(_options.MaxEntries);
    }

    public long TotalHits => Volatile.Read(ref _totalHits);

    public long StaleHits => Volatile.Read(ref _staleHits);

    public long TotalMisses => Volatile.Read(ref _totalMisses);

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    public double HitRatePercent
    {
        get
        {
            long hits = Volatile.Read(ref _totalHits);
            long misses = Volatile.Read(ref _totalMisses);
            long total = hits + misses;
            return total == 0 ? 0.0 : (double)hits / total * 100.0;
        }
    }

    /// <summary>
    /// Attempts to read an entry from cache without triggering a background refresh.
    /// </summary>
    public bool TryGet(in DnsCacheKey key, out CacheLookupResult result)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        DateTimeOffset now = _timeProvider.GetUtcNow();
        CacheEntry? matchedEntry = null;
        bool isFresh = false;

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out LinkedListNode<CacheEntry>? node))
            {
                CacheEntry entry = node.Value;
                if (now < entry.FreshUntilUtc)
                {
                    PromoteNodeLocked(node);
                    matchedEntry = entry;
                    isFresh = true;
                }
                else if (now <= entry.StaleUntilUtc)
                {
                    PromoteNodeLocked(node);
                    matchedEntry = entry;
                    isFresh = false;
                }
                else
                {
                    RemoveNodeLocked(key, node);
                }
            }
        }

        if (matchedEntry is null)
        {
            Interlocked.Increment(ref _totalMisses);
            result = new CacheLookupResult(CacheLookupStatus.Miss, null, false);
            return false;
        }

        if (isFresh)
        {
            Interlocked.Increment(ref _totalHits);
            uint remainingSeconds = ComputeRemainingTtlSeconds(matchedEntry.FreshUntilUtc, now);
            result = new CacheLookupResult(
                CacheLookupStatus.FreshHit,
                CloneWithAdjustedTtl(matchedEntry.Response, remainingSeconds),
                false);
            return true;
        }

        Interlocked.Increment(ref _totalHits);
        Interlocked.Increment(ref _staleHits);
        result = new CacheLookupResult(
            CacheLookupStatus.StaleHit,
            CloneWithAdjustedTtl(matchedEntry.Response, _options.StaleResponseTtlSeconds),
            false);
        return true;
    }

    /// <summary>
    /// Attempts to read an entry from cache; if expired within <see cref="OptimisticCacheOptions.ServeStaleGrace"/>,
    /// serves the stale response immediately and triggers a single-flight background refresh deduplicated per key.
    /// </summary>
    public bool TryGetOrRefresh(
        in DnsCacheKey key,
        Func<CancellationToken, Task<DnsMessage>> refreshFactory,
        out CacheLookupResult result)
    {
        ArgumentNullException.ThrowIfNull(refreshFactory);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        DateTimeOffset now = _timeProvider.GetUtcNow();
        CacheEntry? matchedEntry = null;
        bool isFresh = false;

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out LinkedListNode<CacheEntry>? node))
            {
                CacheEntry entry = node.Value;
                if (now < entry.FreshUntilUtc)
                {
                    PromoteNodeLocked(node);
                    matchedEntry = entry;
                    isFresh = true;
                }
                else if (now <= entry.StaleUntilUtc)
                {
                    PromoteNodeLocked(node);
                    matchedEntry = entry;
                    isFresh = false;
                }
                else
                {
                    RemoveNodeLocked(key, node);
                }
            }
        }

        if (matchedEntry is null)
        {
            Interlocked.Increment(ref _totalMisses);
            result = new CacheLookupResult(CacheLookupStatus.Miss, null, false);
            return false;
        }

        if (isFresh)
        {
            Interlocked.Increment(ref _totalHits);
            uint remainingSeconds = ComputeRemainingTtlSeconds(matchedEntry.FreshUntilUtc, now);
            result = new CacheLookupResult(
                CacheLookupStatus.FreshHit,
                CloneWithAdjustedTtl(matchedEntry.Response, remainingSeconds),
                false);
            return true;
        }

        Interlocked.Increment(ref _totalHits);
        Interlocked.Increment(ref _staleHits);

        bool refreshTriggered = TryStartSingleFlightRefresh(key, refreshFactory);
        result = new CacheLookupResult(
            CacheLookupStatus.StaleHit,
            CloneWithAdjustedTtl(matchedEntry.Response, _options.StaleResponseTtlSeconds),
            refreshTriggered);
        return true;
    }

    /// <summary>
    /// Stores a cacheable DNS response according to RFC 8767 rules.
    /// Error responses (<c>SERVFAIL</c>, <c>REFUSED</c>, <c>FORMERR</c>, etc.) and explicit zero-TTL responses are not cached.
    /// </summary>
    /// <returns><see langword="true"/> if cached; <see langword="false"/> if uncacheable.</returns>
    public bool Set(in DnsCacheKey key, DnsMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (!TryComputeEffectiveTtl(response, out TimeSpan effectiveTtl))
        {
            return false;
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        DateTimeOffset freshUntil = now.Add(effectiveTtl);
        DateTimeOffset staleUntil = freshUntil.Add(_options.ServeStaleGrace);
        CacheEntry entry = new(key, response, now, freshUntil, staleUntil);

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out LinkedListNode<CacheEntry>? existingNode))
            {
                existingNode.Value = entry;
                PromoteNodeLocked(existingNode);
            }
            else
            {
                LinkedListNode<CacheEntry> newNode = new(entry);
                _lruList.AddFirst(newNode);
                _entries[key] = newNode;

                while (_entries.Count > _options.MaxEntries && _lruList.Last is { } lruNode)
                {
                    _lruList.RemoveLast();
                    _entries.Remove(lruNode.Value.Key);
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Removes a specific key from the cache.
    /// </summary>
    public bool Remove(in DnsCacheKey key)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out LinkedListNode<CacheEntry>? node))
            {
                RemoveNodeLocked(key, node);
                return true;
            }

            return false;
        }
    }

    /// <summary>
    /// Clears all entries from the cache without resetting atomic telemetry counters.
    /// </summary>
    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            _lruList.Clear();
        }
    }

    /// <summary>
    /// Returns true if an asynchronous stale refresh is currently active for <paramref name="key"/>.
    /// </summary>
    public bool IsRefreshInFlight(in DnsCacheKey key)
    {
        return _inFlightRefreshes.ContainsKey(key);
    }

    /// <summary>
    /// Awaits completion of all currently active background stale refresh tasks.
    /// </summary>
    public async Task WaitForPendingRefreshesAsync(CancellationToken cancellationToken = default)
    {
        Task[] tasks = [.. _inFlightRefreshes.Values];
        if (tasks.Length == 0)
        {
            return;
        }

        await Task.WhenAll(tasks).WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();
        _disposeCts.Dispose();
    }

    private bool TryStartSingleFlightRefresh(
        DnsCacheKey key,
        Func<CancellationToken, Task<DnsMessage>> refreshFactory)
    {
        if (Volatile.Read(ref _disposed) != 0 || _inFlightRefreshes.ContainsKey(key))
        {
            return false;
        }

        TaskCompletionSource tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_inFlightRefreshes.TryAdd(key, tcs.Task))
        {
            return false;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await ExecuteRefreshCoreAsync(key, refreshFactory).ConfigureAwait(false);
            }
            finally
            {
                _inFlightRefreshes.TryRemove(key, out _);
                tcs.TrySetResult();
            }
        });

        return true;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "RFC 8767 background stale refresh must isolate upstream exceptions so existing stale entries are preserved.")]
    private async Task ExecuteRefreshCoreAsync(
        DnsCacheKey key,
        Func<CancellationToken, Task<DnsMessage>> refreshFactory)
    {
        try
        {
            using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_disposeCts.Token);
            timeoutCts.CancelAfter(_options.StaleRefreshTimeout);

            DnsMessage refreshed = await refreshFactory(timeoutCts.Token).ConfigureAwait(false);
            if (Volatile.Read(ref _disposed) == 0 && refreshed is not null)
            {
                Set(key, refreshed);
            }
        }
        catch (Exception)
        {
            // Keep existing stale entry untouched within ServeStaleGrace per RFC 8767 section 5.
        }
    }

    private bool TryComputeEffectiveTtl(DnsMessage response, out TimeSpan ttl)
    {
        ttl = TimeSpan.Zero;

        DnsResponseCode rcode = response.EffectiveResponseCode;
        if (rcode is not DnsResponseCode.NoError and not DnsResponseCode.NxDomain)
        {
            return false;
        }

        if (response.IsTruncated)
        {
            return false;
        }

        if (response.Answers.Count > 0)
        {
            uint minSeconds = uint.MaxValue;
            foreach (DnsResourceRecord record in response.Answers)
            {
                if (record.RecordType == DnsRecordType.OPT)
                {
                    continue;
                }

                if (record.TimeToLive < minSeconds)
                {
                    minSeconds = record.TimeToLive;
                }
            }

            if (minSeconds == uint.MaxValue || minSeconds == 0)
            {
                return false;
            }

            ttl = ClampTtl(TimeSpan.FromSeconds(minSeconds));
            return ttl > TimeSpan.Zero;
        }

        // Negative / NODATA response (RFC 2308 & RFC 8767).
        uint? soaTtl = null;
        foreach (DnsResourceRecord authority in response.Authorities)
        {
            if (authority.RecordType == DnsRecordType.SOA)
            {
                uint candidate = Math.Min(authority.TimeToLive, authority.SoaMinimum);
                soaTtl = soaTtl.HasValue ? Math.Min(soaTtl.Value, candidate) : candidate;
            }
        }

        if (soaTtl.HasValue)
        {
            if (soaTtl.Value == 0)
            {
                return false;
            }

            ttl = ClampTtl(TimeSpan.FromSeconds(soaTtl.Value));
            return ttl > TimeSpan.Zero;
        }

        if (_options.NegativeCacheTtl == TimeSpan.Zero)
        {
            return false;
        }

        ttl = ClampTtl(_options.NegativeCacheTtl);
        return ttl > TimeSpan.Zero;
    }

    private TimeSpan ClampTtl(TimeSpan rawTtl)
    {
        if (rawTtl < _options.MinTtl)
        {
            return _options.MinTtl;
        }

        if (rawTtl > _options.MaxTtl)
        {
            return _options.MaxTtl;
        }

        return rawTtl;
    }

    private static uint ComputeRemainingTtlSeconds(DateTimeOffset freshUntilUtc, DateTimeOffset nowUtc)
    {
        double remaining = Math.Floor((freshUntilUtc - nowUtc).TotalSeconds);
        if (remaining < 1.0)
        {
            return 1u;
        }

        if (remaining >= uint.MaxValue)
        {
            return uint.MaxValue;
        }

        return (uint)remaining;
    }

    private static DnsMessage CloneWithAdjustedTtl(DnsMessage source, uint newTtl)
    {
        List<DnsResourceRecord> answers = AdjustSectionTtl(source.Answers, newTtl);
        List<DnsResourceRecord> authorities = AdjustSectionTtl(source.Authorities, newTtl);
        List<DnsResourceRecord> additionals = AdjustSectionTtl(source.Additionals, newTtl);

        return source with
        {
            Answers = answers,
            Authorities = authorities,
            Additionals = additionals
        };
    }

    private static List<DnsResourceRecord> AdjustSectionTtl(IReadOnlyList<DnsResourceRecord> section, uint newTtl)
    {
        if (section.Count == 0)
        {
            return [];
        }

        List<DnsResourceRecord> result = new(section.Count);
        foreach (DnsResourceRecord record in section)
        {
            if (record.RecordType == DnsRecordType.OPT)
            {
                result.Add(record);
                continue;
            }

            uint adjusted = Math.Min(record.TimeToLive, newTtl);
            result.Add(record with { TimeToLive = adjusted });
        }

        return result;
    }

    private void PromoteNodeLocked(LinkedListNode<CacheEntry> node)
    {
        if (!ReferenceEquals(_lruList.First, node))
        {
            _lruList.Remove(node);
            _lruList.AddFirst(node);
        }
    }

    private void RemoveNodeLocked(in DnsCacheKey key, LinkedListNode<CacheEntry> node)
    {
        _lruList.Remove(node);
        _entries.Remove(key);
    }

    private sealed record CacheEntry(
        DnsCacheKey Key,
        DnsMessage Response,
        DateTimeOffset CachedAtUtc,
        DateTimeOffset FreshUntilUtc,
        DateTimeOffset StaleUntilUtc);
}
