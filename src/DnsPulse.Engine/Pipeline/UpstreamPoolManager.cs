using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Pipeline;

/// <summary>
/// Immutable snapshot of tracked EWMA latency and health state for an upstream server.
/// </summary>
public sealed record UpstreamHealthSnapshot(
    string ServerId,
    double EwmaRttMs,
    int ConsecutiveFailures,
    long TotalSuccesses,
    long TotalFailures,
    bool IsHealthy,
    DateTimeOffset? LastSuccessUtc,
    DateTimeOffset? LastFailureUtc);

/// <summary>
/// Result of executing a query across an upstream pool under a <see cref="PoolSelectionStrategy"/>.
/// </summary>
public sealed record PoolExecutionResult(
    UpstreamQueryResult? QueryResult,
    DnsServerEntry? ServerUsed,
    bool Succeeded,
    string Note);

/// <summary>
/// Manages upstream server pools, EWMA RTT tracking, failure cooldowns, and strategy-based query dispatch.
/// Enforces the hard security invariant that Zone 4 default internet pools reject any server failing
/// <see cref="TrustTierPolicy.CanServeDefaultInternet"/>.
/// </summary>
public sealed class UpstreamPoolManager
{
    private readonly double _ewmaAlpha;
    private readonly int _failureThreshold;
    private readonly TimeSpan _unhealthyCooldown;
    private readonly TimeProvider _timeProvider;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, HealthState> _healthStates = new(StringComparer.OrdinalIgnoreCase);

    private List<DnsServerEntry> _zone4Servers = [];
    private List<DnsServerEntry> _rejectedZone4Servers = [];
    private int _roundRobinCounter;

    public UpstreamPoolManager(
        IEnumerable<DnsServerEntry>? zone4Servers = null,
        double ewmaAlpha = 0.25,
        int failureThreshold = 3,
        TimeSpan? unhealthyCooldown = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ewmaAlpha, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ewmaAlpha, 1.0);
        ArgumentOutOfRangeException.ThrowIfLessThan(failureThreshold, 1);

        _ewmaAlpha = ewmaAlpha;
        _failureThreshold = failureThreshold;
        _unhealthyCooldown = unhealthyCooldown ?? TimeSpan.FromSeconds(30);
        ArgumentOutOfRangeException.ThrowIfLessThan(_unhealthyCooldown, TimeSpan.Zero, nameof(unhealthyCooldown));

        _timeProvider = timeProvider ?? TimeProvider.System;

        if (zone4Servers is not null)
        {
            UpdateZone4Pool(zone4Servers);
        }
    }

    public IReadOnlyList<DnsServerEntry> Zone4Servers
    {
        get
        {
            lock (_gate)
            {
                return [.. _zone4Servers];
            }
        }
    }

    public IReadOnlyList<DnsServerEntry> RejectedZone4Servers
    {
        get
        {
            lock (_gate)
            {
                return [.. _rejectedZone4Servers];
            }
        }
    }

    /// <summary>
    /// Replaces the Zone 4 default internet pool, strictly filtering out any entry that violates
    /// <see cref="TrustTierPolicy.CanServeDefaultInternet"/>.
    /// </summary>
    public void UpdateZone4Pool(IEnumerable<DnsServerEntry> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);

        List<DnsServerEntry> accepted = [];
        List<DnsServerEntry> rejected = [];

        foreach (DnsServerEntry entry in servers)
        {
            if (entry is null)
            {
                continue;
            }

            if (TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
            {
                accepted.Add(entry);
            }
            else
            {
                rejected.Add(entry);
            }
        }

        lock (_gate)
        {
            _zone4Servers = accepted;
            _rejectedZone4Servers = rejected;
            foreach (DnsServerEntry entry in accepted)
            {
                EnsureHealthStateLocked(entry);
            }
        }
    }

    /// <summary>
    /// Adds a single server to the Zone 4 default internet pool, throwing <see cref="ArgumentException"/>
    /// if the entry violates <see cref="TrustTierPolicy.CanServeDefaultInternet"/>.
    /// </summary>
    public void AddZone4Server(DnsServerEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (!TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
        {
            throw new ArgumentException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Server '{entry.Name}' ({entry.TrustTier}, {entry.Protocol}) is not eligible for Zone 4 default internet resolution."),
                nameof(entry));
        }

        lock (_gate)
        {
            _zone4Servers.Add(entry);
            EnsureHealthStateLocked(entry);
        }
    }

    /// <summary>
    /// Attempts to add a single server to the Zone 4 pool, returning <see langword="false"/> if ineligible.
    /// </summary>
    public bool TryAddZone4Server(DnsServerEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (!TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
        {
            lock (_gate)
            {
                _rejectedZone4Servers.Add(entry);
            }

            return false;
        }

        lock (_gate)
        {
            _zone4Servers.Add(entry);
            EnsureHealthStateLocked(entry);
        }

        return true;
    }

    /// <summary>
    /// Records a successful query latency sample and updates the server's EWMA RTT.
    /// </summary>
    public void RecordSuccess(DnsServerEntry server, double rttMs)
    {
        ArgumentNullException.ThrowIfNull(server);
        double clampedRtt = Math.Max(0.01, rttMs);
        DateTimeOffset now = _timeProvider.GetUtcNow();

        lock (_gate)
        {
            HealthState state = EnsureHealthStateLocked(server);
            state.EwmaRttMs = state.HasSample
                ? (_ewmaAlpha * clampedRtt) + ((1.0 - _ewmaAlpha) * state.EwmaRttMs)
                : clampedRtt;
            state.HasSample = true;
            state.ConsecutiveFailures = 0;
            state.TotalSuccesses++;
            state.LastSuccessUtc = now;
        }
    }

    /// <summary>
    /// Records a failed or poisoned upstream attempt for <paramref name="server"/>.
    /// </summary>
    public void RecordFailure(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);
        DateTimeOffset now = _timeProvider.GetUtcNow();

        lock (_gate)
        {
            HealthState state = EnsureHealthStateLocked(server);
            state.ConsecutiveFailures++;
            state.TotalFailures++;
            state.LastFailureUtc = now;
        }
    }

    /// <summary>
    /// Returns the current health snapshot for a server if tracked.
    /// </summary>
    public UpstreamHealthSnapshot? GetHealthSnapshot(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);

        string key = GetServerKey(server);
        DateTimeOffset now = _timeProvider.GetUtcNow();

        lock (_gate)
        {
            if (!_healthStates.TryGetValue(key, out HealthState? state))
            {
                return null;
            }

            return ToSnapshot(key, state, now);
        }
    }

    /// <summary>
    /// Returns snapshots for all tracked upstreams.
    /// </summary>
    public IReadOnlyList<UpstreamHealthSnapshot> GetAllHealthSnapshots()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        lock (_gate)
        {
            List<UpstreamHealthSnapshot> result = new(_healthStates.Count);
            foreach (KeyValuePair<string, HealthState> pair in _healthStates)
            {
                result.Add(ToSnapshot(pair.Key, pair.Value, now));
            }

            return result;
        }
    }

    /// <summary>
    /// Orders candidate upstreams according to health and <paramref name="strategy"/>.
    /// </summary>
    public IReadOnlyList<DnsServerEntry> SelectCandidates(
        IReadOnlyList<DnsServerEntry> pool,
        PoolSelectionStrategy strategy,
        bool enforceZone4TrustTier = false)
    {
        ArgumentNullException.ThrowIfNull(pool);

        List<DnsServerEntry> eligible = new(pool.Count);
        foreach (DnsServerEntry entry in pool)
        {
            if (entry is null)
            {
                continue;
            }

            if (enforceZone4TrustTier && !TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
            {
                continue;
            }

            eligible.Add(entry);
        }

        if (eligible.Count <= 1)
        {
            return eligible;
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        List<DnsServerEntry> healthy = new(eligible.Count);
        List<DnsServerEntry> degraded = [];

        lock (_gate)
        {
            foreach (DnsServerEntry entry in eligible)
            {
                HealthState state = EnsureHealthStateLocked(entry);
                if (IsHealthyLocked(state, now))
                {
                    healthy.Add(entry);
                }
                else
                {
                    degraded.Add(entry);
                }
            }

            List<DnsServerEntry> orderedHealthy = OrderSubsetLocked(healthy, strategy);
            List<DnsServerEntry> orderedDegraded = OrderSubsetLocked(degraded, strategy);

            if (orderedDegraded.Count == 0)
            {
                return orderedHealthy;
            }

            orderedHealthy.AddRange(orderedDegraded);
            return orderedHealthy;
        }
    }

    /// <summary>
    /// Executes a DNS query against the Zone 4 default pool using the specified strategy,
    /// strictly enforcing <see cref="TrustTierPolicy.CanServeDefaultInternet"/>.
    /// </summary>
    public Task<PoolExecutionResult> QueryZone4Async(
        PoolSelectionStrategy strategy,
        Func<DnsServerEntry, CancellationToken, Task<UpstreamQueryResult>> executor,
        Func<UpstreamQueryResult, DnsServerEntry, bool>? responseValidator = null,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<DnsServerEntry> poolSnapshot = Zone4Servers;
        return QueryPoolAsync(
            poolSnapshot,
            strategy,
            executor,
            responseValidator,
            enforceZone4TrustTier: true,
            cancellationToken);
    }

    /// <summary>
    /// Executes a DNS query against <paramref name="pool"/> under <paramref name="strategy"/>.
    /// For <see cref="PoolSelectionStrategy.Parallel"/>, races the top 2 candidates and selects the first valid non-poisoned answer.
    /// </summary>
    public async Task<PoolExecutionResult> QueryPoolAsync(
        IReadOnlyList<DnsServerEntry> pool,
        PoolSelectionStrategy strategy,
        Func<DnsServerEntry, CancellationToken, Task<UpstreamQueryResult>> executor,
        Func<UpstreamQueryResult, DnsServerEntry, bool>? responseValidator = null,
        bool enforceZone4TrustTier = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(executor);

        IReadOnlyList<DnsServerEntry> candidates = SelectCandidates(pool, strategy, enforceZone4TrustTier);
        if (candidates.Count == 0)
        {
            return new PoolExecutionResult(null, null, false, "NoEligibleUpstreams");
        }

        if (strategy == PoolSelectionStrategy.Parallel && candidates.Count >= 2)
        {
            PoolExecutionResult parallelResult = await ExecuteParallelTopTwoAsync(
                candidates[0],
                candidates[1],
                executor,
                responseValidator,
                cancellationToken).ConfigureAwait(false);

            if (parallelResult.Succeeded)
            {
                return parallelResult;
            }

            for (int index = 2; index < candidates.Count; index++)
            {
                PoolExecutionResult fallback = await ExecuteSingleCandidateAsync(
                    candidates[index],
                    executor,
                    responseValidator,
                    cancellationToken).ConfigureAwait(false);

                if (fallback.Succeeded)
                {
                    return fallback;
                }
            }

            return parallelResult;
        }

        PoolExecutionResult? lastFailure = null;
        foreach (DnsServerEntry candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            PoolExecutionResult attempt = await ExecuteSingleCandidateAsync(
                candidate,
                executor,
                responseValidator,
                cancellationToken).ConfigureAwait(false);

            if (attempt.Succeeded)
            {
                return attempt;
            }

            lastFailure = attempt;
        }

        return lastFailure ?? new PoolExecutionResult(null, null, false, "AllUpstreamsFailed");
    }

    private async Task<PoolExecutionResult> ExecuteParallelTopTwoAsync(
        DnsServerEntry primary,
        DnsServerEntry secondary,
        Func<DnsServerEntry, CancellationToken, Task<UpstreamQueryResult>> executor,
        Func<UpstreamQueryResult, DnsServerEntry, bool>? responseValidator,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource raceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Task<(DnsServerEntry Server, PoolExecutionResult Outcome)> task0 = RunRaceArmAsync(
            primary,
            executor,
            responseValidator,
            raceCts.Token);

        Task<(DnsServerEntry Server, PoolExecutionResult Outcome)> task1 = RunRaceArmAsync(
            secondary,
            executor,
            responseValidator,
            raceCts.Token);

        List<Task<(DnsServerEntry Server, PoolExecutionResult Outcome)>> pending = [task0, task1];
        PoolExecutionResult? lastFailure = null;

        while (pending.Count > 0)
        {
            Task<(DnsServerEntry Server, PoolExecutionResult Outcome)> completed =
                await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(completed);

            (DnsServerEntry _, PoolExecutionResult outcome) = await completed.ConfigureAwait(false);
            if (outcome.Succeeded)
            {
                await raceCts.CancelAsync().ConfigureAwait(false);
                ObservePendingTasks(pending);
                return outcome;
            }

            lastFailure = outcome;
        }

        return lastFailure ?? new PoolExecutionResult(null, null, false, "ParallelRaceFailed");
    }

    private async Task<(DnsServerEntry Server, PoolExecutionResult Outcome)> RunRaceArmAsync(
        DnsServerEntry server,
        Func<DnsServerEntry, CancellationToken, Task<UpstreamQueryResult>> executor,
        Func<UpstreamQueryResult, DnsServerEntry, bool>? responseValidator,
        CancellationToken cancellationToken)
    {
        PoolExecutionResult outcome = await ExecuteSingleCandidateAsync(
            server,
            executor,
            responseValidator,
            cancellationToken).ConfigureAwait(false);

        return (server, outcome);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Upstream transport failures must record health degradation and allow pool failover.")]
    private async Task<PoolExecutionResult> ExecuteSingleCandidateAsync(
        DnsServerEntry server,
        Func<DnsServerEntry, CancellationToken, Task<UpstreamQueryResult>> executor,
        Func<UpstreamQueryResult, DnsServerEntry, bool>? responseValidator,
        CancellationToken cancellationToken)
    {
        try
        {
            UpstreamQueryResult result = await executor(server, cancellationToken).ConfigureAwait(false);
            if (result is null || result.Response is null)
            {
                RecordFailure(server);
                return new PoolExecutionResult(null, server, false, "NullUpstreamResponse");
            }

            DnsResponseCode rcode = result.Response.EffectiveResponseCode;
            if (rcode is DnsResponseCode.ServFail or DnsResponseCode.Refused or DnsResponseCode.FormErr or DnsResponseCode.NotImp)
            {
                RecordFailure(server);
                return new PoolExecutionResult(result, server, false, string.Create(CultureInfo.InvariantCulture, $"UpstreamRcode:{rcode}"));
            }

            if (responseValidator is not null && !responseValidator(result, server))
            {
                RecordFailure(server);
                return new PoolExecutionResult(result, server, false, "RejectedByValidator");
            }

            RecordSuccess(server, result.Latency.TotalMilliseconds);
            return new PoolExecutionResult(result, server, true, "Resolved");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new PoolExecutionResult(null, server, false, "Canceled");
        }
        catch (Exception ex)
        {
            RecordFailure(server);
            return new PoolExecutionResult(null, server, false, string.Create(CultureInfo.InvariantCulture, $"Exception:{ex.GetType().Name}"));
        }
    }

    private static void ObservePendingTasks(List<Task<(DnsServerEntry Server, PoolExecutionResult Outcome)>> pending)
    {
        foreach (Task<(DnsServerEntry Server, PoolExecutionResult Outcome)> task in pending)
        {
            _ = task.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private List<DnsServerEntry> OrderSubsetLocked(List<DnsServerEntry> subset, PoolSelectionStrategy strategy)
    {
        if (subset.Count <= 1)
        {
            return subset;
        }

        switch (strategy)
        {
            case PoolSelectionStrategy.Fastest:
            case PoolSelectionStrategy.Parallel:
                subset.Sort((left, right) =>
                {
                    double leftRtt = _healthStates[GetServerKey(left)].EwmaRttMs;
                    double rightRtt = _healthStates[GetServerKey(right)].EwmaRttMs;
                    return leftRtt.CompareTo(rightRtt);
                });
                return subset;

            case PoolSelectionStrategy.LoadBalance:
                uint index = (uint)(Interlocked.Increment(ref _roundRobinCounter) - 1);
                int start = (int)(index % (uint)subset.Count);
                if (start == 0)
                {
                    return subset;
                }

                List<DnsServerEntry> rotated = new(subset.Count);
                for (int i = 0; i < subset.Count; i++)
                {
                    rotated.Add(subset[(start + i) % subset.Count]);
                }

                return rotated;

            case PoolSelectionStrategy.Failover:
            case PoolSelectionStrategy.None:
            default:
                return subset;
        }
    }

    private HealthState EnsureHealthStateLocked(DnsServerEntry server)
    {
        string key = GetServerKey(server);
        if (!_healthStates.TryGetValue(key, out HealthState? state))
        {
            double initialRtt = server.LastLatencyMs ?? server.LatencyP50Ms ?? 50.0;
            state = new HealthState(Math.Max(0.01, initialRtt));
            _healthStates[key] = state;
        }

        return state;
    }

    private bool IsHealthyLocked(HealthState state, DateTimeOffset nowUtc)
    {
        if (state.ConsecutiveFailures < _failureThreshold)
        {
            return true;
        }

        if (!state.LastFailureUtc.HasValue)
        {
            return true;
        }

        return nowUtc - state.LastFailureUtc.Value >= _unhealthyCooldown;
    }

    private UpstreamHealthSnapshot ToSnapshot(string serverId, HealthState state, DateTimeOffset nowUtc)
    {
        return new UpstreamHealthSnapshot(
            serverId,
            state.EwmaRttMs,
            state.ConsecutiveFailures,
            state.TotalSuccesses,
            state.TotalFailures,
            IsHealthyLocked(state, nowUtc),
            state.LastSuccessUtc,
            state.LastFailureUtc);
    }

    private static string GetServerKey(DnsServerEntry server)
    {
        return !string.IsNullOrWhiteSpace(server.Id) ? server.Id : server.EndpointLabel;
    }

    private sealed class HealthState(double initialRttMs)
    {
        public double EwmaRttMs { get; set; } = initialRttMs;

        public bool HasSample { get; set; }

        public int ConsecutiveFailures { get; set; }

        public long TotalSuccesses { get; set; }

        public long TotalFailures { get; set; }

        public DateTimeOffset? LastSuccessUtc { get; set; }

        public DateTimeOffset? LastFailureUtc { get; set; }
    }
}
