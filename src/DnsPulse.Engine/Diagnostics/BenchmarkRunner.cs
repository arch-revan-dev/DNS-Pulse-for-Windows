using System.Runtime.CompilerServices;
using System.Threading.Channels;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Diagnostics;

/// <summary>
/// Configuration options for concurrent section or pool benchmarking via <see cref="BenchmarkRunner"/>.
/// </summary>
public sealed record BenchmarkOptions
{
    public int MaxConcurrency { get; init; } = 6;

    public int SamplesPerServer { get; init; } = 3;

    public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromMilliseconds(2600);

    public bool RunFullSixLayerDiagnostics { get; init; }

    public DiagnosticProbeOptions? DiagnosticOptions { get; init; }
}

/// <summary>
/// Progress update yielded by <see cref="BenchmarkRunner"/> as each server benchmark completes.
/// </summary>
public sealed record BenchmarkProgressUpdate(
    int Index,
    int CompletedCount,
    int TotalCount,
    DnsServerEntry UpdatedServer,
    DiagnosticReport Report);

/// <summary>
/// Concurrent, cancellable resolver pool benchmark runner producing p50/p95 RTT, jitter, and verdict updates.
/// </summary>
public sealed class BenchmarkRunner
{
    private const int MaxHistoryLength = 20;

    private readonly SixLayerDiagnosticEngine _diagnosticEngine;

    public BenchmarkRunner(SixLayerDiagnosticEngine diagnosticEngine)
    {
        ArgumentNullException.ThrowIfNull(diagnosticEngine);
        _diagnosticEngine = diagnosticEngine;
    }

    public BenchmarkRunner(
        IBootstrapResolver bootstrapResolver,
        Func<DnsProtocol, IDnsUpstreamClient> clientFactory,
        IHostNetworkHealthProvider? hostHealthProvider = null)
    {
        _diagnosticEngine = new SixLayerDiagnosticEngine(bootstrapResolver, clientFactory, hostHealthProvider);
    }

    /// <summary>
    /// Streams benchmark progress updates as each server completes, bounded by <see cref="BenchmarkOptions.MaxConcurrency"/>.
    /// </summary>
    public async IAsyncEnumerable<BenchmarkProgressUpdate> StreamAsync(
        IReadOnlyList<DnsServerEntry> servers,
        string targetDomain,
        BenchmarkOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDomain);

        if (servers.Count == 0)
        {
            yield break;
        }

        BenchmarkOptions effectiveOptions = options ?? new BenchmarkOptions();
        int maxConcurrency = Math.Clamp(effectiveOptions.MaxConcurrency, 1, 16);

        DiagnosticProbeOptions probeOptions = effectiveOptions.DiagnosticOptions is not null
            ? effectiveOptions.DiagnosticOptions with
            {
                TransportProbeSamples = Math.Clamp(effectiveOptions.SamplesPerServer, 1, 16),
                ProbeTimeout = effectiveOptions.ProbeTimeout,
                IncludeTlsAndApplicationProbes = effectiveOptions.RunFullSixLayerDiagnostics
            }
            : new DiagnosticProbeOptions
            {
                TransportProbeSamples = Math.Clamp(effectiveOptions.SamplesPerServer, 1, 16),
                ProbeTimeout = effectiveOptions.ProbeTimeout,
                IncludeTlsAndApplicationProbes = effectiveOptions.RunFullSixLayerDiagnostics
            };

        Channel<BenchmarkProgressUpdate> channel = Channel.CreateUnbounded<BenchmarkProgressUpdate>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });

        int completedCounter = 0;

        Task producerTask = Task.Run(
            async () =>
            {
                using SemaphoreSlim gate = new(maxConcurrency, maxConcurrency);
                try
                {
                    Task[] workerTasks = new Task[servers.Count];
                    for (int i = 0; i < servers.Count; i++)
                    {
                        int serverIndex = i;
                        DnsServerEntry server = servers[i];
                        workerTasks[i] = BenchmarkSingleAsync(
                            serverIndex,
                            server,
                            servers.Count,
                            targetDomain,
                            probeOptions,
                            gate,
                            channel.Writer,
                            () => Interlocked.Increment(ref completedCounter),
                            cancellationToken);
                    }

                    await Task.WhenAll(workerTasks).ConfigureAwait(false);
                    channel.Writer.TryComplete();
                }
                catch (OperationCanceledException ex)
                {
                    channel.Writer.TryComplete(ex);
                }
                catch (InvalidOperationException ex)
                {
                    channel.Writer.TryComplete(ex);
                }
                catch (ArgumentException ex)
                {
                    channel.Writer.TryComplete(ex);
                }
            },
            cancellationToken);

        await foreach (BenchmarkProgressUpdate update in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return update;
        }

        await producerTask.ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the benchmark for all <paramref name="servers"/> concurrently and returns the updated entries in input order.
    /// </summary>
    public async Task<IReadOnlyList<DnsServerEntry>> RunAsync(
        IReadOnlyList<DnsServerEntry> servers,
        string targetDomain,
        BenchmarkOptions? options = null,
        IProgress<BenchmarkProgressUpdate>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDomain);

        if (servers.Count == 0)
        {
            return [];
        }

        DnsServerEntry[] results = new DnsServerEntry[servers.Count];

        await foreach (BenchmarkProgressUpdate update in StreamAsync(servers, targetDomain, options, cancellationToken).ConfigureAwait(false))
        {
            results[update.Index] = update.UpdatedServer;
            progress?.Report(update);
        }

        return results;
    }

    private async Task BenchmarkSingleAsync(
        int index,
        DnsServerEntry server,
        int totalCount,
        string targetDomain,
        DiagnosticProbeOptions probeOptions,
        SemaphoreSlim gate,
        ChannelWriter<BenchmarkProgressUpdate> writer,
        Func<int> incrementCompleted,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DiagnosticReport report = await _diagnosticEngine.DiagnoseAsync(
                targetDomain,
                server,
                probeOptions,
                cancellationToken).ConfigureAwait(false);

            DnsServerEntry updated = ApplyReportToServer(server, report);
            int completed = incrementCompleted();
            await writer.WriteAsync(
                new BenchmarkProgressUpdate(index, completed, totalCount, updated, report),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static DnsServerEntry ApplyReportToServer(DnsServerEntry server, DiagnosticReport report)
    {
        int successRate = (int)Math.Round(Math.Clamp(100.0 - report.PacketLossPercent, 0.0, 100.0), MidpointRounding.AwayFromZero);

        List<int> updatedHistory = [.. server.HistoryMs];
        if (report.LatencyP50Ms is double p50)
        {
            updatedHistory.Add((int)Math.Round(p50, MidpointRounding.AwayFromZero));
            if (updatedHistory.Count > MaxHistoryLength)
            {
                updatedHistory.RemoveRange(0, updatedHistory.Count - MaxHistoryLength);
            }
        }

        double? minLatency = server.MinLatencyMs;
        if (report.LatencyP50Ms is double currentLatency)
        {
            minLatency = minLatency.HasValue
                ? Math.Min(minLatency.Value, currentLatency)
                : currentLatency;
        }

        double? avgLatency = updatedHistory.Count > 0
            ? updatedHistory.Average()
            : server.AvgLatencyMs;

        string[] resolvedStrings = new string[report.ResolvedAddresses.Count];
        for (int i = 0; i < report.ResolvedAddresses.Count; i++)
        {
            resolvedStrings[i] = report.ResolvedAddresses[i].ToString();
        }

        return server with
        {
            LastLatencyMs = report.LatencyP50Ms,
            MinLatencyMs = minLatency,
            AvgLatencyMs = avgLatency,
            LatencyP50Ms = report.LatencyP50Ms,
            LatencyP95Ms = report.LatencyP95Ms,
            JitterMs = report.JitterMs,
            SuccessRatePercent = successRate,
            Verdict = report.Verdict,
            VerdictReason = report.Reason,
            ResolvedIps = resolvedStrings,
            CompanionPassed = report.CompanionPassed,
            Port443Ok = report.TlsHandshakeSucceeded ? true : server.Port443Ok,
            HttpStatus = report.HttpStatusCode,
            LastCheckedDomain = report.TargetDomain,
            LastCheckedAt = report.StartedAtUtc,
            HistoryMs = updatedHistory
        };
    }
}
