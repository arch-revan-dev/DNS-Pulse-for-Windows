using System.Collections.Concurrent;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App.Services;

public sealed class SubnetScannerService
{
    private readonly FourStageProber _prober = new();

    public async Task<List<DnsServerEntry>> ScanAsync(
        string subnetOrAuto,
        string targetDomain,
        bool requiresBypass,
        bool scanUdp53,
        bool checkPort443,
        IProgress<double>? progress,
        CancellationToken ct)
    {
        var targets = ExpandTargets(subnetOrAuto);
        var found = new ConcurrentBag<DnsServerEntry>();
        using var gate = new SemaphoreSlim(24);
        int done = 0;

        var tasks = targets.Select(async ip =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var candidate = new DnsServerEntry
                {
                    Id = $"scan_{ip.Replace('.', '_')}",
                    Name = $"Узел {ip}",
                    Provider = "Сканер подсетей",
                    Protocol = scanUdp53 ? DnsProtocol.UDP : DnsProtocol.SNI443,
                    PrimaryIp = ip,
                    SmartProxyIp = checkPort443 ? ip : null,
                    Category = "Свои / Найденные",
                    SupportsBypass = checkPort443
                };

                var probe = await _prober.ProbeFourStagesAsync(candidate, targetDomain, requiresBypass, ct);
                if (probe.Verdict is BypassVerdict.VERIFIED_PROXY_OK or BypassVerdict.DIRECT_NO_PROXY)
                {
                    candidate.LastLatencyMs = probe.LatencyMs;
                    candidate.Verdict = probe.Verdict;
                    candidate.VerdictReason = probe.VerdictReason;
                    candidate.Port443Ok = probe.Port443Ok;
                    found.Add(candidate);
                }
            }
            catch
            {
                // Ignore unreachable hosts
            }
            finally
            {
                int current = Interlocked.Increment(ref done);
                progress?.Report((double)current / targets.Count);
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);
        return found.OrderBy(s => s.LastLatencyMs ?? double.MaxValue).ToList();
    }

    private static List<string> ExpandTargets(string input)
    {
        var clean = input.Trim();
        if (string.IsNullOrEmpty(clean) || clean.Equals("AUTO", StringComparison.OrdinalIgnoreCase))
        {
            return ["192.255.159.240", "192.255.159.241", "192.3.233.253", "107.175.76.134", "5.175.161.40", "179.254.166.171", "164.5.224.81", "83.220.169.155", "176.99.11.77"];
        }
        if (clean.EndsWith(".0/24", StringComparison.Ordinal))
        {
            var prefix = clean[..^5];
            return Enumerable.Range(1, 254).Select(i => $"{prefix}.{i}").ToList();
        }
        return [clean];
    }
}
