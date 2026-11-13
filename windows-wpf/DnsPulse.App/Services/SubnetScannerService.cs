using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App.Services;

public sealed partial class SubnetScannerService
{
    private static readonly string[] DefaultCuratedPrefixes =
    {
        "192.255.159",
        "192.3.233",
        "107.175.76",
        "5.175.161",
        "143.20.64",
        "37.221.93",
        "185.236.10",
        "82.47.171",
        "179.254.166",
        "83.220.169",
        "212.109.195",
        "111.88.96"
    };

    private static readonly int[] KnownClusterOctets =
    {
        2, 3, 5, 10, 21, 37, 40, 54, 93, 120, 134, 141, 155, 192, 240, 241, 252, 253
    };

    public async Task<List<DnsServerEntry>> ScanAsync(
        string subnetOrAuto,
        string targetDomain,
        bool requiresBypass,
        bool scanUdp53,
        bool checkPort443,
        IProgress<double>? progress,
        CancellationToken ct,
        IProgress<(int Done, int Total, int Found, string CurrentIp)>? detailedProgress = null)
    {
        var targets = BuildHunterCandidateIps(subnetOrAuto);
        var found = new ConcurrentBag<DnsServerEntry>();
        var prober = new FourStageProber();
        int done = 0;
        int foundCount = 0;
        int total = Math.Max(1, targets.Count);

        var checkDomain = string.IsNullOrWhiteSpace(targetDomain)
            ? "gemini.google.com"
            : targetDomain.Trim().TrimEnd('.').ToLowerInvariant();

        using var sem = new SemaphoreSlim(24);
        var tasks = targets.Select(async ip =>
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (ct.IsCancellationRequested) return;

                bool addedForThisIp = false;

                // 1. Probe UDP 53 Resolver / Smart-DNS
                if (scanUdp53)
                {
                    try
                    {
                        var (ips, lat) = await prober.QueryUdp53Async(ip, checkDomain, ct).ConfigureAwait(false);
                        if (ips.Count > 0)
                        {
                            bool isDirect = AntiDirectIpFilter.IsDirectServiceIp(ips[0], checkDomain);
                            if (!requiresBypass || !isDirect)
                            {
                                bool p443Ok = true;
                                int? httpCode = null;
                                if (requiresBypass || checkPort443)
                                {
                                    var sni = await prober.ProbeSniPort443DetailedAsync(ips[0], checkDomain, null, ct).ConfigureAwait(false);
                                    p443Ok = sni.Port443Ok && !sni.GeoBlockedBody && !AntiDirectIpFilter.IsGeoBlockedRedirect(sni.HttpStatus, sni.RedirectLocation);
                                    httpCode = sni.HttpStatus;
                                }

                                if (!requiresBypass || p443Ok)
                                {
                                    found.Add(new DnsServerEntry
                                    {
                                        Id = $"scan_udp_{ip.Replace('.', '_')}",
                                        Name = requiresBypass ? $"Найден Smart-DNS {ip}" : $"Найден DNS {ip}",
                                        Provider = "Сканер подсетей",
                                        Protocol = DnsProtocol.UDP,
                                        PrimaryIp = ip,
                                        Category = "Свои / Найденные",
                                        Country = "SCAN",
                                        Tags = new List<string> { "Scan", "UDP", requiresBypass ? "SmartDNS" : "DNS" },
                                        Description = $"Обнаружен сканером на порту UDP 53 → {ips[0]}.",
                                        SupportsBypass = requiresBypass,
                                        IsBuiltin = false,
                                        IsFreeUnlimited = true,
                                        LastLatencyMs = Math.Round(lat),
                                        LastTps = Math.Round(1000.0 / Math.Max(1.0, lat), 1),
                                        SuccessRatePercent = 100,
                                        Port443Ok = requiresBypass ? p443Ok : null,
                                        HttpStatus = httpCode,
                                        ResolvedIps = ips,
                                        Verdict = BypassVerdict.VERIFIED_PROXY_OK,
                                        VerdictReason = $"Найден сканером ({Math.Round(lat)} мс → {ips[0]})",
                                        LastCheckedDomain = checkDomain
                                    });
                                    addedForThisIp = true;
                                    Interlocked.Increment(ref foundCount);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch
                    {
                        // IP did not answer UDP 53
                    }
                }

                // 2. Probe direct Smart-Proxy TLS 443 SNI Node (smartproxy://<ip>)
                if (checkPort443 && !addedForThisIp)
                {
                    try
                    {
                        var sw = Stopwatch.StartNew();
                        var sni = await prober.ProbeSniPort443DetailedAsync(ip, checkDomain, null, ct).ConfigureAwait(false);
                        sw.Stop();

                        if (sni.Port443Ok && !sni.GeoBlockedBody && !AntiDirectIpFilter.IsGeoBlockedRedirect(sni.HttpStatus, sni.RedirectLocation))
                        {
                            double lat = Math.Max(1, Math.Round(sw.Elapsed.TotalMilliseconds));
                            found.Add(new DnsServerEntry
                            {
                                Id = $"scan_sni_{ip.Replace('.', '_')}",
                                Name = $"Smart-Proxy SNI {ip}",
                                Provider = "Сканер SNI 443",
                                Protocol = DnsProtocol.SNI443,
                                PrimaryIp = ip,
                                SmartProxyIp = ip,
                                DohUrl = $"smartproxy://{ip}",
                                Port = 443,
                                Category = "Свои / Найденные",
                                Country = "SCAN",
                                Tags = new List<string> { "Scan", "SNI443", "SmartProxy" },
                                Description = $"Открытый Smart-Proxy узел на порту 443 для {checkDomain}.",
                                SupportsBypass = true,
                                IsBuiltin = false,
                                IsFreeUnlimited = true,
                                LastLatencyMs = lat,
                                LastTps = Math.Round(1000.0 / Math.Max(1.0, lat), 1),
                                SuccessRatePercent = 100,
                                Port443Ok = true,
                                HttpStatus = sni.HttpStatus,
                                ResolvedIps = new List<string> { ip },
                                Verdict = BypassVerdict.VERIFIED_PROXY_OK,
                                VerdictReason = $"Рабочий SNI-443 прокси (HTTP {sni.HttpStatus?.ToString() ?? "OK"}, {lat} мс)",
                                LastCheckedDomain = checkDomain
                            });
                            Interlocked.Increment(ref foundCount);
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch
                    {
                        // Port 443 closed or TLS failed
                    }
                }
            }
            finally
            {
                int currentDone = Interlocked.Increment(ref done);
                progress?.Report(currentDone * 100.0 / total);
                detailedProgress?.Report((currentDone, total, Volatile.Read(ref foundCount), ip));
                sem.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return found.OrderBy(s => s.LastLatencyMs ?? double.MaxValue).ToList();
    }

    public static List<string> BuildHunterCandidateIps(string? seedInput)
    {
        var trimmed = (seedInput ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Equals("AUTO", StringComparison.OrdinalIgnoreCase))
        {
            var octets = new SortedSet<int>(KnownClusterOctets);
            for (int o = 1; o <= 254; o += 8)
                octets.Add(o);

            var list = new List<string>(DefaultCuratedPrefixes.Length * octets.Count);
            foreach (var prefix in DefaultCuratedPrefixes)
            {
                foreach (var octet in octets)
                    list.Add($"{prefix}.{octet}");
            }
            return list;
        }

        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var tokens = trimmed.Split(new[] { ',', ';', '\n', '\r', ' ' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var token in tokens)
        {
            var m = IpOrCidrRegex().Match(token.Trim());
            if (!m.Success) continue;

            if (!int.TryParse(m.Groups[1].Value, out int o1) ||
                !int.TryParse(m.Groups[2].Value, out int o2) ||
                !int.TryParse(m.Groups[3].Value, out int o3) ||
                !int.TryParse(m.Groups[4].Value, out int o4))
            {
                continue;
            }

            if (o1 < 1 || o1 > 254 || o2 < 0 || o2 > 255 || o3 < 0 || o3 > 255)
                continue;

            bool hasMask = m.Groups[5].Success;
            if (!hasMask && o4 >= 1 && o4 <= 254)
            {
                var exact = $"{o1}.{o2}.{o3}.{o4}";
                if (seen.Add(exact)) result.Add(exact);
            }

            for (int host = 1; host <= 254; host++)
            {
                var candidate = $"{o1}.{o2}.{o3}.{host}";
                if (seen.Add(candidate)) result.Add(candidate);
            }

            if (result.Count >= 1200)
                break;
        }

        return result.Take(1200).ToList();
    }

    [GeneratedRegex(@"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$")]
    private static partial Regex IpOrCidrRegex();
}
