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
        "163.5.63",
        "5.10.223",
        "185.194.177",
        "87.229.95",
        "179.254.166",
        "83.220.169",
        "212.109.195",
        "111.88.96"
    };

    private static readonly int[] KnownClusterOctets =
    {
        1, 2, 3, 5, 10, 20, 21, 37, 40, 54, 77, 81, 93, 104, 112, 120, 134, 141, 149,
        155, 171, 177, 190, 192, 200, 221, 240, 241, 252, 253, 254
    };

    private static readonly string[] GamingDomainKeywords =
    {
        "xbox", "live.com", "brawlstars", "supercell", "clash", "hayday", "boombeach",
        "steam", "epicgames", "unrealengine", "playstation", "psn", "nintendo",
        "geforcenow", "nvidia", "roblox", "fortnite", "ea.com", "origin.com",
        "riot", "valorant", "leagueoflegends", "discord", "blizzard", "battle.net"
    };

    public static (string Category, string ServiceTag, string GroupHint) ClassifyTargetDomain(
        string? targetDomain,
        bool requiresBypass)
    {
        var domain = string.IsNullOrWhiteSpace(targetDomain)
            ? "gemini.google.com"
            : targetDomain.Trim().TrimEnd('.').ToLowerInvariant();

        if (!requiresBypass)
        {
            return ("Скоростные", "CleanPing", "Чистая скорость");
        }

        string serviceTag = ResolveServiceTag(domain);
        foreach (var kw in GamingDomainKeywords)
        {
            if (domain.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                return ("Игры и Регионы", serviceTag, "Игры и консоли");
            }
        }

        return ("Smart-DNS", serviceTag, "Smart-DNS обход");
    }

    private static string ResolveServiceTag(string domain)
    {
        if (domain.Contains("aistudio.google", StringComparison.OrdinalIgnoreCase)) return "AIStudio";
        if (domain.Contains("gemini.google", StringComparison.OrdinalIgnoreCase)) return "Gemini";
        if (domain.Contains("chatgpt.com", StringComparison.OrdinalIgnoreCase) || domain.Contains("openai.com", StringComparison.OrdinalIgnoreCase)) return "ChatGPT";
        if (domain.Contains("claude.ai", StringComparison.OrdinalIgnoreCase)) return "Claude";
        if (domain.Contains("copilot.microsoft", StringComparison.OrdinalIgnoreCase)) return "Copilot";
        if (domain.Contains("spotify", StringComparison.OrdinalIgnoreCase)) return "Spotify";
        if (domain.Contains("youtube", StringComparison.OrdinalIgnoreCase)) return "YouTube";
        if (domain.Contains("twitch", StringComparison.OrdinalIgnoreCase)) return "Twitch";
        if (domain.Contains("netflix", StringComparison.OrdinalIgnoreCase)) return "Netflix";
        if (domain.Contains("xbox", StringComparison.OrdinalIgnoreCase) || domain.Contains("live.com", StringComparison.OrdinalIgnoreCase)) return "Xbox";
        if (domain.Contains("brawlstars", StringComparison.OrdinalIgnoreCase) || domain.Contains("supercell", StringComparison.OrdinalIgnoreCase)) return "BrawlStars";
        if (domain.Contains("steam", StringComparison.OrdinalIgnoreCase)) return "Steam";
        if (domain.Contains("epicgames", StringComparison.OrdinalIgnoreCase)) return "EpicGames";
        return domain;
    }

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
        var classified = ClassifyTargetDomain(checkDomain, requiresBypass);

        using var sem = new SemaphoreSlim(48);
        var tasks = targets.Select(async ip =>
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (ct.IsCancellationRequested) return;

                Task ProbeUdpAsync() => Task.Run(async () =>
                {
                    if (!scanUdp53) return;
                    try
                    {
                        var (ips, lat) = await prober.QueryUdp53Async(ip, checkDomain, ct, timeoutMs: 900).ConfigureAwait(false);
                        if (ips.Count == 0) return;

                        bool isDirect = AntiDirectIpFilter.IsDirectServiceIp(ips[0], checkDomain);
                        if (requiresBypass && isDirect) return;

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
                            double roundedLat = Math.Max(1, Math.Round(lat));
                            found.Add(new DnsServerEntry
                            {
                                Id = $"auto_smartdns_{ip.Replace('.', '_')}",
                                Name = requiresBypass ? $"Auto SmartDNS {ip}" : $"Auto FastDNS {ip}",
                                Provider = "Auto Discovery (UDP 53)",
                                Protocol = DnsProtocol.UDP,
                                PrimaryIp = ip,
                                Category = classified.Category,
                                Country = "AUTO",
                                Tags = new List<string> { "AutoSmartDNS", "UDP53", classified.ServiceTag, checkDomain },
                                Description = $"Автоподбор ({classified.GroupHint}) на порту UDP 53 для {checkDomain} → {ips[0]}.",
                                SupportsBypass = requiresBypass,
                                IsBuiltin = false,
                                IsFreeUnlimited = true,
                                LastLatencyMs = roundedLat,
                                LastTps = Math.Round(1000.0 / Math.Max(1.0, roundedLat), 1),
                                SuccessRatePercent = 100,
                                Port443Ok = requiresBypass ? p443Ok : null,
                                HttpStatus = httpCode,
                                ResolvedIps = ips,
                                Verdict = BypassVerdict.VERIFIED_PROXY_OK,
                                VerdictReason = $"Auto SmartDNS ({roundedLat} мс → {ips[0]})",
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
                        // IP did not answer UDP 53
                    }
                }, ct);

                Task ProbeSni443Async() => Task.Run(async () =>
                {
                    if (!checkPort443) return;
                    if (requiresBypass && AntiDirectIpFilter.IsDirectServiceIp(ip, checkDomain)) return;
                    try
                    {
                        var (tcpOpen, tcpMs) = await prober.ProbeTcp443LatencyAsync(ip, 950, ct).ConfigureAwait(false);
                        if (!tcpOpen) return;

                        var sw = Stopwatch.StartNew();
                        var sni = await prober.ProbeSniPort443DetailedAsync(ip, checkDomain, null, ct).ConfigureAwait(false);
                        sw.Stop();

                        if (sni.Port443Ok && !sni.GeoBlockedBody && !AntiDirectIpFilter.IsGeoBlockedRedirect(sni.HttpStatus, sni.RedirectLocation))
                        {
                            double lat = Math.Max(1, Math.Min(tcpMs, Math.Round(sw.Elapsed.TotalMilliseconds)));
                            found.Add(new DnsServerEntry
                            {
                                Id = $"auto_proxy_{ip.Replace('.', '_')}",
                                Name = $"Auto Proxy Node {ip}",
                                Provider = "Auto Proxy (Smart-VPN 443)",
                                Protocol = DnsProtocol.SNI443,
                                PrimaryIp = ip,
                                SmartProxyIp = ip,
                                DohUrl = $"smartproxy://{ip}",
                                Port = 443,
                                Category = classified.Category,
                                Country = "AUTO",
                                Tags = new List<string> { "AutoProxy", "SNI443", classified.ServiceTag, checkDomain },
                                Description = $"Auto Proxy SNI-443 узел ({classified.GroupHint}) для {checkDomain}.",
                                SupportsBypass = requiresBypass,
                                IsBuiltin = false,
                                IsFreeUnlimited = true,
                                LastLatencyMs = lat,
                                LastTps = Math.Round(1000.0 / Math.Max(1.0, lat), 1),
                                SuccessRatePercent = 100,
                                Port443Ok = true,
                                HttpStatus = sni.HttpStatus,
                                ResolvedIps = new List<string> { ip },
                                Verdict = BypassVerdict.VERIFIED_PROXY_OK,
                                VerdictReason = $"Auto Proxy SNI-443 (HTTP {sni.HttpStatus?.ToString() ?? "OK"}, {lat} мс)",
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
                }, ct);

                await Task.WhenAll(ProbeUdpAsync(), ProbeSni443Async()).ConfigureAwait(false);
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
            for (int o = 1; o <= 254; o += 4)
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
