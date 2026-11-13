using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App.Services;

public sealed partial class OnlineFeedSyncService
{
    private readonly HttpClient _http = BootstrapDnsResolver.CreateBootstrapHttpClient(
        TimeSpan.FromMilliseconds(5500),
        allowAutoRedirect: true);

    private static readonly (string Url, string Tag)[] CommunityServerSources =
    {
        ("https://raw.githubusercontent.com/neiroseti-ai/hb-ai-xbox-dns/main/README.md", "HB-AI"),
        ("https://raw.githubusercontent.com/vezlin1/antigravity-bypass-russia/main/README.md", "Antigravity")
    };

    private static readonly string[] BypassHostFeedUrls =
    {
        "https://dns.malw.link/hosts",
        "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts"
    };

    public async Task<(List<string> Hosts, List<DnsServerEntry> Discovered)> SyncAsync(CancellationToken ct)
    {
        var extractedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var discovered = new List<DnsServerEntry>();
        var seenEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Sync dynamic geo-restricted hosts (malw.link / ImMALWARE mirrors)
        foreach (var hostUrl in BypassHostFeedUrls)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                var raw = await _http.GetStringAsync(hostUrl, ct).ConfigureAwait(false);
                var parsed = ServerFilterSorter.ParseDynamicHosts(raw);
                foreach (var h in parsed)
                {
                    if (DynamicBypassRegistry.IsValidDomainName(h))
                        extractedDomains.Add(h);
                }
                if (extractedDomains.Count >= 15)
                    break;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Try next mirror
            }
        }

        if (extractedDomains.Count > 0)
        {
            DynamicBypassRegistry.ClassifyAndAddDomains(extractedDomains);
        }

        // 2. QuickDNS community default_profiles.json (validated JSON catalog)
        try
        {
            var jsonRaw = await _http.GetStringAsync(
                "https://raw.githubusercontent.com/szanko02/QuickDNS/main/default_profiles.json",
                ct).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(jsonRaw) && jsonRaw.TrimStart().StartsWith('['))
            {
                using var doc = JsonDocument.Parse(jsonRaw);
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var name = ReadJsonString(el, "name");
                    var primaryIp = FirstNonEmpty(ReadJsonString(el, "primary"), ReadJsonString(el, "primaryIp"));
                    var secondaryIp = FirstNonEmpty(ReadJsonString(el, "secondary"), ReadJsonString(el, "secondaryIp"));
                    var dohUrl = FirstNonEmpty(ReadJsonString(el, "doh"), ReadJsonString(el, "dohUrl"));
                    var dotHost = FirstNonEmpty(ReadJsonString(el, "dot"), ReadJsonString(el, "dotHostname"));

                    var protocol = !string.IsNullOrWhiteSpace(dohUrl)
                        ? DnsProtocol.DoH
                        : !string.IsNullOrWhiteSpace(dotHost)
                            ? DnsProtocol.DoT
                            : DnsProtocol.UDP;

                    if (string.IsNullOrWhiteSpace(primaryIp) && string.IsNullOrWhiteSpace(dohUrl) && string.IsNullOrWhiteSpace(dotHost))
                        continue;

                    var dedupKey = $"{primaryIp}|{dohUrl}|{dotHost}".ToLowerInvariant();
                    if (!seenEndpoints.Add(dedupKey))
                        continue;

                    var title = string.IsNullOrWhiteSpace(name)
                        ? (!string.IsNullOrWhiteSpace(primaryIp) ? primaryIp : dotHost)
                        : name;

                    discovered.Add(new DnsServerEntry
                    {
                        Id = BuildStableId("quickdns", title, dedupKey),
                        Name = $"{title} (QuickDNS)",
                        Provider = "GitHub QuickDNS",
                        Protocol = protocol,
                        PrimaryIp = primaryIp,
                        SecondaryIp = string.IsNullOrWhiteSpace(secondaryIp) ? null : secondaryIp,
                        DohUrl = string.IsNullOrWhiteSpace(dohUrl) ? null : dohUrl,
                        DotHost = string.IsNullOrWhiteSpace(dotHost) ? null : dotHost,
                        Category = "Smart-DNS",
                        Country = "GLOBAL",
                        Tags = new List<string> { "OnlineFeed", "QuickDNS", "SmartDNS", "Free" },
                        Description = "Загружен из онлайн-репозитория QuickDNS (через Bootstrap DNS).",
                        SupportsBypass = true,
                        IsBuiltin = false,
                        IsFreeUnlimited = true
                    });
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Continue with secondary sources
        }

        // 3. Community markdown Smart-DNS / DoH feeds
        foreach (var (url, tag) in CommunityServerSources)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                var raw = await _http.GetStringAsync(url, ct).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(raw)) continue;

                foreach (Match m in DohRegex().Matches(raw))
                {
                    var doh = m.Value.TrimEnd('.', ',', ';', ')', '`', '"', '\'');
                    if (seenEndpoints.Add($"|{doh}|"))
                    {
                        var host = Uri.TryCreate(doh, UriKind.Absolute, out var u) ? u.Host : doh;
                        discovered.Add(new DnsServerEntry
                        {
                            Id = BuildStableId("feed_doh", host, doh),
                            Name = $"{host} ({tag})",
                            Provider = $"Online Feed · {tag}",
                            Protocol = DnsProtocol.DoH,
                            DohUrl = doh,
                            Category = "Smart-DNS",
                            Country = "GLOBAL",
                            Tags = new List<string> { "OnlineFeed", "DoH", tag },
                            Description = $"Автоматически найден в онлайн-списке {tag}.",
                            SupportsBypass = true,
                            IsBuiltin = false,
                            IsFreeUnlimited = true
                        });
                    }
                }

                int ipTake = 0;
                foreach (Match m in IpRegex().Matches(raw))
                {
                    if (ipTake >= 20) break;
                    var ip = m.Value;
                    if (ip is "1.1.1.1" or "1.0.0.1" or "8.8.8.8" or "8.8.4.4" or "9.9.9.9" ||
                        AntiDirectIpFilter.IsBogonOrLoopback(ip))
                    {
                        continue;
                    }
                    if (seenEndpoints.Add($"{ip}||"))
                    {
                        ipTake++;
                        discovered.Add(new DnsServerEntry
                        {
                            Id = BuildStableId("feed_ip", ip, ip),
                            Name = $"Smart-DNS {ip} ({tag})",
                            Provider = $"Online Feed · {tag}",
                            Protocol = DnsProtocol.UDP,
                            PrimaryIp = ip,
                            Category = "Smart-DNS",
                            Country = "GLOBAL",
                            Tags = new List<string> { "OnlineFeed", "UDP", tag },
                            Description = $"IP-кандидат из онлайн-базы {tag}.",
                            SupportsBypass = true,
                            IsBuiltin = false,
                            IsFreeUnlimited = true
                        });
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Skip unavailable feed silently
            }
        }

        return (DynamicBypassRegistry.GetAllProtectedDomains().ToList(), discovered);
    }

    private static string ReadJsonString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? (v.GetString() ?? string.Empty).Trim()
            : string.Empty;

    private static string FirstNonEmpty(string a, string b) =>
        !string.IsNullOrWhiteSpace(a) ? a : b;

    private static string BuildStableId(string prefix, string label, string unique)
    {
        var hash = Math.Abs(unique.ToLowerInvariant().GetHashCode());
        var clean = Regex.Replace(label.ToLowerInvariant(), "[^a-z0-9]+", "_").Trim('_');
        if (clean.Length > 24) clean = clean[..24];
        return $"{prefix}_{clean}_{hash}";
    }

    [GeneratedRegex(@"https://[^\s""'<>`)]+/dns-query[^\s""'<>`)]*", RegexOptions.IgnoreCase)]
    private static partial Regex DohRegex();

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")]
    private static partial Regex IpRegex();
}
