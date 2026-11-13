using System.Net.Http;
using System.Text.RegularExpressions;
using DnsPulse.App.Data;
using DnsPulse.App.Models;

namespace DnsPulse.App.Services;

public sealed partial class OnlineFeedSyncService
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

    private static readonly string[] FeedUrls =
    [
        "https://dns.malw.link/hosts",
        "https://raw.githubusercontent.com/I10467/QuickDNS/main/dns.txt"
    ];

    public async Task<(List<string> Hosts, List<DnsServerEntry> Discovered)> SyncAsync(CancellationToken ct)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var servers = new List<DnsServerEntry>();

        foreach (var url in FeedUrls)
        {
            try
            {
                var text = await _http.GetStringAsync(url, ct);
                foreach (var h in ServerFilterSorter.ParseDynamicHosts(text))
                    hosts.Add(h);

                foreach (Match m in DohRegex().Matches(text))
                {
                    if (!Uri.TryCreate(m.Value, UriKind.Absolute, out var uri)) continue;
                    servers.Add(new DnsServerEntry
                    {
                        Id = $"sync_{uri.Host.Replace('.', '_')}",
                        Name = $"Sync • {uri.Host}",
                        Provider = "Online Sync",
                        Protocol = DnsProtocol.DoH,
                        DohUrl = uri.ToString(),
                        DotHost = uri.Host,
                        Category = "Свои / Найденные",
                        SupportsBypass = true
                    });
                }
            }
            catch
            {
                // Continue syncing other feeds cleanly
            }
        }

        return ([.. hosts], servers.DistinctBy(s => s.Id).ToList());
    }

    [GeneratedRegex(@"https://[a-zA-Z0-9.-]+/dns-query", RegexOptions.Compiled)]
    private static partial Regex DohRegex();
}
