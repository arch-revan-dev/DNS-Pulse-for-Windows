using DnsPulse.App.Models;

namespace DnsPulse.App.Data;

public static class ServerFilterSorter
{
    public static List<DnsServerEntry> FilterAndSort(
        IEnumerable<DnsServerEntry> servers,
        string category,
        bool bypassOnly,
        bool favoritesOnly,
        bool encryptedOnly,
        bool freeOnly,
        string search,
        SortMode sortMode,
        bool requiresBypass)
    {
        var q = search.Trim().ToLowerInvariant();
        var tokens = string.IsNullOrEmpty(q)
            ? Array.Empty<string>()
            : q.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries);

        var filtered = servers.Where(s =>
        {
            if (category != "Все" && s.Category != category) return false;
            if (freeOnly && s.IsSubscription) return false;
            if (favoritesOnly && !s.IsFavorite) return false;
            if (encryptedOnly && s.Protocol is not (DnsProtocol.DoH or DnsProtocol.DoT)) return false;
            if (bypassOnly && requiresBypass)
            {
                bool ok = s.Verdict == BypassVerdict.VERIFIED_PROXY_OK || (s.Verdict == BypassVerdict.UNCHECKED && s.SupportsBypass);
                if (!ok) return false;
            }
            if (tokens.Length > 0)
            {
                var hay = $"{s.Name} {s.Provider} {s.Category} {s.Country} {s.ProtocolBadge} {s.EndpointLabel} {s.PrimaryIp} {s.DohUrl} {s.DotHost} {s.SmartProxyIp} {string.Join(' ', s.Tags)} {s.Description} {s.VerdictReason}".ToLowerInvariant();
                foreach (var token in tokens)
                {
                    if (!hay.Contains(token))
                        return false;
                }
            }
            return true;
        });

        return sortMode switch
        {
            SortMode.LOWEST_PING => filtered.OrderBy(s => s.LastLatencyMs ?? s.AvgLatencyMs ?? double.MaxValue).ThenBy(s => s.Name).ToList(),
            SortMode.HIGHEST_TPS => filtered.OrderByDescending(s => s.LastTps ?? -1).ThenBy(s => s.LastLatencyMs ?? double.MaxValue).ToList(),
            SortMode.FAVORITES_FIRST => filtered.OrderByDescending(s => s.IsFavorite).ThenBy(s => s.LastLatencyMs ?? double.MaxValue).ToList(),
            SortMode.ALPHABETICAL => filtered.OrderBy(s => s.Name, StringComparer.CurrentCultureIgnoreCase).ToList(),
            _ => filtered.OrderBy(s => VerdictRank(s.Verdict, s.SupportsBypass)).ThenBy(s => s.LastLatencyMs ?? s.AvgLatencyMs ?? double.MaxValue).ToList()
        };
    }

    private static int VerdictRank(BypassVerdict v, bool bypass) => v switch
    {
        BypassVerdict.VERIFIED_PROXY_OK => 0,
        BypassVerdict.UNCHECKED => bypass ? 1 : 2,
        BypassVerdict.DIRECT_NO_PROXY => 3,
        BypassVerdict.GEO_REDIRECT_BLOCKED => 4,
        BypassVerdict.PROXY_PORT_DEAD => 5,
        _ => 6
    };

    public static List<string> ParseDynamicHosts(string raw)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in raw.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Split('#')[0].Trim();
            if (string.IsNullOrEmpty(line)) continue;
            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                if (parts[0] is "0.0.0.0" or "127.0.0.1" or "::1" or "::") continue;
                hosts.Add(parts[1].ToLowerInvariant());
            }
        }
        return [.. hosts];
    }

    public static List<string> BuildRotationQueue(IEnumerable<DnsServerEntry> servers, string? currentId)
    {
        var list = servers
            .Where(s => s.Verdict == BypassVerdict.VERIFIED_PROXY_OK)
            .OrderBy(s => s.LastLatencyMs ?? double.MaxValue)
            .Select(s => s.Id)
            .ToList();
        if (!string.IsNullOrEmpty(currentId) && !list.Contains(currentId)) list.Insert(0, currentId);
        return list;
    }

    public static string? NextRotationId(IReadOnlyList<string> queue, string? currentId)
    {
        if (queue.Count == 0) return null;
        if (string.IsNullOrEmpty(currentId)) return queue[0];
        int idx = -1;
        for (int i = 0; i < queue.Count; i++) if (queue[i] == currentId) { idx = i; break; }
        return idx < 0 || idx + 1 >= queue.Count ? queue[0] : queue[idx + 1];
    }
}
