using System.Globalization;
using System.Text;
using System.Text.Json;
using DnsPulse.App.Models;

namespace DnsPulse.App.Data;

public static class ImportExportCodec
{
    public static List<DnsServerEntry> ParseImportedServers(string rawText)
    {
        var trimmed = rawText.Trim();
        if (string.IsNullOrEmpty(trimmed)) return [];

        if (trimmed.StartsWith('[') || trimmed.StartsWith('{'))
        {
            try
            {
                var items = trimmed.StartsWith('[')
                    ? JsonSerializer.Deserialize<List<DnsServerEntry>>(trimmed, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    : [JsonSerializer.Deserialize<DnsServerEntry>(trimmed, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!];

                if (items is not null)
                {
                    return items
                        .Where(s => s is not null && (!string.IsNullOrWhiteSpace(s.PrimaryIp) || !string.IsNullOrWhiteSpace(s.DohUrl) || !string.IsNullOrWhiteSpace(s.DotHost)))
                        .Select((s, i) => NormalizeCustom(s, i))
                        .ToList();
                }
            }
            catch
            {
                // Fallback to plain-text parsing
            }
        }

        var list = new List<DnsServerEntry>();
        var lines = trimmed.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#')) continue;
            if (i == 0 && line.ToLowerInvariant().Contains("name") && line.ToLowerInvariant().Contains("endpoint")) continue;

            if (line.Contains(','))
            {
                var cols = line.Split(',').Select(c => c.Trim().Trim('"')).ToArray();
                if (cols.Length >= 2)
                {
                    var name = cols[0];
                    var ep = cols[1];
                    var prov = cols.Length > 2 && !string.IsNullOrEmpty(cols[2]) ? cols[2] : "Импорт";
                    var bypass = cols.Length > 3 && cols[3].Equals("true", StringComparison.OrdinalIgnoreCase);
                    var entry = FromEndpoint(ep, string.IsNullOrEmpty(name) ? ep : name, prov, bypass, i);
                    if (entry is not null) list.Add(entry);
                    continue;
                }
            }

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            var endpoint = parts[0];
            var customName = parts.Length > 1 ? string.Join(' ', parts.Skip(1)) : "";
            var parsed = FromEndpoint(endpoint, string.IsNullOrEmpty(customName) ? endpoint : customName, "Импорт", true, i);
            if (parsed is not null) list.Add(parsed);
        }
        return list;
    }

    private static DnsServerEntry? FromEndpoint(string endpoint, string name, string provider, bool supportsBypass, int idx)
    {
        var ep = endpoint.Trim();
        if (ep.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(ep, UriKind.Absolute, out var uri)) return null;
            return new DnsServerEntry
            {
                Id = $"custom_import_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{idx}",
                Name = name,
                Provider = provider,
                Protocol = DnsProtocol.DoH,
                DohUrl = uri.ToString(),
                DotHost = uri.Host,
                Category = "Свои / Найденные",
                SupportsBypass = supportsBypass,
                IsBuiltin = false,
                IsSubscription = ep.Contains("/kkkr", StringComparison.OrdinalIgnoreCase)
            };
        }

        if (ep.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
        {
            var host = ep[6..].Split(':')[0];
            if (string.IsNullOrWhiteSpace(host)) return null;
            return new DnsServerEntry
            {
                Id = $"custom_import_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{idx}",
                Name = name,
                Provider = provider,
                Protocol = DnsProtocol.DoT,
                DotHost = host,
                Category = "Свои / Найденные",
                SupportsBypass = supportsBypass,
                IsBuiltin = false
            };
        }

        if (ep.StartsWith("smartproxy://", StringComparison.OrdinalIgnoreCase))
        {
            var ip = ep["smartproxy://".Length..].Split(':')[0];
            if (string.IsNullOrWhiteSpace(ip)) return null;
            return new DnsServerEntry
            {
                Id = $"custom_import_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{idx}",
                Name = name,
                Provider = provider,
                Protocol = DnsProtocol.SNI443,
                PrimaryIp = ip,
                SmartProxyIp = ip,
                Port = 443,
                Category = "Свои / Найденные",
                SupportsBypass = true,
                IsBuiltin = false
            };
        }

        if (!System.Net.IPAddress.TryParse(ep, out _)) return null;
        return new DnsServerEntry
        {
            Id = $"custom_import_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{idx}",
            Name = name,
            Provider = provider,
            Protocol = DnsProtocol.UDP,
            PrimaryIp = ep,
            Category = "Свои / Найденные",
            SupportsBypass = supportsBypass,
            IsBuiltin = false
        };
    }

    private static DnsServerEntry NormalizeCustom(DnsServerEntry s, int idx)
    {
        if (string.IsNullOrWhiteSpace(s.Id))
            s.Id = $"custom_import_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{idx}";
        if (string.IsNullOrWhiteSpace(s.Category)) s.Category = "Свои / Найденные";
        if (string.IsNullOrWhiteSpace(s.Provider)) s.Provider = "Импорт";
        s.IsBuiltin = false;
        return s;
    }

    public static string ExportToCsv(IEnumerable<DnsServerEntry> servers)
    {
        var sb = new StringBuilder();
        sb.AppendLine("name,endpoint,provider,supportsBypass,verdict,latencyMs");
        foreach (var s in servers)
        {
            var ep = s.DohUrl ?? s.DotHost ?? s.SmartProxyIp ?? s.PrimaryIp;
            var lat = s.LastLatencyMs?.ToString(CultureInfo.InvariantCulture) ?? "";
            sb.AppendLine($"\"{s.Name.Replace("\"", "'")}\",\"{ep}\",\"{s.Provider.Replace("\"", "'")}\",{s.SupportsBypass.ToString().ToLowerInvariant()},{s.Verdict},{lat}");
        }
        return sb.ToString();
    }
}
