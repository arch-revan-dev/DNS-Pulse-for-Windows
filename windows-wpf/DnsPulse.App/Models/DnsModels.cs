using System.Text.Json.Serialization;

namespace DnsPulse.App.Models;

public enum DnsProtocol
{
    DoH,
    DoT,
    UDP,
    SNI443
}

public enum BypassVerdict
{
    UNCHECKED,
    TESTING,
    VERIFIED_PROXY_OK,
    DIRECT_NO_PROXY,
    GEO_REDIRECT_BLOCKED,
    PROXY_PORT_DEAD,
    DNS_TIMEOUT
}

public enum SortMode
{
    BEST,
    LOWEST_PING,
    HIGHEST_TPS,
    FAVORITES_FIRST,
    ALPHABETICAL
}

public sealed class DnsServerEntry
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Provider { get; set; } = "";
    public DnsProtocol Protocol { get; set; } = DnsProtocol.UDP;
    public string PrimaryIp { get; set; } = "";
    public string? SecondaryIp { get; set; }
    public string? DohUrl { get; set; }
    public string? DotHost { get; set; }
    public string? SmartProxyIp { get; set; }
    public int? Port { get; set; }
    public string Category { get; set; } = "Скоростные";
    public string Country { get; set; } = "GLOBAL";
    public List<string> Tags { get; set; } = new();
    public string Description { get; set; } = "";
    public bool SupportsBypass { get; set; }
    public bool IsBuiltin { get; set; }
    public bool IsFavorite { get; set; } // Always false by default for built-ins
    public bool IsSubscription { get; set; }
    public bool IsFreeUnlimited { get; set; } = true;
    public double? LastLatencyMs { get; set; }
    public double? MinLatencyMs { get; set; }
    public double? AvgLatencyMs { get; set; }
    public double? JitterMs { get; set; }
    public double? LastTps { get; set; }
    public BypassVerdict Verdict { get; set; } = BypassVerdict.UNCHECKED;
    public string VerdictReason { get; set; } = "Не проверялся";
    public List<string> ResolvedIps { get; set; } = new();
    public bool? CompanionPassed { get; set; }
    public bool? Port443Ok { get; set; }
    public int? HttpStatus { get; set; }
    public string? LastCheckedDomain { get; set; }
    public DateTimeOffset? LastCheckedAt { get; set; }
    public List<int> HistoryMs { get; set; } = new();

    [JsonIgnore]
    public string ProtocolBadge => Protocol == DnsProtocol.SNI443 ? "443" : Protocol.ToString();

    [JsonIgnore]
    public string EndpointLabel => Protocol switch
    {
        DnsProtocol.DoH when !string.IsNullOrWhiteSpace(DohUrl) => DohUrl!,
        DnsProtocol.DoT when !string.IsNullOrWhiteSpace(DotHost) => $"tls://{DotHost}:853",
        DnsProtocol.SNI443 => $"smartproxy://{SmartProxyIp ?? PrimaryIp}:443",
        _ => !string.IsNullOrWhiteSpace(PrimaryIp) ? PrimaryIp : (DotHost ?? DohUrl ?? "—")
    };

    [JsonIgnore]
    public string MetaLine => $"{Category} · {Country} · {EndpointLabel}";

    [JsonIgnore]
    public string LatencyDisplay => LastLatencyMs.HasValue ? $"{Math.Round(LastLatencyMs.Value)} мс" : "Тест";

    [JsonIgnore]
    public string TpsDisplay => LastTps.HasValue ? $"{LastTps.Value:0.#} TPS" : "4 этапа";

    [JsonIgnore]
    public string JitterDisplay => JitterMs.HasValue ? $"±{Math.Round(JitterMs.Value)} мс" : "—";

    [JsonIgnore]
    public string Port443Display => Port443Ok switch
    {
        true => $"OK ({HttpStatus?.ToString() ?? "200"})",
        false => HttpStatus.HasValue ? $"FAIL ({HttpStatus})" : "FAIL",
        null => "—"
    };

    [JsonIgnore]
    public string ResolvedIpsDisplay => ResolvedIps.Count > 0 ? string.Join(", ", ResolvedIps) : "—";

    [JsonIgnore]
    public bool IsCustom => !IsBuiltin;

    [JsonIgnore]
    public string Win11PowerShellCommand => !string.IsNullOrWhiteSpace(DohUrl)
        ? $"Add-DnsClientDohServerAddress -ServerAddress \"{(!string.IsNullOrWhiteSpace(PrimaryIp) ? PrimaryIp : "1.1.1.1")}\" -DohTemplate \"{DohUrl}\" -AllowFallbackToUdp $True -AutoUpgrade $True"
        : $"Set-DnsClientServerAddress -InterfaceAlias \"Wi-Fi\" -ServerAddresses \"{(!string.IsNullOrWhiteSpace(PrimaryIp) ? PrimaryIp : SmartProxyIp ?? "1.1.1.1")}\"";
}

public sealed class ProbeResult
{
    public string ServerId { get; set; } = "";
    public string TargetDomain { get; set; } = "";
    public bool RequiresBypass { get; set; }
    public double? LatencyMs { get; set; }
    public double? MinLatencyMs { get; set; }
    public double? AvgLatencyMs { get; set; }
    public double? JitterMs { get; set; }
    public double? Tps { get; set; }
    public List<string> ResolvedIps { get; set; } = new();
    public BypassVerdict Verdict { get; set; } = BypassVerdict.UNCHECKED;
    public string VerdictReason { get; set; } = "";
    public bool? CompanionPassed { get; set; }
    public bool? Port443Ok { get; set; }
    public int? HttpStatus { get; set; }
    public string? RedirectLocation { get; set; }
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class AdapterDnsBackup
{
    public string InterfaceAlias { get; set; } = "";
    public bool WasDhcp { get; set; }
    public List<string> PreviousDnsServers { get; set; } = new();
}

public sealed class RestoreNetworkState
{
    public DateTimeOffset? CapturedAt { get; set; }
    public bool ActiveTunnel { get; set; }
    public List<AdapterDnsBackup> Adapters { get; set; } = new();
}
