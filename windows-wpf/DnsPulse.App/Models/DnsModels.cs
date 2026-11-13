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
