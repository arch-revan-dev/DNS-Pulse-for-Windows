using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json.Serialization;

namespace DnsPulse.Core.Models;

/// <summary>
/// Immutable catalog and telemetry entry describing a DNS resolver or Smart-DNS/SNI-Proxy node.
/// </summary>
public sealed record DnsServerEntry
{
    public string Id { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string Provider { get; init; } = string.Empty;

    public DnsProtocol Protocol { get; init; }

    public TrustTier TrustTier { get; init; } = TrustTier.Tier3CustomOrSelfHosted;

    public string PrimaryIp { get; init; } = string.Empty;

    public string? SecondaryIp { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Preserves v1.5.3 string serialization and custom scheme endpoints.")]
    public string? DohUrl { get; init; }

    public string? DotHost { get; init; }

    public string? SmartProxyIp { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Stores raw sdns:// DNSCrypt stamp strings without Uri parsing overhead.")]
    public string? DnsStampUri { get; init; }

    public string? SpkiPinSha256 { get; init; }

    public IReadOnlyList<string> BootstrapIps { get; init; } = [];

    public int? Port { get; init; }

    public string Category { get; init; } = "Скоростные";

    public string Country { get; init; } = "GLOBAL";

    public IReadOnlyList<string> Tags { get; init; } = [];

    public string Description { get; init; } = string.Empty;

    public bool SupportsBypass { get; init; }

    public bool IsBuiltin { get; init; }

    public bool IsFavorite { get; init; }

    public bool IsSubscription { get; init; }

    public bool IsFreeUnlimited { get; init; } = true;

    public double? LastLatencyMs { get; init; }

    public double? MinLatencyMs { get; init; }

    public double? AvgLatencyMs { get; init; }

    public double? LatencyP50Ms { get; init; }

    public double? LatencyP95Ms { get; init; }

    public double? JitterMs { get; init; }

    public double? LastTps { get; init; }

    public int? SuccessRatePercent { get; init; }

    public DiagnosticVerdict Verdict { get; init; }

    public string VerdictReason { get; init; } = "Не проверялся";

    public IReadOnlyList<string> ResolvedIps { get; init; } = [];

    public bool? CompanionPassed { get; init; }

    public bool? Port443Ok { get; init; }

    public int? HttpStatus { get; init; }

    public string? LastCheckedDomain { get; init; }

    public DateTimeOffset? LastCheckedAt { get; init; }

    public IReadOnlyList<int> HistoryMs { get; init; } = [];

    [JsonIgnore]
    public bool IsCustom => !IsBuiltin;

    [JsonIgnore]
    public bool IsEncrypted => Protocol is DnsProtocol.DoT
        or DnsProtocol.DoH
        or DnsProtocol.DoH3
        or DnsProtocol.DoQ
        or DnsProtocol.DnsCrypt
        or DnsProtocol.AnonymizedDnsCrypt
        or DnsProtocol.ODoH;

    [JsonIgnore]
    public bool IsEligibleForDefaultInternet => TrustTierPolicy.CanServeDefaultInternet(TrustTier, Protocol);

    [JsonIgnore]
    public string ProtocolBadge => Protocol == DnsProtocol.SniProxy ? "443" : Protocol.ToString();

    [JsonIgnore]
    public string EndpointLabel => Protocol switch
    {
        DnsProtocol.DoH or DnsProtocol.DoH3 when !string.IsNullOrWhiteSpace(DohUrl) => DohUrl,
        DnsProtocol.DoT when !string.IsNullOrWhiteSpace(DotHost) => string.Create(CultureInfo.InvariantCulture, $"tls://{DotHost}:{Port ?? 853}"),
        DnsProtocol.DoQ when !string.IsNullOrWhiteSpace(DotHost) => string.Create(CultureInfo.InvariantCulture, $"quic://{DotHost}:{Port ?? 853}"),
        DnsProtocol.SniProxy => string.Create(CultureInfo.InvariantCulture, $"smartproxy://{(!string.IsNullOrWhiteSpace(SmartProxyIp) ? SmartProxyIp : PrimaryIp)}:{Port ?? 443}"),
        _ when !string.IsNullOrWhiteSpace(DnsStampUri) => DnsStampUri,
        _ => !string.IsNullOrWhiteSpace(PrimaryIp) ? PrimaryIp : (DotHost ?? DohUrl ?? "—")
    };
}
