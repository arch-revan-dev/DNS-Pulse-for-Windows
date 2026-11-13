using System.Net;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;

namespace DnsPulse.Engine.Diagnostics;

/// <summary>
/// Execution status for an individual diagnostic layer.
/// </summary>
public enum DiagnosticLayerStatus
{
    Skipped = 0,
    Passed = 1,
    Warning = 2,
    Failed = 3
}

/// <summary>
/// Actionable 1-click remediation produced by Layer 6 root-cause classification.
/// </summary>
public enum RemediationActionKind
{
    None = 0,
    SwitchToDoQOrFragmentedDoh = 1,
    EnableTlsSplitPacForDomain = 2,
    RouteViaVerifiedGeoUnlock = 3,
    FixLocalPort53Conflict = 4,
    DisableBrowserDohOverride = 5,
    DeploySelfHostedVps = 6
}

/// <summary>
/// Structured outcome and telemetry from a single layer of <see cref="SixLayerDiagnosticEngine"/>.
/// </summary>
public sealed record DiagnosticLayerResult(
    int LayerNumber,
    string LayerName,
    DiagnosticLayerStatus Status,
    TimeSpan Duration,
    string Summary,
    IReadOnlyDictionary<string, string>? Metrics = null);

/// <summary>
/// Deterministic 1-click remediation guidance returned by Layer 6 classification.
/// </summary>
public sealed record RecommendedRemediation(
    RemediationActionKind Action,
    string Title,
    string Description,
    string? TargetDomain = null,
    string? SuggestedServerId = null);

/// <summary>
/// Optional tuning and endpoint-override configuration for <see cref="SixLayerDiagnosticEngine"/>.
/// </summary>
public sealed record DiagnosticProbeOptions
{
    public int TransportProbeSamples { get; init; } = 3;

    public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromMilliseconds(2600);

    public int HttpsPort { get; init; } = 443;

    public bool ProbeCompanionDomains { get; init; } = true;

    public bool IncludeTlsAndApplicationProbes { get; init; } = true;

    public bool CheckEchViaBaseline { get; init; } = true;

    public string? HttpProbePath { get; init; }

    /// <summary>
    /// Optional additional root/leaf certificates trusted exclusively for this probe via
    /// <see cref="X509ChainTrustMode.CustomRootTrust"/> (SAN hostname verification remains strictly enforced).
    /// </summary>
    public IReadOnlyList<X509Certificate2>? AdditionalTrustedRoots { get; init; }

    /// <summary>
    /// Optional TCP/TLS endpoint override for local integration testing while keeping <c>TargetHost = domain</c>.
    /// </summary>
    public IPEndPoint? OverrideTlsEndpoint { get; init; }

    /// <summary>
    /// Optional companion-domain TCP/TLS endpoint overrides for local integration testing.
    /// </summary>
    public IReadOnlyDictionary<string, IPEndPoint>? CompanionEndpointOverrides { get; init; }
}

/// <summary>
/// Comprehensive 6-layer diagnostic report produced for a target domain and upstream resolver.
/// </summary>
public sealed record DiagnosticReport
{
    public required string TargetDomain { get; init; }

    public required DnsServerEntry Upstream { get; init; }

    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public TimeSpan TotalDuration { get; init; }

    public DiagnosticVerdict Verdict { get; init; } = DiagnosticVerdict.Unknown;

    public string Reason { get; init; } = string.Empty;

    public required RecommendedRemediation Remediation { get; init; }

    public IReadOnlyList<DiagnosticLayerResult> Layers { get; init; } = [];

    public double? LatencyP50Ms { get; init; }

    public double? LatencyP95Ms { get; init; }

    public double? JitterMs { get; init; }

    public double PacketLossPercent { get; init; }

    public IReadOnlyList<IPAddress> ResolvedAddresses { get; init; } = [];

    public bool TlsHandshakeSucceeded { get; init; }

    public string? NegotiatedAlpn { get; init; }

    public bool EchAdvertised { get; init; }

    public int? HttpStatusCode { get; init; }

    public bool? CompanionPassed { get; init; }

    public Contracts.HostNetworkHealthSnapshot? HostHealth { get; init; }
}
