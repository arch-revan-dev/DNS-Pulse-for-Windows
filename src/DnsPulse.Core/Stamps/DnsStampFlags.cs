using System.Diagnostics.CodeAnalysis;

namespace DnsPulse.Core.Stamps;

/// <summary>
/// Server property flags encoded in DNSCrypt v2 DNS stamps.
/// </summary>
[Flags]
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "Public API name mandated for DNSCrypt v2 stamp flags.")]
public enum DnsStampFlags
{
    /// <summary>No flags set.</summary>
    None = 0,

    /// <summary>Server supports DNSSEC validation.</summary>
    DnsSec = 1,

    /// <summary>Server does not keep logs.</summary>
    NoLog = 2,

    /// <summary>Server does not intentionally block domains.</summary>
    NoFilter = 4
}
