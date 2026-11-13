namespace DnsPulse.Core.Models;

/// <summary>
/// Security and operational trust classification for DNS and Geo-Unlock endpoints.
/// </summary>
public enum TrustTier
{
    Tier1EncryptedTrusted = 0,
    Tier2VerifiedGeoUnlock = 1,
    Tier3CustomOrSelfHosted = 2,
    Tier4ExperimentalLab = 3
}

/// <summary>
/// Policy helpers enforcing strict separation between default internet resolution and Geo-Unlock/experimental nodes.
/// </summary>
public static class TrustTierPolicy
{
    /// <summary>
    /// Returns true only when the trust tier and protocol are eligible for Tier 1 default internet resolution.
    /// Tier 4 nodes, unencrypted transports, and arbitrary SNI proxies never qualify.
    /// </summary>
    public static bool CanServeDefaultInternet(TrustTier tier, DnsProtocol protocol)
    {
        if (tier != TrustTier.Tier1EncryptedTrusted)
        {
            return false;
        }

        return protocol is DnsProtocol.DoT
            or DnsProtocol.DoH
            or DnsProtocol.DoH3
            or DnsProtocol.DoQ
            or DnsProtocol.DnsCrypt
            or DnsProtocol.AnonymizedDnsCrypt
            or DnsProtocol.ODoH;
    }

    /// <summary>
    /// Returns true when the trust tier is permitted for scoped Geo-Unlock routing (Zone 3).
    /// </summary>
    public static bool CanServeGeoUnlock(TrustTier tier)
    {
        return tier is TrustTier.Tier2VerifiedGeoUnlock
            or TrustTier.Tier3CustomOrSelfHosted
            or TrustTier.Tier4ExperimentalLab;
    }
}
