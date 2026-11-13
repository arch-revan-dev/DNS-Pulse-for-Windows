namespace DnsPulse.Core.Routing;

/// <summary>
/// Represents the strict four-zone routing hierarchy evaluated by <see cref="SplitNamespaceRouter"/>.
/// </summary>
public enum RouteZone
{
    /// <summary>
    /// Unassigned / default zero value.
    /// </summary>
    None = 0,

    /// <summary>
    /// Zone 1: Local, LAN, reverse-DNS, and corporate suffixes routed to the original interface or VPN DNS.
    /// </summary>
    Zone1LocalBypass = 1,

    /// <summary>
    /// Zone 2: Blocked domains (ad/malware rules) or security-critical pinned domains protected from Zone 3 hijacking.
    /// </summary>
    Zone2BlockOrProtect = 2,

    /// <summary>
    /// Zone 3: Explicitly enabled Geo-unlock / Smart-DNS domains.
    /// </summary>
    Zone3GeoUnlock = 3,

    /// <summary>
    /// Zone 4: Default encrypted trusted internet DNS.
    /// </summary>
    Zone4EncryptedTrusted = 4
}
