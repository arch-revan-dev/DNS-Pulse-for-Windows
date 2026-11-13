using System.Net;
using DnsPulse.Core.Routing;

namespace DnsPulse.Core.Security;

/// <summary>
/// Describes a named built-in carrier-private Anycast resolver endpoint that may be explicitly opted into
/// despite residing within an RFC 1918 prefix (e.g., <c>10.202.10.*</c> for 403.online / Radar Game).
/// </summary>
/// <param name="EndpointId">Canonical built-in endpoint identifier.</param>
/// <param name="DisplayName">Human-readable name of the carrier endpoint.</param>
/// <param name="AllowedCidr">The narrow CIDR prefix permitted when explicitly opted in.</param>
public sealed record CarrierAnycastEndpoint(
    string EndpointId,
    string DisplayName,
    string AllowedCidr);

/// <summary>
/// Result of validating DNS answer IP addresses against DNS rebinding attacks.
/// </summary>
/// <param name="IsSafe"><c>true</c> if no private/bogon addresses were rejected.</param>
/// <param name="AcceptedAddresses">Addresses allowed for the target zone and resolver.</param>
/// <param name="RejectedAddresses">Private/bogon addresses blocked by DNS rebinding protection.</param>
/// <param name="RejectionReason">Diagnostic reason when <paramref name="IsSafe"/> is <c>false</c>.</param>
public sealed record DnsRebindingValidationResult(
    bool IsSafe,
    IReadOnlyList<IPAddress> AcceptedAddresses,
    IReadOnlyList<IPAddress> RejectedAddresses,
    string? RejectionReason);

/// <summary>
/// Validates IP addresses returned by external DNS resolvers to prevent DNS rebinding attacks against
/// loopback, LAN, CGNAT, link-local, or IPv4-mapped IPv6 targets, while supporting explicit opt-in
/// exceptions solely for named built-in carrier Anycast endpoints.
/// </summary>
public static class DnsRebindingValidator
{
    private static readonly IReadOnlyList<CarrierAnycastEndpoint> BuiltinCarrierEndpoints = Array.AsReadOnly(
    [
        new CarrierAnycastEndpoint("403.online", "403.online Carrier Anycast", "10.202.10.0/24"),
        new CarrierAnycastEndpoint("dns.403.online", "403.online Carrier Anycast", "10.202.10.0/24"),
        new CarrierAnycastEndpoint("radar-game", "Radar Game Carrier Anycast", "10.202.10.0/24"),
        new CarrierAnycastEndpoint("radar.game", "Radar Game Carrier Anycast", "10.202.10.0/24")
    ]);

    private static readonly Dictionary<string, CidrRadixTrie<string>> CarrierTrieByEndpoint = BuildCarrierTries();

    /// <summary>
    /// Gets the registered named built-in carrier Anycast endpoints.
    /// </summary>
    public static IReadOnlyList<CarrierAnycastEndpoint> BuiltinCarrierAnycastEndpoints => BuiltinCarrierEndpoints;

    /// <summary>
    /// Validates resolved IP addresses for a query routed according to <paramref name="routeDecision"/>.
    /// </summary>
    public static DnsRebindingValidationResult ValidateAnswer(
        RouteDecision routeDecision,
        IEnumerable<IPAddress> resolvedAddresses,
        bool allowCarrierAnycastExceptions = false,
        string? namedCarrierEndpointId = null)
    {
        ArgumentNullException.ThrowIfNull(routeDecision);
        return ValidateAnswer(
            routeDecision.Zone,
            resolvedAddresses,
            allowCarrierAnycastExceptions,
            namedCarrierEndpointId);
    }

    /// <summary>
    /// Validates resolved IP addresses for a query in the given <paramref name="zone"/>.
    /// Zone 1 local/LAN/corporate queries permit private addresses; all public zones (Zone 2/3/4)
    /// reject private/bogon/loopback/CGNAT/link-local/ULA/IPv4-mapped private addresses unless
    /// explicitly permitted for a named built-in carrier Anycast endpoint.
    /// </summary>
    public static DnsRebindingValidationResult ValidateAnswer(
        RouteZone zone,
        IEnumerable<IPAddress> resolvedAddresses,
        bool allowCarrierAnycastExceptions = false,
        string? namedCarrierEndpointId = null)
    {
        ArgumentNullException.ThrowIfNull(resolvedAddresses);

        List<IPAddress> accepted = [];
        List<IPAddress> rejected = [];

        if (zone == RouteZone.Zone1LocalBypass)
        {
            foreach (IPAddress addr in resolvedAddresses)
            {
                if (addr is not null)
                {
                    accepted.Add(addr);
                }
            }

            return new DnsRebindingValidationResult(true, accepted, rejected, null);
        }

        foreach (IPAddress addr in resolvedAddresses)
        {
            if (addr is null)
            {
                continue;
            }

            IpInspectionResult inspection = IpSafetyInspector.Inspect(addr);
            if (inspection.IsPublicRoutable)
            {
                accepted.Add(addr);
                continue;
            }

            if (allowCarrierAnycastExceptions &&
                IsAllowedCarrierAnycastIp(inspection.NormalizedAddress, namedCarrierEndpointId))
            {
                accepted.Add(addr);
                continue;
            }

            rejected.Add(addr);
        }

        if (rejected.Count > 0)
        {
            return new DnsRebindingValidationResult(
                IsSafe: false,
                AcceptedAddresses: accepted,
                RejectedAddresses: rejected,
                RejectionReason: "DNS rebinding protection rejected private or bogon IP address(es) for non-Zone1 domain.");
        }

        return new DnsRebindingValidationResult(true, accepted, rejected, null);
    }

    /// <summary>
    /// Validates whether a DNS upstream endpoint IP is safe to contact (rejecting bogon/private IPs
    /// unless <paramref name="allowCarrierAnycastExceptions"/> is <c>true</c> and
    /// <paramref name="namedCarrierEndpointId"/> matches an explicit built-in carrier Anycast endpoint).
    /// </summary>
    public static bool IsAllowedResolverEndpointIp(
        IPAddress address,
        bool allowCarrierAnycastExceptions = false,
        string? namedCarrierEndpointId = null)
    {
        ArgumentNullException.ThrowIfNull(address);

        IpInspectionResult inspection = IpSafetyInspector.Inspect(address);
        if (inspection.IsPublicRoutable)
        {
            return true;
        }

        return allowCarrierAnycastExceptions &&
               IsAllowedCarrierAnycastIp(inspection.NormalizedAddress, namedCarrierEndpointId);
    }

    /// <summary>
    /// Checks whether <paramref name="address"/> belongs to the explicit CIDR of a named built-in
    /// carrier Anycast endpoint (e.g., <c>10.202.10.*</c> for <c>403.online</c> or <c>radar-game</c>).
    /// </summary>
    public static bool IsAllowedCarrierAnycastIp(IPAddress address, string? namedCarrierEndpointId)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (string.IsNullOrWhiteSpace(namedCarrierEndpointId))
        {
            return false;
        }

        string key = namedCarrierEndpointId.Trim();
        if (!CarrierTrieByEndpoint.TryGetValue(key, out CidrRadixTrie<string>? trie))
        {
            return false;
        }

        return trie.TryMatch(address, out _, unwrapIpv4Mapped: true);
    }

    private static Dictionary<string, CidrRadixTrie<string>> BuildCarrierTries()
    {
        Dictionary<string, CidrRadixTrie<string>> map = new(StringComparer.OrdinalIgnoreCase);
        foreach (CarrierAnycastEndpoint endpoint in BuiltinCarrierEndpoints)
        {
            CidrRadixTrieBuilder<string> builder = new();
            builder.TryAddCidr(endpoint.AllowedCidr, endpoint.EndpointId);
            map[endpoint.EndpointId] = builder.Build();
        }

        return map;
    }
}
