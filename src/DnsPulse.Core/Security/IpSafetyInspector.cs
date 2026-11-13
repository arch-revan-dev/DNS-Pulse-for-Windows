using System.Net;
using System.Net.Sockets;

namespace DnsPulse.Core.Security;

/// <summary>
/// Categorizes an IPv4 or IPv6 address according to routability and RFC bogon/private reservations.
/// </summary>
public enum IpAddressCategory
{
    /// <summary>Globally routable public unicast address.</summary>
    Public = 0,

    /// <summary>Unspecified address (<c>0.0.0.0/8</c> or <c>::/128</c>).</summary>
    Unspecified = 1,

    /// <summary>Loopback address (<c>127.0.0.0/8</c> or <c>::1/128</c>).</summary>
    Loopback = 2,

    /// <summary>RFC 1918 private address (<c>10.0.0.0/8</c>, <c>172.16.0.0/12</c>, <c>192.168.0.0/16</c>).</summary>
    PrivateRfc1918 = 3,

    /// <summary>RFC 6598 Carrier-Grade NAT shared space (<c>100.64.0.0/10</c>).</summary>
    CarrierGradeNat = 4,

    /// <summary>Link-local address (<c>169.254.0.0/16</c> or <c>fe80::/10</c>).</summary>
    LinkLocal = 5,

    /// <summary>RFC 4193 IPv6 Unique Local Address (<c>fc00::/7</c>).</summary>
    UniqueLocalIpv6 = 6,

    /// <summary>Multicast address (<c>224.0.0.0/4</c> or <c>ff00::/8</c>).</summary>
    Multicast = 7,

    /// <summary>Documentation, benchmarking, broadcast, or other special-use/bogon space.</summary>
    SpecialUseOrBogon = 8
}

/// <summary>
/// Detailed classification result produced by <see cref="IpSafetyInspector"/>.
/// </summary>
/// <param name="OriginalAddress">The inspected <see cref="IPAddress"/> as supplied.</param>
/// <param name="NormalizedAddress">The unwrapped IPv4 address if IPv4-mapped IPv6; otherwise <paramref name="OriginalAddress"/>.</param>
/// <param name="Category">The classified address category.</param>
/// <param name="IsPublicRoutable"><c>true</c> only when the normalized address is globally routable public unicast.</param>
/// <param name="IsPrivateOrBogon"><c>true</c> when the address is private, loopback, link-local, CGNAT, ULA, multicast, or bogon.</param>
/// <param name="WasIpv4MappedIpv6"><c>true</c> when <paramref name="OriginalAddress"/> was an <c>::ffff:a.b.c.d</c> IPv4-mapped IPv6 address.</param>
public sealed record IpInspectionResult(
    IPAddress OriginalAddress,
    IPAddress NormalizedAddress,
    IpAddressCategory Category,
    bool IsPublicRoutable,
    bool IsPrivateOrBogon,
    bool WasIpv4MappedIpv6);

/// <summary>
/// Inspects IPv4, IPv6, and IPv4-mapped IPv6 addresses for bogons, private networks, loopback, CGNAT,
/// link-local, multicast, and reserved ranges.
/// </summary>
public static class IpSafetyInspector
{
    /// <summary>
    /// Classifies an <see cref="IPAddress"/>, unwrapping IPv4-mapped IPv6 addresses (<c>::ffff:a.b.c.d</c>)
    /// via <see cref="IPAddress.IsIPv4MappedToIPv6"/> and <see cref="IPAddress.MapToIPv4"/>.
    /// </summary>
    public static IpInspectionResult Inspect(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            IPAddress mapped = address.MapToIPv4();
            IpAddressCategory mappedCategory = ClassifyIpv4(mapped);
            bool mappedPublic = mappedCategory == IpAddressCategory.Public;
            return new IpInspectionResult(
                address,
                mapped,
                mappedCategory,
                IsPublicRoutable: mappedPublic,
                IsPrivateOrBogon: !mappedPublic,
                WasIpv4MappedIpv6: true);
        }

        IpAddressCategory category = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => ClassifyIpv4(address),
            AddressFamily.InterNetworkV6 => ClassifyIpv6(address),
            _ => IpAddressCategory.SpecialUseOrBogon
        };

        bool isPublic = category == IpAddressCategory.Public;
        return new IpInspectionResult(
            address,
            address,
            category,
            IsPublicRoutable: isPublic,
            IsPrivateOrBogon: !isPublic,
            WasIpv4MappedIpv6: false);
    }

    /// <summary>
    /// Attempts to parse and classify an IP address string.
    /// </summary>
    public static bool TryInspect(string? ipAddress, out IpInspectionResult? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            return false;
        }

        if (!IPAddress.TryParse(ipAddress.AsSpan().Trim(), out IPAddress? parsed))
        {
            return false;
        }

        result = Inspect(parsed);
        return true;
    }

    /// <summary>
    /// Returns <c>true</c> if <paramref name="address"/> is globally routable public unicast.
    /// </summary>
    public static bool IsPublicRoutable(IPAddress address)
    {
        return Inspect(address).IsPublicRoutable;
    }

    /// <summary>
    /// Returns <c>true</c> if <paramref name="ipAddress"/> parses cleanly and is globally routable public unicast.
    /// </summary>
    public static bool IsPublicRoutable(string? ipAddress)
    {
        return TryInspect(ipAddress, out IpInspectionResult? result) && result is { IsPublicRoutable: true };
    }

    /// <summary>
    /// Returns <c>true</c> if <paramref name="address"/> is private, loopback, CGNAT, link-local, multicast, or bogon.
    /// </summary>
    public static bool IsPrivateOrBogon(IPAddress address)
    {
        return Inspect(address).IsPrivateOrBogon;
    }

    /// <summary>
    /// Returns <c>true</c> if <paramref name="ipAddress"/> is invalid, private, loopback, CGNAT, link-local, multicast, or bogon.
    /// </summary>
    public static bool IsPrivateOrBogon(string? ipAddress)
    {
        return !TryInspect(ipAddress, out IpInspectionResult? result) || result is not { IsPublicRoutable: true };
    }

    private static IpAddressCategory ClassifyIpv4(IPAddress address)
    {
        Span<byte> b = stackalloc byte[4];
        if (!address.TryWriteBytes(b, out int written) || written != 4)
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        if (b[0] == 0)
        {
            return IpAddressCategory.Unspecified;
        }

        if (b[0] == 127)
        {
            return IpAddressCategory.Loopback;
        }

        if (b[0] == 10)
        {
            return IpAddressCategory.PrivateRfc1918;
        }

        if (b[0] == 100 && b[1] is >= 64 and <= 127)
        {
            return IpAddressCategory.CarrierGradeNat;
        }

        if (b[0] == 169 && b[1] == 254)
        {
            return IpAddressCategory.LinkLocal;
        }

        if (b[0] == 172 && b[1] is >= 16 and <= 31)
        {
            return IpAddressCategory.PrivateRfc1918;
        }

        if (b[0] == 192 && b[1] == 168)
        {
            return IpAddressCategory.PrivateRfc1918;
        }

        if (b[0] is >= 224 and <= 239)
        {
            return IpAddressCategory.Multicast;
        }

        if (b[0] >= 240)
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        // RFC 6890 / IETF special-purpose IPv4 blocks
        if ((b[0] == 192 && b[1] == 0 && b[2] == 0) ||
            (b[0] == 192 && b[1] == 0 && b[2] == 2) ||
            (b[0] == 198 && b[1] is 18 or 19) ||
            (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
            (b[0] == 203 && b[1] == 0 && b[2] == 113))
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        return IpAddressCategory.Public;
    }

    private static IpAddressCategory ClassifyIpv6(IPAddress address)
    {
        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out int written) || written != 16)
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        bool top96Zero = true;
        for (int i = 0; i < 12; i++)
        {
            if (b[i] != 0)
            {
                top96Zero = false;
                break;
            }
        }

        if (top96Zero)
        {
            if (b[12] == 0 && b[13] == 0 && b[14] == 0)
            {
                if (b[15] == 0)
                {
                    return IpAddressCategory.Unspecified;
                }

                if (b[15] == 1)
                {
                    return IpAddressCategory.Loopback;
                }
            }

            // Deprecated IPv4-compatible IPv6 (::/96)
            return IpAddressCategory.SpecialUseOrBogon;
        }

        // Multicast ff00::/8
        if (b[0] == 0xFF)
        {
            return IpAddressCategory.Multicast;
        }

        // Unique Local Address fc00::/7
        if ((b[0] & 0xFE) == 0xFC)
        {
            return IpAddressCategory.UniqueLocalIpv6;
        }

        // Link-Local fe80::/10
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
        {
            return IpAddressCategory.LinkLocal;
        }

        // Deprecated Site-Local fec0::/10
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0)
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        // Documentation 2001:db8::/32
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8)
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        // Discard-Only 100::/64 (RFC 6666)
        if (b[0] == 0x01 && b[1] == 0x00 &&
            b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0)
        {
            return IpAddressCategory.SpecialUseOrBogon;
        }

        return IpAddressCategory.Public;
    }
}
