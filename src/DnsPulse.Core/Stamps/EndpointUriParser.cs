using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace DnsPulse.Core.Stamps;

/// <summary>
/// Categorizes a validated and normalized DNS endpoint.
/// </summary>
public enum EndpointKind
{
    /// <summary>DNSCrypt v2 <c>sdns://</c> stamp.</summary>
    DnsStamp = 0,

    /// <summary>DNS-over-HTTPS (<c>https://</c>).</summary>
    DoH = 1,

    /// <summary>DNS-over-TLS (<c>tls://</c>).</summary>
    DoT = 2,

    /// <summary>DNS-over-QUIC (<c>quic://</c>).</summary>
    DoQ = 3,

    /// <summary>Oblivious DoH (<c>odoh://</c>).</summary>
    ObliviousDoH = 4,

    /// <summary>SNI/Smart-DNS proxy endpoint (<c>smartproxy://</c>).</summary>
    SmartProxy = 5,

    /// <summary>Plain IPv4 or IPv6 DNS endpoint.</summary>
    PlainIp = 6,

    /// <summary>Plaintext <c>http://</c> endpoint restricted to loopback addresses.</summary>
    PlainHttpLoopback = 7
}

/// <summary>
/// Represents a validated and normalized DNS endpoint.
/// </summary>
public sealed record ParsedEndpoint
{
    /// <summary>Gets the endpoint kind.</summary>
    public EndpointKind Kind { get; init; }

    /// <summary>Gets the canonical normalized endpoint string.</summary>
    public string NormalizedEndpoint { get; init; } = string.Empty;

    /// <summary>Gets the parsed <see cref="Uri"/> when the endpoint uses a hierarchical URI scheme.</summary>
    public Uri? ParsedUri { get; init; }

    /// <summary>Gets the unbracketed host name or canonical IP address.</summary>
    public string Host { get; init; } = string.Empty;

    /// <summary>Gets the normalized network port.</summary>
    public int Port { get; init; }

    /// <summary>Gets the optional HTTP path and query string.</summary>
    public string? Path { get; init; }

    /// <summary>Gets the decoded <see cref="DnsStamp"/> when <see cref="Kind"/> is <see cref="EndpointKind.DnsStamp"/>.</summary>
    public DnsStamp? Stamp { get; init; }
}

/// <summary>
/// Validates and normalizes DNS endpoints across <c>sdns://</c>, <c>https://</c>, <c>tls://</c>,
/// <c>quic://</c>, <c>odoh://</c>, <c>smartproxy://</c>, loopback <c>http://</c>, and raw IPv4/IPv6 addresses.
/// </summary>
public static class EndpointUriParser
{
    private static readonly SearchValues<char> AuthorityTerminators = SearchValues.Create(['/', '?', '#']);

    /// <summary>
    /// Validates and normalizes an endpoint string.
    /// </summary>
    /// <param name="endpoint">The raw endpoint string.</param>
    /// <returns>The validated <see cref="ParsedEndpoint"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="endpoint"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="endpoint"/> is malformed, insecure, or contains credentials.</exception>
    public static ParsedEndpoint Parse(string endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        if (!TryParseInternal(endpoint, out ParsedEndpoint? result, out string? error))
        {
            throw new FormatException(error);
        }

        return result;
    }

    /// <summary>
    /// Attempts to validate and normalize an endpoint string without throwing.
    /// </summary>
    /// <param name="endpoint">The raw endpoint string.</param>
    /// <param name="result">When this method returns <see langword="true"/>, contains the parsed endpoint.</param>
    /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
    public static bool TryParse(string? endpoint, [NotNullWhen(true)] out ParsedEndpoint? result)
    {
        if (endpoint is null)
        {
            result = null;
            return false;
        }

        return TryParseInternal(endpoint, out result, out _);
    }

    private static bool TryParseInternal(
        string endpoint,
        [NotNullWhen(true)] out ParsedEndpoint? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;

        string trimmed = endpoint.Trim();
        if (trimmed.Length == 0)
        {
            error = "Endpoint string cannot be empty or whitespace.";
            return false;
        }

        for (int i = 0; i < trimmed.Length; i++)
        {
            if (char.IsWhiteSpace(trimmed[i]))
            {
                error = "Endpoint string cannot contain embedded whitespace.";
                return false;
            }
        }

        if (trimmed.StartsWith(DnsStampCodec.SchemePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return TryParseStampEndpoint(trimmed, out result, out error);
        }

        int schemeSeparatorIndex = trimmed.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparatorIndex >= 0)
        {
            return TryParseUriEndpoint(trimmed, schemeSeparatorIndex, out result, out error);
        }

        if (trimmed.Contains(':', StringComparison.Ordinal) || trimmed.Contains('.', StringComparison.Ordinal))
        {
            return TryParseRawIpEndpoint(trimmed, out result, out error);
        }

        error = $"Unsupported or malformed endpoint '{trimmed}'.";
        return false;
    }

    private static bool TryParseStampEndpoint(
        string trimmed,
        [NotNullWhen(true)] out ParsedEndpoint? result,
        [NotNullWhen(false)] out string? error)
    {
        if (!DnsStampCodec.TryParse(trimmed, out DnsStamp? stamp))
        {
            result = null;
            error = "Malformed 'sdns://' DNS stamp.";
            return false;
        }

        int defaultPort = stamp.Protocol switch
        {
            DnsStampProtocol.Plain => 53,
            DnsStampProtocol.DoT or DnsStampProtocol.DoQ => 853,
            _ => 443
        };

        string host = string.Empty;
        int port = defaultPort;
        string rawHostSource = !string.IsNullOrEmpty(stamp.HostName)
            ? stamp.HostName
            : stamp.ServerAddress;

        if (!string.IsNullOrEmpty(rawHostSource))
        {
            TrySplitHostAndPort(rawHostSource, defaultPort, out host, out port);
        }

        result = new ParsedEndpoint
        {
            Kind = EndpointKind.DnsStamp,
            NormalizedEndpoint = DnsStampCodec.Encode(stamp),
            ParsedUri = null,
            Host = host,
            Port = port,
            Path = string.IsNullOrEmpty(stamp.Path) ? null : stamp.Path,
            Stamp = stamp
        };
        error = null;
        return true;
    }

    private static bool TryParseUriEndpoint(
        string trimmed,
        int schemeSeparatorIndex,
        [NotNullWhen(true)] out ParsedEndpoint? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;

        if (schemeSeparatorIndex == 0)
        {
            error = "Endpoint URI is missing a scheme.";
            return false;
        }

        int authorityStart = schemeSeparatorIndex + 3;
        ReadOnlySpan<char> afterScheme = trimmed.AsSpan(authorityStart);
        int authorityLength = afterScheme.IndexOfAny(AuthorityTerminators);
        ReadOnlySpan<char> authoritySpan = authorityLength >= 0
            ? afterScheme[..authorityLength]
            : afterScheme;

        if (authoritySpan.IsEmpty)
        {
            error = "Endpoint URI is missing a host.";
            return false;
        }

        if (authoritySpan.Contains('@'))
        {
            error = "Endpoint URI must not contain embedded userinfo credentials.";
            return false;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri))
        {
            error = $"Malformed endpoint URI '{trimmed}'.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            error = "Endpoint URI must not contain embedded userinfo credentials.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Fragment) || trimmed.Contains('#', StringComparison.Ordinal))
        {
            error = "Endpoint URI must not contain a fragment.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(uri.DnsSafeHost) || uri.HostNameType == UriHostNameType.Unknown)
        {
            error = "Endpoint URI has an invalid or missing host.";
            return false;
        }

        string scheme;
        EndpointKind kind;
        int defaultPort;
        bool allowPathAndQuery;

        if (string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            scheme = "https";
            kind = EndpointKind.DoH;
            defaultPort = 443;
            allowPathAndQuery = true;
        }
        else if (string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            if (!IsLoopbackHost(uri.DnsSafeHost))
            {
                error = "Plaintext 'http://' endpoints are only permitted for loopback addresses.";
                return false;
            }

            scheme = "http";
            kind = EndpointKind.PlainHttpLoopback;
            defaultPort = 80;
            allowPathAndQuery = true;
        }
        else if (string.Equals(uri.Scheme, "tls", StringComparison.OrdinalIgnoreCase))
        {
            scheme = "tls";
            kind = EndpointKind.DoT;
            defaultPort = 853;
            allowPathAndQuery = false;
        }
        else if (string.Equals(uri.Scheme, "quic", StringComparison.OrdinalIgnoreCase))
        {
            scheme = "quic";
            kind = EndpointKind.DoQ;
            defaultPort = 853;
            allowPathAndQuery = false;
        }
        else if (string.Equals(uri.Scheme, "odoh", StringComparison.OrdinalIgnoreCase))
        {
            scheme = "odoh";
            kind = EndpointKind.ObliviousDoH;
            defaultPort = 443;
            allowPathAndQuery = true;
        }
        else if (string.Equals(uri.Scheme, "smartproxy", StringComparison.OrdinalIgnoreCase))
        {
            scheme = "smartproxy";
            kind = EndpointKind.SmartProxy;
            defaultPort = 443;
            allowPathAndQuery = false;
        }
        else
        {
            error = $"Unsupported endpoint URI scheme '{uri.Scheme}'.";
            return false;
        }

        if (uri.Port == 0)
        {
            error = "Endpoint port 0 is out of range.";
            return false;
        }

        int port = uri.Port > 0 ? uri.Port : defaultPort;
        if (port is < 1 or > 65535)
        {
            error = string.Create(CultureInfo.InvariantCulture, $"Endpoint port {port} is out of range.");
            return false;
        }

        if (!TryNormalizeHost(uri.DnsSafeHost, uri.HostNameType, out string normalizedHost, out bool isIpv6))
        {
            error = $"Endpoint host '{uri.DnsSafeHost}' is invalid.";
            return false;
        }

        if (!allowPathAndQuery
            && ((uri.AbsolutePath.Length > 0 && !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal))
                || !string.IsNullOrEmpty(uri.Query)))
        {
            error = $"Scheme '{scheme}://' does not accept a path or query component.";
            return false;
        }

        string formattedAuthorityHost = isIpv6 ? $"[{normalizedHost}]" : normalizedHost;
        string portSuffix = port == defaultPort
            ? string.Empty
            : string.Create(CultureInfo.InvariantCulture, $":{port}");

        string? normalizedPath = null;
        string normalizedEndpoint;

        if (allowPathAndQuery)
        {
            normalizedPath = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
            normalizedEndpoint = string.Concat(scheme, "://", formattedAuthorityHost, portSuffix, normalizedPath);
        }
        else
        {
            normalizedEndpoint = string.Concat(scheme, "://", formattedAuthorityHost, portSuffix);
        }

        result = new ParsedEndpoint
        {
            Kind = kind,
            NormalizedEndpoint = normalizedEndpoint,
            ParsedUri = new Uri(normalizedEndpoint, UriKind.Absolute),
            Host = normalizedHost,
            Port = port,
            Path = normalizedPath,
            Stamp = null
        };
        error = null;
        return true;
    }

    private static bool TryParseRawIpEndpoint(
        string trimmed,
        [NotNullWhen(true)] out ParsedEndpoint? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        const int defaultPort = 53;
        int port = defaultPort;
        IPAddress? address;

        if (trimmed[0] == '[')
        {
            int closeBracket = trimmed.IndexOf(']', StringComparison.Ordinal);
            if (closeBracket <= 1)
            {
                error = $"Malformed bracketed IPv6 endpoint '{trimmed}'.";
                return false;
            }

            string ipv6Part = trimmed[1..closeBracket];
            if (!IPAddress.TryParse(ipv6Part, out address)
                || address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                error = $"Invalid IPv6 address '{ipv6Part}'.";
                return false;
            }

            if (closeBracket < trimmed.Length - 1)
            {
                if (trimmed[closeBracket + 1] != ':')
                {
                    error = $"Unexpected trailing characters in endpoint '{trimmed}'.";
                    return false;
                }

                ReadOnlySpan<char> portSpan = trimmed.AsSpan(closeBracket + 2);
                if (!TryParsePort(portSpan, out port))
                {
                    error = $"Invalid port in endpoint '{trimmed}'.";
                    return false;
                }
            }
        }
        else if (IPAddress.TryParse(trimmed, out address))
        {
            if (address.AddressFamily == AddressFamily.InterNetwork && trimmed.AsSpan().Count('.') != 3)
            {
                error = $"IPv4 address '{trimmed}' must be in dotted-quad notation.";
                return false;
            }
        }
        else
        {
            int colonIndex = trimmed.LastIndexOf(':');
            if (colonIndex <= 0 || colonIndex == trimmed.Length - 1)
            {
                error = $"Invalid IP endpoint '{trimmed}'.";
                return false;
            }

            string hostPart = trimmed[..colonIndex];
            ReadOnlySpan<char> portSpan = trimmed.AsSpan(colonIndex + 1);

            if (!IPAddress.TryParse(hostPart, out address)
                || address.AddressFamily != AddressFamily.InterNetwork
                || hostPart.AsSpan().Count('.') != 3
                || !TryParsePort(portSpan, out port))
            {
                error = $"Invalid IP:port endpoint '{trimmed}'.";
                return false;
            }
        }

        string canonicalIp = address.ToString();
        bool isIpv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        string normalizedEndpoint = isIpv6
            ? (port == defaultPort
                ? $"[{canonicalIp}]"
                : string.Create(CultureInfo.InvariantCulture, $"[{canonicalIp}]:{port}"))
            : (port == defaultPort
                ? canonicalIp
                : string.Create(CultureInfo.InvariantCulture, $"{canonicalIp}:{port}"));

        result = new ParsedEndpoint
        {
            Kind = EndpointKind.PlainIp,
            NormalizedEndpoint = normalizedEndpoint,
            ParsedUri = null,
            Host = canonicalIp,
            Port = port,
            Path = null,
            Stamp = null
        };
        error = null;
        return true;
    }

    private static bool TryNormalizeHost(
        string dnsSafeHost,
        UriHostNameType hostNameType,
        out string normalizedHost,
        out bool isIpv6)
    {
        if (hostNameType == UriHostNameType.IPv6)
        {
            if (!IPAddress.TryParse(dnsSafeHost, out IPAddress? v6)
                || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                normalizedHost = string.Empty;
                isIpv6 = false;
                return false;
            }

            normalizedHost = v6.ToString();
            isIpv6 = true;
            return true;
        }

        if (hostNameType == UriHostNameType.IPv4)
        {
            if (!IPAddress.TryParse(dnsSafeHost, out IPAddress? v4)
                || v4.AddressFamily != AddressFamily.InterNetwork)
            {
                normalizedHost = string.Empty;
                isIpv6 = false;
                return false;
            }

            normalizedHost = v4.ToString();
            isIpv6 = false;
            return true;
        }

        string trimmedHost = dnsSafeHost.TrimEnd('.');
        if (trimmedHost.Length == 0 || trimmedHost.Contains("..", StringComparison.Ordinal))
        {
            normalizedHost = string.Empty;
            isIpv6 = false;
            return false;
        }

        normalizedHost = string.Create(
            trimmedHost.Length,
            trimmedHost,
            static (Span<char> destination, string source) =>
            {
                for (int i = 0; i < source.Length; i++)
                {
                    destination[i] = char.ToLowerInvariant(source[i]);
                }
            });
        isIpv6 = false;
        return true;
    }

    private static bool IsLoopbackHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host, out IPAddress? address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return IPAddress.IsLoopback(address);
    }

    private static bool TryParsePort(ReadOnlySpan<char> portSpan, out int port)
    {
        if (portSpan.IsEmpty)
        {
            port = 0;
            return false;
        }

        for (int i = 0; i < portSpan.Length; i++)
        {
            if (portSpan[i] is < '0' or > '9')
            {
                port = 0;
                return false;
            }
        }

        return int.TryParse(portSpan, NumberStyles.None, CultureInfo.InvariantCulture, out port)
            && port is >= 1 and <= 65535;
    }

    private static void TrySplitHostAndPort(string value, int defaultPort, out string host, out int port)
    {
        if (value.StartsWith('['))
        {
            int close = value.IndexOf(']', StringComparison.Ordinal);
            if (close > 1)
            {
                host = value[1..close];
                if (close + 2 <= value.Length - 1
                    && value[close + 1] == ':'
                    && TryParsePort(value.AsSpan(close + 2), out int parsedPort))
                {
                    port = parsedPort;
                    return;
                }

                port = defaultPort;
                return;
            }
        }

        int firstColon = value.IndexOf(':', StringComparison.Ordinal);
        int lastColon = value.LastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon
            && TryParsePort(value.AsSpan(lastColon + 1), out int splitPort))
        {
            host = value[..lastColon];
            port = splitPort;
            return;
        }

        host = value;
        port = defaultPort;
    }
}
