using System.Buffers;
using System.Net;

namespace DnsPulse.Core.Routing;

/// <summary>
/// Represents a parsed AdGuard DNS filtering rule.
/// </summary>
/// <param name="Domain">Normalized domain name without anchor tokens.</param>
/// <param name="IsException"><c>true</c> for <c>@@||</c> allow exceptions; <c>false</c> for block rules.</param>
/// <param name="MatchKind">Match behavior for the rule.</param>
public sealed record AdGuardRule(
    string Domain,
    bool IsException,
    DomainMatchKind MatchKind);

/// <summary>
/// Represents a parsed <c>HOSTS</c>-file mapping entry.
/// </summary>
/// <param name="Address">The target IP address.</param>
/// <param name="Domain">The normalized hostname.</param>
public sealed record HostEntry(
    IPAddress Address,
    string Domain);

/// <summary>
/// Represents a parsed GeoSite domain rule.
/// </summary>
/// <param name="Domain">Normalized domain name.</param>
/// <param name="MatchKind">Match behavior (<c>full:</c> -> <see cref="DomainMatchKind.Exact"/>, wildcard -> <see cref="DomainMatchKind.Wildcard"/>, default -> <see cref="DomainMatchKind.Suffix"/>).</param>
/// <param name="Attribute">Optional trailing attribute tag (e.g., <c>cn</c>, <c>ads</c>).</param>
public sealed record GeoSiteRule(
    string Domain,
    DomainMatchKind MatchKind,
    string? Attribute);

/// <summary>
/// Safe, allocation-conscious parsers for GeoSite domain lists, AdGuard DNS filter syntax, and <c>HOSTS</c> files.
/// </summary>
public static class RuleParsers
{
    private static readonly SearchValues<char> WhitespaceChars = SearchValues.Create(" \t");

    /// <summary>
    /// Parses all valid AdGuard DNS rules from multi-line filter text.
    /// Safely skips comments (<c>!</c>, <c>#</c>), metadata headers, element-hiding rules, regexes, and URL path rules.
    /// </summary>
    public static IReadOnlyList<AdGuardRule> ParseAdGuardRules(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        List<AdGuardRule> results = [];
        using StringReader reader = new(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (TryParseAdGuardLine(line.AsSpan(), out AdGuardRule? rule) && rule is not null)
            {
                results.Add(rule);
            }
        }

        return results;
    }

    /// <summary>
    /// Attempts to parse a single AdGuard DNS rule line (e.g., <c>||ads.example^$important</c> or <c>@@||allow.example^</c>).
    /// </summary>
    public static bool TryParseAdGuardLine(ReadOnlySpan<char> line, out AdGuardRule? rule)
    {
        rule = null;
        ReadOnlySpan<char> span = line.Trim();
        if (span.IsEmpty ||
            span[0] == '!' ||
            span[0] == '#' ||
            span[0] == '[' ||
            (span[0] == '/' && span.Length > 1 && span[^1] == '/'))
        {
            return false;
        }

        // Reject cosmetic / element hiding rules.
        if (span.Contains("##", StringComparison.Ordinal) ||
            span.Contains("#@#", StringComparison.Ordinal) ||
            span.Contains("#?#", StringComparison.Ordinal))
        {
            return false;
        }

        bool isException = false;
        if (span.StartsWith("@@", StringComparison.Ordinal))
        {
            isException = true;
            span = span[2..];
        }

        // Strip trailing $modifiers (e.g., $important, $dnstype=A), skipping unsupported modifier rules.
        int dollarIndex = span.IndexOf('$');
        if (dollarIndex >= 0)
        {
            ReadOnlySpan<char> modifiers = span[(dollarIndex + 1)..];
            if (modifiers.Contains("badfilter", StringComparison.OrdinalIgnoreCase) ||
                modifiers.Contains("dnsrewrite", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            span = span[..dollarIndex];
        }

        DomainMatchKind matchKind = DomainMatchKind.Suffix;
        if (span.StartsWith("||", StringComparison.Ordinal))
        {
            span = span[2..];
            matchKind = DomainMatchKind.Suffix;
        }
        else if (span.Length > 0 && span[0] == '|')
        {
            span = span[1..];
            matchKind = DomainMatchKind.Exact;
        }

        if (span.StartsWith("*.", StringComparison.Ordinal))
        {
            span = span[2..];
            matchKind = DomainMatchKind.Wildcard;
        }

        if (span.Length > 0 && (span[^1] == '^' || span[^1] == '|'))
        {
            span = span[..^1];
        }

        span = span.Trim();
        if (span.IsEmpty ||
            span.Contains('/') ||
            span.Contains('*') ||
            span.Contains('?') ||
            span.Contains(':'))
        {
            return false;
        }

        if (!DomainRadixTrie<byte>.TryNormalizeDomain(span, out string normalized) ||
            IPAddress.TryParse(normalized, out _))
        {
            return false;
        }

        rule = new AdGuardRule(normalized, isException, matchKind);
        return true;
    }

    /// <summary>
    /// Parses all valid <c>HOSTS</c>-file entries from multi-line text.
    /// </summary>
    public static IReadOnlyList<HostEntry> ParseHostsFile(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        List<HostEntry> results = [];
        using StringReader reader = new(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            ParseHostsLine(line.AsSpan(), results);
        }

        return results;
    }

    /// <summary>
    /// Parses a single <c>HOSTS</c>-file line and appends extracted <see cref="HostEntry"/> records to <paramref name="destination"/>.
    /// </summary>
    public static int ParseHostsLine(ReadOnlySpan<char> line, ICollection<HostEntry> destination)
    {
        ArgumentNullException.ThrowIfNull(destination);

        int commentIndex = line.IndexOf('#');
        ReadOnlySpan<char> effective = (commentIndex >= 0 ? line[..commentIndex] : line).Trim();
        if (effective.IsEmpty)
        {
            return 0;
        }

        int firstSep = effective.IndexOfAny(WhitespaceChars);
        if (firstSep <= 0)
        {
            return 0;
        }

        ReadOnlySpan<char> ipToken = effective[..firstSep];
        if (!IPAddress.TryParse(ipToken, out IPAddress? address))
        {
            return 0;
        }

        ReadOnlySpan<char> rest = effective[(firstSep + 1)..].TrimStart();
        int count = 0;
        while (!rest.IsEmpty)
        {
            int nextSep = rest.IndexOfAny(WhitespaceChars);
            ReadOnlySpan<char> hostToken = nextSep < 0 ? rest : rest[..nextSep];

            if (DomainRadixTrie<byte>.TryNormalizeDomain(hostToken, out string normalized) &&
                !IPAddress.TryParse(normalized, out _))
            {
                destination.Add(new HostEntry(address, normalized));
                count++;
            }

            if (nextSep < 0)
            {
                break;
            }

            rest = rest[(nextSep + 1)..].TrimStart();
        }

        return count;
    }

    /// <summary>
    /// Determines whether an IP address in a <c>HOSTS</c> file represents a standard blocking sinkhole
    /// (<c>0.0.0.0</c>, <c>127.0.0.1</c>, <c>::</c>, or <c>::1</c>).
    /// </summary>
    public static bool IsHostsSinkholeAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        return address.Equals(IPAddress.Any) ||
               address.Equals(IPAddress.Loopback) ||
               address.Equals(IPAddress.IPv6Any) ||
               address.Equals(IPAddress.IPv6Loopback);
    }

    /// <summary>
    /// Parses GeoSite domain list lines (<c>domain:</c>, <c>full:</c>, wildcard <c>*.</c>, bare domains, and <c>@attr</c> tags).
    /// Safely ignores <c>keyword:</c>, <c>regexp:</c>, comments, and malformed lines.
    /// </summary>
    public static IReadOnlyList<GeoSiteRule> ParseGeoSiteList(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        List<GeoSiteRule> results = [];
        using StringReader reader = new(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (TryParseGeoSiteLine(line.AsSpan(), out GeoSiteRule? rule) && rule is not null)
            {
                results.Add(rule);
            }
        }

        return results;
    }

    /// <summary>
    /// Attempts to parse a single GeoSite list line.
    /// </summary>
    public static bool TryParseGeoSiteLine(ReadOnlySpan<char> line, out GeoSiteRule? rule)
    {
        rule = null;
        int commentIndex = line.IndexOf('#');
        ReadOnlySpan<char> span = (commentIndex >= 0 ? line[..commentIndex] : line).Trim();
        if (span.IsEmpty)
        {
            return false;
        }

        // Extract optional trailing @attribute (e.g. "domain:google.com @cn").
        string? attribute = null;
        int atIndex = span.IndexOf('@');
        if (atIndex >= 0)
        {
            ReadOnlySpan<char> attrSpan = span[(atIndex + 1)..].Trim();
            if (!attrSpan.IsEmpty)
            {
                int spaceInAttr = attrSpan.IndexOfAny(WhitespaceChars);
                attribute = (spaceInAttr < 0 ? attrSpan : attrSpan[..spaceInAttr]).ToString();
            }

            span = span[..atIndex].Trim();
        }

        if (span.IsEmpty)
        {
            return false;
        }

        DomainMatchKind matchKind = DomainMatchKind.Suffix;
        if (span.StartsWith("full:", StringComparison.OrdinalIgnoreCase))
        {
            span = span[5..];
            matchKind = DomainMatchKind.Exact;
        }
        else if (span.StartsWith("domain:", StringComparison.OrdinalIgnoreCase))
        {
            span = span[7..];
            matchKind = DomainMatchKind.Suffix;
        }
        else if (span.StartsWith("keyword:", StringComparison.OrdinalIgnoreCase) ||
                 span.StartsWith("regexp:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        else if (span.StartsWith("*.", StringComparison.Ordinal))
        {
            span = span[2..];
            matchKind = DomainMatchKind.Wildcard;
        }

        span = span.Trim();
        if (!DomainRadixTrie<byte>.TryNormalizeDomain(span, out string normalized) ||
            IPAddress.TryParse(normalized, out _))
        {
            return false;
        }

        rule = new GeoSiteRule(normalized, matchKind, attribute);
        return true;
    }
}
