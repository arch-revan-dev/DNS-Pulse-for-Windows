using System.Net;
using DnsPulse.Core.Routing;

namespace DnsPulse.Core.Security;

/// <summary>
/// Migrated anti-direct CDN IP prefix detectors, geo-block redirect/body/header signatures,
/// and companion domain lookup tables from v1.5.3 (<c>AntiDirectIpFilter</c> &amp; <c>FourStageProber</c>).
/// </summary>
public static class AntiDirectAndGeoSignatures
{
    private const int MaxGeoBodyInspectLength = 8192;

    private static readonly string[] GoogleDirectCidrStrings =
    [
        "142.250.0.0/16",
        "142.251.0.0/16",
        "172.217.0.0/16",
        "172.253.0.0/16",
        "216.58.0.0/16",
        "216.239.0.0/16",
        "64.233.0.0/16",
        "74.125.0.0/16",
        "108.177.0.0/16",
        "192.178.0.0/16",
        "192.179.0.0/16",
        "199.36.0.0/16",
        "34.0.0.0/8",
        "35.0.0.0/8",
        "104.196.0.0/16",
        "104.199.0.0/16",
        "130.211.0.0/16",
        "173.194.0.0/16"
    ];

    private static readonly string[] AiAndVendorDirectCidrStrings =
    [
        "104.16.0.0/16",
        "104.17.0.0/16",
        "104.18.0.0/16",
        "104.19.0.0/16",
        "104.20.0.0/16",
        "104.21.0.0/16",
        "104.22.0.0/16",
        "172.64.0.0/16",
        "172.65.0.0/16",
        "172.66.0.0/16",
        "172.67.0.0/16",
        "188.114.0.0/16",
        "162.159.0.0/16",
        "13.107.0.0/16",
        "20.190.0.0/16",
        "40.126.0.0/16",
        "151.101.0.0/16",
        "35.186.0.0/16",
        "154.23.0.0/16"
    ];

    private static readonly string[] StrictGoogleAiExactDomains =
    [
        "aistudio.google.com",
        "gemini.google.com",
        "ai.studio",
        "ai.google.dev",
        "makersuite.google.com",
        "notebooklm.google.com",
        "notebooklm.google",
        "labs.google",
        "opal.google.com",
        "jules.google.com",
        "deepmind.google",
        "idx.google.com"
    ];

    private static readonly string[] StrictGoogleAiSubstrings =
    [
        "alkalimakersuite",
        "alkalicore",
        "generativelanguage.googleapis.com",
        "proactivebackend-pa.googleapis.com",
        "aisandbox-pa.googleapis.com",
        "robinfrontend-pa.googleapis.com",
        "geller-pa.googleapis.com"
    ];

    private static readonly string[] VendorDirectKeywords =
    [
        "chatgpt",
        "openai",
        "claude",
        "anthropic",
        "spotify",
        "xbox",
        "brawlstars",
        "supercell",
        "geforcenow",
        "grok",
        "perplexity",
        "copilot"
    ];

    private static readonly string[] GeoRedirectLocationMarkers =
    [
        "available-regions",
        "region-not-supported",
        "unavailable",
        "unsupported",
        "sorry/index",
        "blocked",
        "geo"
    ];

    private static readonly string[] GeoBodyMarkers =
    [
        "docs/available-regions",
        "available-regions",
        "not available in your region",
        "not available in your country",
        "unsupported region",
        "/sorry/index",
        "unusual traffic from your computer"
    ];

    private static readonly string[] GoogleAiResponseMarkers =
    [
        "accounts.google.com",
        "aistudio",
        "makersuite",
        "gstatic",
        "google",
        "gemini"
    ];

    private static readonly IReadOnlyList<string> CompanionAiStudioGemini = Array.AsReadOnly(
    [
        "alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "gemini.google.com"
    ]);

    private static readonly IReadOnlyList<string> CompanionGeminiAiStudio = Array.AsReadOnly(
    [
        "alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "aistudio.google.com"
    ]);

    private static readonly IReadOnlyList<string> CompanionChatGpt = Array.AsReadOnly(["api.openai.com", "auth.openai.com"]);
    private static readonly IReadOnlyList<string> CompanionClaude = Array.AsReadOnly(["api.anthropic.com"]);
    private static readonly IReadOnlyList<string> CompanionSpotify = Array.AsReadOnly(["spclient.wg.spotify.com", "apresolve.spotify.com"]);
    private static readonly IReadOnlyList<string> CompanionXbox = Array.AsReadOnly(["user.auth.xboxlive.com", "xsts.auth.xboxlive.com"]);

    private static readonly CidrRadixTrie<string> GoogleDirectTrie = BuildCidrTrie(GoogleDirectCidrStrings);
    private static readonly CidrRadixTrie<string> AiDirectTrie = BuildCidrTrie(AiAndVendorDirectCidrStrings);
    private static readonly IReadOnlyList<string> ReadOnlyGoogleDirectCidrs = Array.AsReadOnly(GoogleDirectCidrStrings);
    private static readonly IReadOnlyList<string> ReadOnlyAiDirectCidrs = Array.AsReadOnly(AiAndVendorDirectCidrStrings);

    /// <summary>
    /// Gets the 18 Google direct CDN CIDR prefixes flagged when probing Google AI/YouTube targets.
    /// </summary>
    public static IReadOnlyList<string> GoogleDirectCidrs => ReadOnlyGoogleDirectCidrs;

    /// <summary>
    /// Gets the 19 Cloudflare/Microsoft/Fastly/Cloud direct CDN CIDR prefixes flagged for non-Google AI, streaming, and gaming targets.
    /// </summary>
    public static IReadOnlyList<string> AiAndVendorDirectCidrs => ReadOnlyAiDirectCidrs;

    /// <summary>
    /// Determines whether <paramref name="domain"/> belongs to the strict Google AI surface.
    /// </summary>
    public static bool IsStrictGoogleAiDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        string trimmed = domain.Trim().TrimEnd('.');
        foreach (string exact in StrictGoogleAiExactDomains)
        {
            if (trimmed.Equals(exact, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (string token in StrictGoogleAiSubstrings)
        {
            if (trimmed.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether <paramref name="ipAddress"/> is a bogon or known direct unproxied CDN IP for <paramref name="domain"/>.
    /// </summary>
    public static bool IsDirectServiceIp(string? ipAddress, string? domain)
    {
        if (string.IsNullOrWhiteSpace(ipAddress) || !IPAddress.TryParse(ipAddress.AsSpan().Trim(), out IPAddress? parsed))
        {
            return true;
        }

        return IsDirectServiceIp(parsed, domain);
    }

    /// <summary>
    /// Determines whether <paramref name="address"/> is a bogon/private IP or a known direct unproxied CDN IP for <paramref name="domain"/>.
    /// </summary>
    public static bool IsDirectServiceIp(IPAddress address, string? domain)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IpSafetyInspector.IsPrivateOrBogon(address))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        string trimmedDomain = domain.Trim();
        if (IsStrictGoogleAiDomain(trimmedDomain) ||
            trimmedDomain.Contains("google", StringComparison.OrdinalIgnoreCase) ||
            trimmedDomain.Contains("youtube", StringComparison.OrdinalIgnoreCase))
        {
            return GoogleDirectTrie.TryMatch(address, out _, unwrapIpv4Mapped: true);
        }

        foreach (string keyword in VendorDirectKeywords)
        {
            if (trimmedDomain.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return AiDirectTrie.TryMatch(address, out _, unwrapIpv4Mapped: true);
            }
        }

        return false;
    }

    /// <summary>
    /// Detects HTTP status codes or <c>Location</c> redirect targets indicative of regional geo-blocking.
    /// </summary>
    public static bool IsGeoBlockedRedirect(int? statusCode, string? locationHeader)
    {
        if (statusCode is 403 or 451)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(locationHeader))
        {
            return false;
        }

        foreach (string marker in GeoRedirectLocationMarkers)
        {
            if (locationHeader.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Detects HTTP response headers commonly emitted on geo-blocked or anti-bot challenge responses.
    /// </summary>
    public static bool IsGeoBlockedResponseHeader(string headerName, string? headerValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(headerName);

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        if (headerName.Equals("Location", StringComparison.OrdinalIgnoreCase))
        {
            return IsGeoBlockedRedirect(null, headerValue);
        }

        if (headerName.Equals("CF-Mitigated", StringComparison.OrdinalIgnoreCase) &&
            headerValue.Contains("challenge", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (headerName.Equals("X-Geo-Block", StringComparison.OrdinalIgnoreCase) ||
            headerName.Equals("X-Country-Blocked", StringComparison.OrdinalIgnoreCase))
        {
            return headerValue.Equals("1", StringComparison.Ordinal) ||
                   headerValue.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   headerValue.Contains("blocked", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    /// <summary>
    /// Inspects up to the first 8 KiB of an HTTP response body for geo-restriction or anti-abuse block markers.
    /// </summary>
    public static bool IsGeoBlockedBody(string? bodySnippet)
    {
        if (string.IsNullOrWhiteSpace(bodySnippet))
        {
            return false;
        }

        ReadOnlySpan<char> snippet = bodySnippet.Length > MaxGeoBodyInspectLength
            ? bodySnippet.AsSpan(0, MaxGeoBodyInspectLength)
            : bodySnippet.AsSpan();

        foreach (string marker in GeoBodyMarkers)
        {
            if (snippet.Contains(marker.AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether an HTTP status code indicates an upstream proxy/gateway failure (<c>502, 503, 504, 521, 522, 524</c>).
    /// </summary>
    public static bool IsGatewayFailureStatusCode(int statusCode)
    {
        return statusCode is 502 or 503 or 504 or 521 or 522 or 524;
    }

    /// <summary>
    /// Verifies that a Google AI probe body or redirect contains genuine Google/AI Studio signatures.
    /// </summary>
    public static bool HasGoogleAiSignature(string? contentOrLocation)
    {
        if (string.IsNullOrWhiteSpace(contentOrLocation))
        {
            return false;
        }

        foreach (string marker in GoogleAiResponseMarkers)
        {
            if (contentOrLocation.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns companion RPC/auth domains that must also resolve through the proxy for a service to function cleanly.
    /// </summary>
    public static IReadOnlyList<string> GetCompanionDomains(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return [];
        }

        string trimmed = domain.Trim();
        if (trimmed.Contains("aistudio.google.com", StringComparison.OrdinalIgnoreCase))
        {
            return CompanionAiStudioGemini;
        }

        if (trimmed.Contains("gemini.google.com", StringComparison.OrdinalIgnoreCase))
        {
            return CompanionGeminiAiStudio;
        }

        if (trimmed.Contains("chatgpt.com", StringComparison.OrdinalIgnoreCase))
        {
            return CompanionChatGpt;
        }

        if (trimmed.Contains("claude.ai", StringComparison.OrdinalIgnoreCase))
        {
            return CompanionClaude;
        }

        if (trimmed.Contains("spotify.com", StringComparison.OrdinalIgnoreCase))
        {
            return CompanionSpotify;
        }

        if (trimmed.Contains("xboxlive.com", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Contains("xbox.com", StringComparison.OrdinalIgnoreCase))
        {
            return CompanionXbox;
        }

        return [];
    }

    private static CidrRadixTrie<string> BuildCidrTrie(string[] cidrs)
    {
        CidrRadixTrieBuilder<string> builder = new();
        foreach (string cidr in cidrs)
        {
            builder.TryAddCidr(cidr, cidr);
        }

        return builder.Build();
    }
}
