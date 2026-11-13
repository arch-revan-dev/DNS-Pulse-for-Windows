using System.Net;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public static class AntiDirectIpFilter
{
    private static readonly string[] GoogleDirectPrefixes =
    {
        "142.250.", "142.251.", "172.217.", "172.253.", "216.58.", "216.239.",
        "64.233.", "74.125.", "108.177.", "192.178.", "192.179.", "199.36.",
        "34.", "35.", "104.196.", "104.199.", "130.211.", "173.194."
    };

    private static readonly string[] AiDirectPrefixes =
    {
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
        "172.64.", "172.65.", "172.66.", "172.67.",
        "188.114.", "162.159.", "13.107.", "20.190.", "40.126.", "151.101.", "35.186.", "154.23."
    };

    public static bool IsValidNonBogonIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return false;
        if (!IPAddress.TryParse(ip.Trim(), out var addr))
            return false;
        return !IsBogonOrLoopback(ip.Trim());
    }

    public static bool IsBogonOrLoopback(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return true;
        if (IPAddress.IsLoopback(addr)) return true;
        var b = addr.GetAddressBytes();
        if (b.Length != 4) return false;
        return b[0] == 0
            || b[0] == 10
            || b[0] == 127
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            || b[0] >= 224;
    }

    public static bool IsDirectServiceIp(string ip, string domain)
    {
        var clean = ip.Trim();
        if (string.IsNullOrEmpty(clean) || IsBogonOrLoopback(clean))
            return true;

        var d = (domain ?? string.Empty).Trim().ToLowerInvariant();
        if (DynamicBypassRegistry.IsStrictGoogleAiDomain(d) || d.Contains("google") || d.Contains("youtube"))
        {
            return GoogleDirectPrefixes.Any(p => clean.StartsWith(p, StringComparison.Ordinal));
        }

        if (d.Contains("chatgpt") || d.Contains("openai") || d.Contains("claude") || d.Contains("anthropic")
            || d.Contains("spotify") || d.Contains("xbox") || d.Contains("brawlstars") || d.Contains("supercell")
            || d.Contains("geforcenow") || d.Contains("grok") || d.Contains("perplexity") || d.Contains("copilot"))
        {
            return AiDirectPrefixes.Any(p => clean.StartsWith(p, StringComparison.Ordinal));
        }

        return false;
    }

    public static bool IsGeoBlockedRedirect(int? statusCode, string? locationHeader)
    {
        if (statusCode is 403 or 451) return true;
        if (string.IsNullOrWhiteSpace(locationHeader)) return false;
        var loc = locationHeader.ToLowerInvariant();
        return loc.Contains("available-regions")
            || loc.Contains("region-not-supported")
            || loc.Contains("unavailable")
            || loc.Contains("unsupported")
            || loc.Contains("sorry/index")
            || loc.Contains("blocked")
            || loc.Contains("geo");
    }

    public static bool IsGeoBlockedBody(string? bodySnippet)
    {
        if (string.IsNullOrWhiteSpace(bodySnippet))
            return false;
        var body = bodySnippet.ToLowerInvariant();
        return body.Contains("docs/available-regions")
            || body.Contains("available-regions")
            || body.Contains("not available in your region")
            || body.Contains("not available in your country")
            || body.Contains("unsupported region")
            || body.Contains("/sorry/index")
            || body.Contains("unusual traffic from your computer");
    }

    public static string[] GetCompanionDomains(string domain)
    {
        var d = (domain ?? string.Empty).Trim().ToLowerInvariant();
        if (d.Contains("aistudio.google.com") || d.Contains("gemini.google.com"))
        {
            return new[]
            {
                "alkalimakersuite-pa.clients6.google.com",
                "generativelanguage.googleapis.com",
                d.Contains("aistudio") ? "gemini.google.com" : "aistudio.google.com"
            };
        }
        if (d.Contains("chatgpt.com")) return new[] { "api.openai.com", "auth.openai.com" };
        if (d.Contains("claude.ai")) return new[] { "api.anthropic.com" };
        if (d.Contains("spotify.com")) return new[] { "spclient.wg.spotify.com", "apresolve.spotify.com" };
        if (d.Contains("xboxlive.com") || d.Contains("xbox.com")) return new[] { "user.auth.xboxlive.com", "xsts.auth.xboxlive.com" };
        return Array.Empty<string>();
    }

    public static (BypassVerdict Verdict, string Reason) Classify(
        bool requiresBypass,
        IReadOnlyList<string> resolvedIps,
        bool? companionPassed,
        bool? port443Ok,
        int? httpStatus,
        string? redirectLocation,
        string targetDomain,
        bool timedOut,
        bool isGeoBlockedBody = false,
        string? customFailureDetail = null)
    {
        if (timedOut || resolvedIps.Count == 0)
        {
            return (BypassVerdict.DNS_TIMEOUT, "DNS-сервер не ответил или вернул пустой ответ (таймаут)");
        }

        if (!requiresBypass)
        {
            var note = port443Ok == true ? " · TLS 443 OK" : string.Empty;
            return (BypassVerdict.VERIFIED_PROXY_OK, $"Чистый пинг OK ({resolvedIps[0]}{note})");
        }

        if (resolvedIps.Any(ip => IsDirectServiceIp(ip, targetDomain)))
        {
            return (BypassVerdict.DIRECT_NO_PROXY, $"Прямой IP провайдера ({resolvedIps[0]}) — без Smart-DNS обхода");
        }

        if (IsGeoBlockedRedirect(httpStatus, redirectLocation) || isGeoBlockedBody)
        {
            var hint = !string.IsNullOrWhiteSpace(customFailureDetail)
                ? customFailureDetail
                : $"Геоблок / редирект (HTTP {httpStatus?.ToString() ?? "?"} → {redirectLocation ?? "available-regions"})";
            return (BypassVerdict.GEO_REDIRECT_BLOCKED, hint);
        }

        if (port443Ok == false)
        {
            var hint = !string.IsNullOrWhiteSpace(customFailureDetail)
                ? customFailureDetail
                : httpStatus is 502 or 503 or 504 or 521 or 522 or 524
                    ? $"Прокси {resolvedIps[0]} вернул HTTP {httpStatus} (шлюз недоступен)"
                    : $"Прокси-IP {resolvedIps[0]} не отвечает на HTTPS/TLS порт 443";
            return (BypassVerdict.PROXY_PORT_DEAD, hint);
        }

        if (companionPassed == false)
        {
            return (BypassVerdict.DIRECT_NO_PROXY, "Основной домен проксируется, но API-домены (RPC/Auth) отдаются напрямую");
        }

        var statusNote = httpStatus.HasValue ? $" · HTTP {httpStatus.Value}" : string.Empty;
        return (BypassVerdict.VERIFIED_PROXY_OK, $"Подтверждён рабочий обход ({resolvedIps[0]}{statusNote})");
    }
}
