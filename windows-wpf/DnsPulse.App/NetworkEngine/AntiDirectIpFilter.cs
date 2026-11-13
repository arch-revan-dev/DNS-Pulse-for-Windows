using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public static class AntiDirectIpFilter
{
    private static readonly string[] GoogleDirectPrefixes =
    [
        "142.250.", "142.251.", "172.217.", "172.253.", "216.58.", "192.178.",
        "74.125.", "64.233.", "108.177.", "209.85.", "216.239.", "66.102.", "66.249.", "72.14."
    ];

    private static readonly string[] AiDirectPrefixes =
    [
        "104.18.", "172.64.", "162.159.", "160.79.", "13.107.", "204.79."
    ];

    public static bool IsBogonOrLoopback(string ip)
    {
        var s = ip.Trim();
        if (string.IsNullOrEmpty(s)) return true;
        if (s is "0.0.0.0" or "127.0.0.1" or "::1" or "::") return true;
        if (s.StartsWith("127.") || s.StartsWith("10.") || s.StartsWith("169.254.") || s.StartsWith("192.168."))
            return true;
        var parts = s.Split('.');
        if (parts.Length == 4 && int.TryParse(parts[0], out int a) && int.TryParse(parts[1], out int b))
        {
            if (a == 172 && b is >= 16 and <= 31) return true;
        }
        return false;
    }

    public static bool IsDirectServiceIp(string ip, string domain)
    {
        var cleanIp = ip.Trim();
        var cleanDomain = domain.Trim().ToLowerInvariant();
        if (cleanDomain.Contains("google.com") || cleanDomain.Contains("googleapis.com") || cleanDomain.Contains("clients6.google.com"))
            return GoogleDirectPrefixes.Any(p => cleanIp.StartsWith(p, StringComparison.Ordinal));
        if (cleanDomain.Contains("chatgpt.com") || cleanDomain.Contains("openai.com") || cleanDomain.Contains("claude.ai") || cleanDomain.Contains("anthropic.com"))
            return AiDirectPrefixes.Any(p => cleanIp.StartsWith(p, StringComparison.Ordinal));
        return false;
    }

    public static bool IsGeoBlockedRedirect(int? statusCode, string? locationHeader)
    {
        if (statusCode is 403 or 451) return true;
        if (!string.IsNullOrWhiteSpace(locationHeader))
        {
            var loc = locationHeader.ToLowerInvariant();
            if (loc.Contains("/docs/available-regions") || loc.Contains("/sorry/index") || loc.Contains("unsupported-region"))
                return true;
        }
        return false;
    }

    public static string[] GetCompanionDomains(string domain)
    {
        var d = domain.Trim().ToLowerInvariant();
        if (d.Contains("gemini.google.com") || d.Contains("aistudio.google.com"))
            return ["alkalimakersuite-pa.clients6.google.com", "generativelanguage.googleapis.com"];
        if (d.Contains("spotify.com"))
            return ["spclient.wg.spotify.com", "apresolve.spotify.com"];
        if (d.Contains("xboxlive.com"))
            return ["user.auth.xboxlive.com", "xsts.auth.xboxlive.com"];
        return [];
    }

    public static (BypassVerdict Verdict, string Reason) Classify(
        bool requiresBypass,
        IReadOnlyList<string> resolvedIps,
        bool? companionPassed,
        bool? port443Ok,
        int? httpStatus,
        string? redirectLocation,
        string targetDomain,
        bool timedOut)
    {
        if (timedOut || resolvedIps.Count == 0)
            return (BypassVerdict.DNS_TIMEOUT, "Таймаут DNS или пустой ответ");

        var valid = resolvedIps.Where(ip => !IsBogonOrLoopback(ip)).ToList();
        if (valid.Count == 0)
            return (BypassVerdict.DNS_TIMEOUT, $"Заглушка / Bogon IP ({resolvedIps[0]})");

        if (requiresBypass)
        {
            if (valid.All(ip => IsDirectServiceIp(ip, targetDomain)))
                return (BypassVerdict.DIRECT_NO_PROXY, $"Прямой DNS (без обхода) • {valid[0]}");

            if (companionPassed == false)
                return (BypassVerdict.DIRECT_NO_PROXY, "API-домен пошёл напрямую (риск /available-regions)");
        }

        if (IsGeoBlockedRedirect(httpStatus, redirectLocation))
            return (BypassVerdict.GEO_REDIRECT_BLOCKED, $"Геоблок / редирект {httpStatus} {redirectLocation}".Trim());

        if (port443Ok == false || httpStatus is 502 or 504)
            return (BypassVerdict.PROXY_PORT_DEAD, $"Порт 443 / TLS недоступен ({httpStatus?.ToString() ?? "reset"})");

        return (BypassVerdict.VERIFIED_PROXY_OK, requiresBypass
            ? $"Доступ открыт • 443 OK ({valid[0]})"
            : $"Резолв OK • 443 OK ({valid[0]})");
    }
}
