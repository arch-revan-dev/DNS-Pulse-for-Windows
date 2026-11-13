using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;

namespace DnsPulse.App.NetworkEngine;

/// <summary>
/// Maintains the built-in and dynamically synced registry of geo-restricted / AI / streaming / gaming domains
/// that must route through the Smart-DNS or Smart-Proxy upstream rather than direct ISP / 1.1.1.1 DNS.
/// Mirrors Android DynamicBypassRegistry so the protected domain set is NEVER empty even offline.
/// </summary>
public static class DynamicBypassRegistry
{
    public static readonly string[] BuiltinAiDomains =
    {
        "gemini.google.com",
        "aistudio.google.com",
        "ai.studio",
        "alkalimakersuite-pa.clients6.google.com",
        "alkalicore-pa.clients6.google.com",
        "webchannel-alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "geller-pa.googleapis.com",
        "generativeai.google",
        "makersuite.google.com",
        "ai.google.dev",
        "gemini.gstatic.com",
        "bard.google.com",
        "proactivebackend-pa.googleapis.com",
        "notebooklm.google.com",
        "notebooklm.google",
        "labs.google",
        "opal.google.com",
        "jules.google.com",
        "aisandbox-pa.googleapis.com",
        "robinfrontend-pa.googleapis.com",
        "deepmind.google",
        "idx.google.com",
        "stitch.withgoogle.com",
        "clients6.google.com",
        "chatgpt.com",
        "openai.com",
        "api.openai.com",
        "auth.openai.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "claude.ai",
        "anthropic.com",
        "api.anthropic.com",
        "grok.com",
        "x.ai",
        "copilot.microsoft.com",
        "sydney.bing.com",
        "perplexity.ai",
        "elevenlabs.io",
        "api.elevenlabs.io",
        "notion.so",
        "canva.com",
        "figma.com",
        "deepl.com",
        "plugins.jetbrains.com",
        "account.jetbrains.com",
        "copilot-proxy.githubusercontent.com",
        "cursor.sh",
        "cursor.com",
        "codeium.com",
        "huggingface.co"
    };

    public static readonly string[] BuiltinStreamingDomains =
    {
        "spotify.com",
        "open.spotify.com",
        "spclient.wg.spotify.com",
        "apresolve.spotify.com",
        "audio-ak-spotify-com.akamaized.net",
        "soundcloud.com",
        "api-v2.soundcloud.com",
        "tidal.com",
        "deezer.com",
        "twitch.tv",
        "gql.twitch.tv",
        "netflix.com"
    };

    public static readonly string[] BuiltinGamingDomains =
    {
        "xboxlive.com",
        "xbox.com",
        "login.live.com",
        "user.auth.xboxlive.com",
        "xsts.auth.xboxlive.com",
        "title.mgt.xboxlive.com",
        "brawlstars.com",
        "supercell.com",
        "store.supercell.com",
        "game.brawlstarsgame.com",
        "clashroyale.com",
        "clashofclans.com",
        "nvidiagrid.net",
        "geforcenow.com",
        "play.geforcenow.com",
        "playstation.com",
        "playstation.net",
        "parsec.app"
    };

    private static readonly ConcurrentDictionary<string, byte> DynamicDomains = new(StringComparer.OrdinalIgnoreCase);

    static DynamicBypassRegistry()
    {
        SeedBuiltins();
    }

    private static void SeedBuiltins()
    {
        foreach (var d in BuiltinAiDomains)
            DynamicDomains[d] = 0;
        foreach (var d in BuiltinStreamingDomains)
            DynamicDomains[d] = 0;
        foreach (var d in BuiltinGamingDomains)
            DynamicDomains[d] = 0;
    }

    public static bool IsValidDomainName(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
            return false;
        var d = candidate.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.Length < 4 || d.Length > 253 || !d.Contains('.') || d.StartsWith('.') || d.EndsWith('.'))
            return false;
        if (d == "localhost" || d.EndsWith(".local") || d.EndsWith(".arpa") || d.EndsWith(".internal"))
            return false;
        if (System.Net.IPAddress.TryParse(d, out _))
            return false;

        foreach (var ch in d)
        {
            if (!(char.IsAsciiLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_'))
                return false;
        }
        return true;
    }

    public static int ClassifyAndAddDomains(IEnumerable<string> domains)
    {
        int added = 0;
        foreach (var raw in domains)
        {
            var d = (raw ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            if (!IsValidDomainName(d))
                continue;
            if (DynamicDomains.TryAdd(d, 0))
                added++;
        }
        return added;
    }

    public static IReadOnlyCollection<string> GetAllProtectedDomains() =>
        DynamicDomains.Keys.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();

    public static bool IsBypassTargetDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;

        var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.Length == 0)
            return false;

        if (DynamicDomains.ContainsKey(d))
            return true;

        // Walk parent labels: foo.gemini.google.com -> gemini.google.com -> google.com
        int idx = 0;
        while ((idx = d.IndexOf('.', idx)) >= 0)
        {
            idx++;
            if (idx >= d.Length)
                break;
            var suffix = d[idx..];
            if (DynamicDomains.ContainsKey(suffix))
                return true;
        }

        return false;
    }

    public static bool IsStrictGoogleAiDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;
        var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        return d == "aistudio.google.com" ||
               d == "gemini.google.com" ||
               d == "ai.studio" ||
               d == "ai.google.dev" ||
               d == "makersuite.google.com" ||
               d == "notebooklm.google.com" ||
               d == "notebooklm.google" ||
               d == "labs.google" ||
               d == "opal.google.com" ||
               d == "jules.google.com" ||
               d == "deepmind.google" ||
               d == "idx.google.com" ||
               d.Contains("alkalimakersuite") ||
               d.Contains("alkalicore") ||
               d.Contains("generativelanguage.googleapis.com") ||
               d.Contains("proactivebackend-pa.googleapis.com") ||
               d.Contains("aisandbox-pa.googleapis.com") ||
               d.Contains("robinfrontend-pa.googleapis.com") ||
               d.Contains("geller-pa.googleapis.com");
    }

    public static void LoadOfflineCache(string appDataDir)
    {
        SeedBuiltins();
        try
        {
            var path = Path.Combine(appDataDir, "dynamic_bypass_domains.json");
            if (!File.Exists(path))
                return;
            var json = File.ReadAllText(path);
            var list = JsonSerializer.Deserialize<List<string>>(json);
            if (list is { Count: > 0 })
                ClassifyAndAddDomains(list);
        }
        catch
        {
            // Keep built-in defaults on corrupt cache
        }
    }

    public static void SaveOfflineCache(string appDataDir)
    {
        try
        {
            Directory.CreateDirectory(appDataDir);
            var path = Path.Combine(appDataDir, "dynamic_bypass_domains.json");
            var json = JsonSerializer.Serialize(GetAllProtectedDomains());
            File.WriteAllText(path, json);
        }
        catch
        {
            // Non-fatal
        }
    }
}
