namespace DnsPulse.Core.Models;

/// <summary>
/// User-friendly task category for displaying and filtering DNS and Smart-DNS servers.
/// </summary>
public enum ServerDisplayCategory
{
    AiAndGeoUnlock = 0,
    FastEncrypted = 1,
    StreamingAndGaming = 2,
    CustomAndDiscovered = 3
}

/// <summary>
/// Classifies <see cref="DnsServerEntry"/> instances into user-friendly <see cref="ServerDisplayCategory"/> buckets
/// and evaluates domain/capability compatibility for auto-selection without altering security <see cref="TrustTier"/> rules.
/// </summary>
public static class ServerCategoryClassifier
{
    private static readonly HashSet<string> ExplicitAiTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "ai",
        "aistudio",
        "gemini",
        "chatgpt",
        "claude",
        "openai",
        "copilot",
        "grok",
        "perplexity",
        "anti-sanction"
    };

    private static readonly string[] GamingStreamingTagTokens =
    [
        "xbox",
        "gaming",
        "brawl",
        "twitch",
        "spotify",
        "discord",
        "youtube",
        "netflix",
        "steam",
        "epic",
        "playstation",
        "radar",
        "electro"
    ];

    private static readonly string[] GamingNameTokens =
    [
        "xbox",
        "gaming",
        "radar",
        "electro"
    ];

    /// <summary>
    /// Classifies <paramref name="server"/> into its user-facing <see cref="ServerDisplayCategory"/>.
    /// </summary>
    public static ServerDisplayCategory Classify(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);

        if (!server.IsBuiltin ||
            server.TrustTier is TrustTier.Tier3CustomOrSelfHosted or TrustTier.Tier4ExperimentalLab)
        {
            return ServerDisplayCategory.CustomAndDiscovered;
        }

        if (server.SupportsBypass)
        {
            return IsGamingOnlyGeoServer(server)
                ? ServerDisplayCategory.StreamingAndGaming
                : ServerDisplayCategory.AiAndGeoUnlock;
        }

        return ServerDisplayCategory.FastEncrypted;
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="server"/> is a Geo-Unlock node dedicated to gaming or
    /// streaming rather than general AI/geo-unblocking.
    /// </summary>
    public static bool IsGamingOnlyGeoServer(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);

        if (!server.SupportsBypass)
        {
            return false;
        }

        if (HasExplicitAiTag(server))
        {
            return false;
        }

        if (string.Equals(server.Category, "Игры и Регионы", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        foreach (string tag in server.Tags)
        {
            if (ContainsAnyToken(tag, GamingStreamingTagTokens))
            {
                return true;
            }
        }

        return ContainsAnyToken(server.Id, GamingNameTokens)
            || ContainsAnyToken(server.Name, GamingNameTokens);
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="server"/> is an eligible Geo-Unlock DNS resolver
    /// for AI services (such as <c>aistudio.google.com</c> and <c>gemini.google.com</c>), strictly excluding
    /// gaming-only DNS nodes and raw SNI relays.
    /// </summary>
    public static bool SupportsAiDomain(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);

        if (!server.SupportsBypass || server.Protocol == DnsProtocol.SniProxy)
        {
            return false;
        }

        if (IsGamingOnlyGeoServer(server))
        {
            return false;
        }

        return server.TrustTier is TrustTier.Tier2VerifiedGeoUnlock or TrustTier.Tier3CustomOrSelfHosted;
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="server"/> carries an explicit AI capability tag.
    /// </summary>
    public static bool HasExplicitAiTag(DnsServerEntry server)
    {
        ArgumentNullException.ThrowIfNull(server);

        foreach (string tag in server.Tags)
        {
            if (!string.IsNullOrWhiteSpace(tag) && ExplicitAiTags.Contains(tag.Trim()))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="domain"/> matches a built-in AI domain or one of its subdomains.
    /// </summary>
    public static bool IsAiDomain(string? domain)
    {
        return MatchesAnyBuiltinDomain(domain, BuiltInCatalogPresets.BuiltinAiDomains);
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="server"/> is an eligible Geo-Unlock candidate for <paramref name="domain"/>.
    /// </summary>
    public static bool SupportsTargetDomain(DnsServerEntry server, string? domain)
    {
        ArgumentNullException.ThrowIfNull(server);

        if (string.IsNullOrWhiteSpace(domain) || IsAiDomain(domain))
        {
            return SupportsAiDomain(server);
        }

        return server.SupportsBypass
            && server.Protocol != DnsProtocol.SniProxy
            && (server.TrustTier is TrustTier.Tier2VerifiedGeoUnlock or TrustTier.Tier3CustomOrSelfHosted);
    }

    private static bool MatchesAnyBuiltinDomain(string? domain, IReadOnlyList<string> candidates)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        string normalized = domain.Trim().TrimEnd('.');
        foreach (string candidate in candidates)
        {
            if (string.Equals(normalized, candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalized.Length > candidate.Length + 1
                && normalized.EndsWith(candidate, StringComparison.OrdinalIgnoreCase)
                && normalized[normalized.Length - candidate.Length - 1] == '.')
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsAnyToken(string? value, string[] tokens)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        foreach (string token in tokens)
        {
            if (value.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
