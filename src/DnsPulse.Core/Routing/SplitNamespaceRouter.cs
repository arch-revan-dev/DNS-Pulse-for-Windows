using System.Globalization;

namespace DnsPulse.Core.Routing;

/// <summary>
/// Represents an explicitly enabled Zone 3 Geo-unlock rule.
/// </summary>
/// <param name="Pattern">Domain, wildcard (<c>*.example.com</c>), or GeoSite/AdGuard pattern.</param>
/// <param name="TargetProfileId">Optional Smart-DNS / SNI-Proxy profile identifier for this domain.</param>
public sealed record GeoUnlockRule(
    string Pattern,
    string? TargetProfileId = null);

/// <summary>
/// Immutable configuration used to build or atomically swap a <see cref="SplitNamespaceRouter"/> snapshot.
/// </summary>
public sealed record SplitNamespaceRouterConfig
{
    /// <summary>
    /// Gets additional corporate or local suffixes routed to Zone 1 (<see cref="RouteZone.Zone1LocalBypass"/>).
    /// </summary>
    public IReadOnlyList<string> CorporateBypassDomains { get; init; } = [];

    /// <summary>
    /// Gets additional domains pinned to trusted encrypted DNS (never eligible for Zone 3 Geo-unlock).
    /// </summary>
    public IReadOnlyList<string> AdditionalSecurityPinnedDomains { get; init; } = [];

    /// <summary>
    /// Gets blocklist rules (AdGuard <c>||...^</c> / <c>@@||...^</c>, <c>HOSTS</c> entries, GeoSite lines, or plain domain patterns).
    /// </summary>
    public IReadOnlyList<string> BlockRules { get; init; } = [];

    /// <summary>
    /// Gets explicit allow-list exception rules overriding blocklist entries.
    /// </summary>
    public IReadOnlyList<string> AllowExceptionRules { get; init; } = [];

    /// <summary>
    /// Gets explicitly enabled Zone 3 Geo-unlock rules. Empty by default (strict opt-in).
    /// </summary>
    public IReadOnlyList<GeoUnlockRule> GeoUnlockRules { get; init; } = [];

    /// <summary>
    /// Gets the optional profile identifier assigned to Zone 1 local bypass decisions.
    /// </summary>
    public string? LocalBypassProfileId { get; init; }

    /// <summary>
    /// Gets the default profile identifier assigned to Zone 3 Geo-unlock decisions when a rule omits its own target.
    /// </summary>
    public string? DefaultGeoUnlockProfileId { get; init; }

    /// <summary>
    /// Gets the optional profile identifier assigned to Zone 4 encrypted trusted decisions.
    /// </summary>
    public string? EncryptedTrustedProfileId { get; init; }
}

/// <summary>
/// Thread-safe, lock-free split-namespace DNS router using atomic snapshot swapping (<see cref="Volatile.Read{T}"/>)
/// and strict 4-zone precedence: <c>Zone 1 (Local/LAN) &gt; Security Pinning &gt; Zone 2 (Block) &gt; Zone 3 (Geo-Unlock) &gt; Zone 4 (Default Internet)</c>.
/// </summary>
public sealed class SplitNamespaceRouter
{
    private static readonly string[] BuiltinZone1Suffixes =
    [
        "localhost",
        "local",
        "lan",
        "home.arpa",
        "internal",
        "localdomain",
        "10.in-addr.arpa",
        "168.192.in-addr.arpa",
        "127.in-addr.arpa",
        "254.169.in-addr.arpa",
        "d.f.ip6.arpa",
        "c.f.ip6.arpa",
        "16.172.in-addr.arpa",
        "17.172.in-addr.arpa",
        "18.172.in-addr.arpa",
        "19.172.in-addr.arpa",
        "20.172.in-addr.arpa",
        "21.172.in-addr.arpa",
        "22.172.in-addr.arpa",
        "23.172.in-addr.arpa",
        "24.172.in-addr.arpa",
        "25.172.in-addr.arpa",
        "26.172.in-addr.arpa",
        "27.172.in-addr.arpa",
        "28.172.in-addr.arpa",
        "29.172.in-addr.arpa",
        "30.172.in-addr.arpa",
        "31.172.in-addr.arpa"
    ];

    private static readonly string[] BuiltinSecurityPinnedSuffixes =
    [
        // OS updates & connectivity probes
        "windowsupdate.com",
        "update.microsoft.com",
        "msftconnecttest.com",
        // Code & supply-chain integrity
        "github.com",
        "githubusercontent.com",
        // PKI & certificate authorities
        "digicert.com",
        "letsencrypt.org",
        "sectigo.com",
        "pki.goog",
        // OS vendor & security ecosystem
        "apple.com",
        // Auth & financial endpoints
        "accounts.google.com",
        "login.microsoftonline.com",
        "paypal.com",
        "stripe.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "hsbc.com",
        "sberbank.ru",
        "tbank.ru",
        "vtb.ru",
        "alfabank.ru"
    ];

    private RouterSnapshot _snapshot;

    /// <summary>
    /// Initializes a new <see cref="SplitNamespaceRouter"/> with optional initial configuration.
    /// </summary>
    public SplitNamespaceRouter(SplitNamespaceRouterConfig? config = null)
    {
        _snapshot = BuildSnapshot(config ?? new SplitNamespaceRouterConfig());
    }

    /// <summary>
    /// Gets the active Zone 1 rule count in the current snapshot.
    /// </summary>
    public int Zone1RuleCount => Volatile.Read(ref _snapshot).Zone1Trie.RuleCount;

    /// <summary>
    /// Gets the active Security-Pinned rule count in the current snapshot.
    /// </summary>
    public int SecurityPinnedRuleCount => Volatile.Read(ref _snapshot).SecurityPinnedTrie.RuleCount;

    /// <summary>
    /// Gets the active Zone 2 block rule count in the current snapshot.
    /// </summary>
    public int BlockRuleCount => Volatile.Read(ref _snapshot).BlockTrie.RuleCount;

    /// <summary>
    /// Gets the active Zone 2 allow-exception rule count in the current snapshot.
    /// </summary>
    public int AllowExceptionRuleCount => Volatile.Read(ref _snapshot).AllowTrie.RuleCount;

    /// <summary>
    /// Gets the active Zone 3 Geo-unlock rule count in the current snapshot.
    /// </summary>
    public int GeoUnlockRuleCount => Volatile.Read(ref _snapshot).GeoUnlockTrie.RuleCount;

    /// <summary>
    /// Atomically compiles and swaps in a new routing configuration snapshot without blocking active readers.
    /// </summary>
    public void UpdateConfiguration(SplitNamespaceRouterConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        RouterSnapshot nextSnapshot = BuildSnapshot(config);
        Interlocked.Exchange(ref _snapshot, nextSnapshot);
    }

    /// <summary>
    /// Evaluates the routing decision for <paramref name="domain"/> strictly in 4-zone precedence order.
    /// </summary>
    /// <param name="domain">The queried domain name.</param>
    /// <returns>The immutable <see cref="RouteDecision"/> for the domain.</returns>
    public RouteDecision Route(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        RouterSnapshot snapshot = Volatile.Read(ref _snapshot);
        ReadOnlySpan<char> querySpan = TrimTrailingDots(domain.AsSpan().Trim());
        if (querySpan.IsEmpty)
        {
            throw new ArgumentException("Domain name cannot consist solely of dots.", nameof(domain));
        }

        // 1. Zone 1: Local / LAN / Private Reverse DNS / Corporate Bypass
        if (snapshot.Zone1Trie.TryMatch(querySpan, out DomainMatchResult<byte>? zone1Match) && zone1Match is not null)
        {
            return new RouteDecision(
                RouteZone.Zone1LocalBypass,
                IsBlocked: false,
                IsSecurityPinned: false,
                MatchedRule: zone1Match.MatchedPattern,
                TargetProfileId: snapshot.LocalBypassProfileId);
        }

        // 2a. Security-Critical Domain Pinning (hard-forbids Zone 3 hijack and accidental blocking)
        if (TryMatchSecurityPin(snapshot.SecurityPinnedTrie, querySpan, out string? pinnedRule) && pinnedRule is not null)
        {
            return new RouteDecision(
                RouteZone.Zone4EncryptedTrusted,
                IsBlocked: false,
                IsSecurityPinned: true,
                MatchedRule: pinnedRule,
                TargetProfileId: snapshot.EncryptedTrustedProfileId);
        }

        // 2b. Zone 2: Blocklists (honoring @@|| allow exceptions)
        if (!snapshot.AllowTrie.TryMatch(querySpan, out _) &&
            snapshot.BlockTrie.TryMatch(querySpan, out DomainMatchResult<string>? blockMatch) &&
            blockMatch is not null)
        {
            return new RouteDecision(
                RouteZone.Zone2BlockOrProtect,
                IsBlocked: true,
                IsSecurityPinned: false,
                MatchedRule: blockMatch.MatchedPattern,
                TargetProfileId: null);
        }

        // 3. Zone 3: Scoped Geo-Unlock (opt-in only)
        if (snapshot.GeoUnlockTrie.TryMatch(querySpan, out DomainMatchResult<string?>? geoMatch) && geoMatch is not null)
        {
            return new RouteDecision(
                RouteZone.Zone3GeoUnlock,
                IsBlocked: false,
                IsSecurityPinned: false,
                MatchedRule: geoMatch.MatchedPattern,
                TargetProfileId: geoMatch.Value ?? snapshot.DefaultGeoUnlockProfileId);
        }

        // 4. Zone 4: Default Encrypted Trusted Internet
        return new RouteDecision(
            RouteZone.Zone4EncryptedTrusted,
            IsBlocked: false,
            IsSecurityPinned: false,
            MatchedRule: "*",
            TargetProfileId: snapshot.EncryptedTrustedProfileId);
    }

    private static bool TryMatchSecurityPin(
        DomainRadixTrie<byte> securityPinnedTrie,
        ReadOnlySpan<char> querySpan,
        out string? matchedRule)
    {
        if (securityPinnedTrie.TryMatch(querySpan, out DomainMatchResult<byte>? match) && match is not null)
        {
            matchedRule = match.MatchedPattern;
            return true;
        }

        // Prefix-label pinning for OCSP and CRL infrastructure: ocsp.* and crl.*
        int firstDot = querySpan.IndexOf('.');
        if (firstDot > 0 && firstDot < querySpan.Length - 1)
        {
            ReadOnlySpan<char> firstLabel = querySpan[..firstDot];
            if (firstLabel.Equals("ocsp", StringComparison.OrdinalIgnoreCase))
            {
                matchedRule = "ocsp.*";
                return true;
            }

            if (firstLabel.Equals("crl", StringComparison.OrdinalIgnoreCase))
            {
                matchedRule = "crl.*";
                return true;
            }
        }

        matchedRule = null;
        return false;
    }

    private static RouterSnapshot BuildSnapshot(SplitNamespaceRouterConfig config)
    {
        DomainRadixTrieBuilder<byte> zone1Builder = new();
        foreach (string suffix in BuiltinZone1Suffixes)
        {
            zone1Builder.TryAddSuffix(suffix, 1);
        }

        foreach (string corporate in config.CorporateBypassDomains)
        {
            if (!string.IsNullOrWhiteSpace(corporate))
            {
                zone1Builder.TryAddPattern(corporate, 1, DomainMatchKind.Suffix);
            }
        }

        DomainRadixTrieBuilder<byte> pinnedBuilder = new();
        foreach (string suffix in BuiltinSecurityPinnedSuffixes)
        {
            pinnedBuilder.TryAddSuffix(suffix, 1);
        }

        foreach (string customPin in config.AdditionalSecurityPinnedDomains)
        {
            if (!string.IsNullOrWhiteSpace(customPin))
            {
                pinnedBuilder.TryAddPattern(customPin, 1, DomainMatchKind.Suffix);
            }
        }

        DomainRadixTrieBuilder<string> blockBuilder = new();
        DomainRadixTrieBuilder<byte> allowBuilder = new();
        List<HostEntry> hostBuffer = [];

        foreach (string rawRule in config.AllowExceptionRules)
        {
            AddExceptionRule(rawRule, allowBuilder);
        }

        foreach (string rawRule in config.BlockRules)
        {
            AddBlockOrExceptionRule(rawRule, blockBuilder, allowBuilder, hostBuffer);
        }

        DomainRadixTrieBuilder<string?> geoBuilder = new();
        foreach (GeoUnlockRule rule in config.GeoUnlockRules)
        {
            if (rule is null || string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            ReadOnlySpan<char> patternSpan = rule.Pattern.AsSpan().Trim();
            if (RuleParsers.TryParseGeoSiteLine(patternSpan, out GeoSiteRule? geoSite) && geoSite is not null)
            {
                AddByKind(geoBuilder, geoSite.Domain, geoSite.MatchKind, rule.TargetProfileId);
            }
            else
            {
                geoBuilder.TryAddPattern(rule.Pattern, rule.TargetProfileId, DomainMatchKind.Suffix);
            }
        }

        return new RouterSnapshot(
            zone1Builder.Build(),
            pinnedBuilder.Build(),
            blockBuilder.Build(),
            allowBuilder.Build(),
            geoBuilder.Build(),
            config.LocalBypassProfileId,
            config.DefaultGeoUnlockProfileId,
            config.EncryptedTrustedProfileId);
    }

    private static void AddExceptionRule(string rawRule, DomainRadixTrieBuilder<byte> allowBuilder)
    {
        if (string.IsNullOrWhiteSpace(rawRule))
        {
            return;
        }

        ReadOnlySpan<char> span = rawRule.AsSpan().Trim();
        if (RuleParsers.TryParseAdGuardLine(span, out AdGuardRule? adGuard) && adGuard is not null)
        {
            AddByKind(allowBuilder, adGuard.Domain, adGuard.MatchKind, (byte)1);
            return;
        }

        allowBuilder.TryAddPattern(rawRule, (byte)1, DomainMatchKind.Suffix);
    }

    private static void AddBlockOrExceptionRule(
        string rawRule,
        DomainRadixTrieBuilder<string> blockBuilder,
        DomainRadixTrieBuilder<byte> allowBuilder,
        List<HostEntry> hostBuffer)
    {
        if (string.IsNullOrWhiteSpace(rawRule))
        {
            return;
        }

        ReadOnlySpan<char> span = rawRule.AsSpan().Trim();

        // 1. Check HOSTS line syntax first (e.g. "0.0.0.0 ads.example.com").
        hostBuffer.Clear();
        if (RuleParsers.ParseHostsLine(span, hostBuffer) > 0)
        {
            foreach (HostEntry entry in hostBuffer)
            {
                if (RuleParsers.IsHostsSinkholeAddress(entry.Address))
                {
                    blockBuilder.TryAddSuffix(entry.Domain, string.Create(CultureInfo.InvariantCulture, $"hosts:{entry.Domain}"));
                }
            }

            return;
        }

        // 2. Check AdGuard DNS syntax (||ads.example^ or @@||allow.example^).
        if (RuleParsers.TryParseAdGuardLine(span, out AdGuardRule? adGuard) && adGuard is not null)
        {
            if (adGuard.IsException)
            {
                AddByKind(allowBuilder, adGuard.Domain, adGuard.MatchKind, (byte)1);
            }
            else
            {
                AddByKind(blockBuilder, adGuard.Domain, adGuard.MatchKind, adGuard.Domain);
            }

            return;
        }

        // 3. Check GeoSite syntax (domain:..., full:..., *.domain).
        if (RuleParsers.TryParseGeoSiteLine(span, out GeoSiteRule? geoSite) && geoSite is not null)
        {
            AddByKind(blockBuilder, geoSite.Domain, geoSite.MatchKind, geoSite.Domain);
        }
    }

    private static void AddByKind<TPayload>(
        DomainRadixTrieBuilder<TPayload> builder,
        string domain,
        DomainMatchKind kind,
        TPayload value)
    {
        switch (kind)
        {
            case DomainMatchKind.Exact:
                builder.TryAddExact(domain, value);
                break;
            case DomainMatchKind.Wildcard:
                builder.TryAddWildcard(domain, value);
                break;
            case DomainMatchKind.Suffix:
                builder.TryAddSuffix(domain, value);
                break;
        }
    }

    private static ReadOnlySpan<char> TrimTrailingDots(ReadOnlySpan<char> span)
    {
        while (span.Length > 0 && span[^1] == '.')
        {
            span = span[..^1];
        }

        return span;
    }

    private sealed class RouterSnapshot
    {
        public RouterSnapshot(
            DomainRadixTrie<byte> zone1Trie,
            DomainRadixTrie<byte> securityPinnedTrie,
            DomainRadixTrie<string> blockTrie,
            DomainRadixTrie<byte> allowTrie,
            DomainRadixTrie<string?> geoUnlockTrie,
            string? localBypassProfileId,
            string? defaultGeoUnlockProfileId,
            string? encryptedTrustedProfileId)
        {
            Zone1Trie = zone1Trie;
            SecurityPinnedTrie = securityPinnedTrie;
            BlockTrie = blockTrie;
            AllowTrie = allowTrie;
            GeoUnlockTrie = geoUnlockTrie;
            LocalBypassProfileId = localBypassProfileId;
            DefaultGeoUnlockProfileId = defaultGeoUnlockProfileId;
            EncryptedTrustedProfileId = encryptedTrustedProfileId;
        }

        public DomainRadixTrie<byte> Zone1Trie { get; }

        public DomainRadixTrie<byte> SecurityPinnedTrie { get; }

        public DomainRadixTrie<string> BlockTrie { get; }

        public DomainRadixTrie<byte> AllowTrie { get; }

        public DomainRadixTrie<string?> GeoUnlockTrie { get; }

        public string? LocalBypassProfileId { get; }

        public string? DefaultGeoUnlockProfileId { get; }

        public string? EncryptedTrustedProfileId { get; }
    }
}
