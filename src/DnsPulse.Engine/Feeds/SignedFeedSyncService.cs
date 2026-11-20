using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DnsPulse.Core.Cryptography;
using DnsPulse.Core.Models;
using DnsPulse.Core.Security;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Feeds;

/// <summary>
/// Verification policy applied by <see cref="SignedFeedSyncService"/> when fetching remote domain/server feeds.
/// </summary>
public enum FeedVerificationMode
{
    /// <summary>Fail closed: reject any feed lacking a verified Ed25519 signature (and SHA-256 manifest if configured).</summary>
    RequireSigned = 0,

    /// <summary>Explicit opt-in permitting unsigned community feeds while still rejecting any invalid/tampered signatures.</summary>
    AllowUnsignedFeeds = 1,

    /// <summary>Permits the 4 built-in trusted community feeds without Ed25519 signatures while still failing closed on unknown unsigned third-party feeds.</summary>
    BuiltInCommunityTrusted = 2
}

/// <summary>
/// Cryptographic verification outcome for a single fetched feed.
/// </summary>
public enum FeedVerificationStatus
{
    VerifiedSigned = 0,
    RejectedMissingSignature = 1,
    RejectedInvalidSignature = 2,
    RejectedChecksumMismatch = 3,
    UnsignedAcceptedOptIn = 4,
    FetchFailed = 5
}

/// <summary>
/// High-level content category of a remote database feed.
/// </summary>
public enum FeedCategory
{
    DnsServers = 0,
    DomainList = 1,
    IpSubnetList = 2,
    MixedCommunity = 3
}

/// <summary>
/// Format of an online community or signed DNS/bypass feed.
/// </summary>
public enum FeedKind
{
    BypassHosts = 0,
    QuickDnsJson = 1,
    CommunityMarkdown = 2,
    DnsCryptResolversMd = 3,
    DomainListCommunity = 4,
    IpCidrList = 5,
    PlainResolverList = 6
}

/// <summary>
/// Descriptor identifying a remote feed endpoint and optional Ed25519 + SHA-256 manifest verification material.
/// </summary>
public sealed record FeedSourceDescriptor
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required FeedKind Kind { get; init; }

    public FeedCategory Category { get; init; } = FeedCategory.MixedCommunity;

    public string? Description { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Configurable remote HTTPS feed endpoint.")]
    public required string FeedUrl { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Optional mirror HTTPS feed endpoint.")]
    public string? FallbackFeedUrl { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Optional SHA256SUMS.txt manifest URL.")]
    public string? ManifestUrl { get; init; }

    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Optional detached Ed25519 signature URL.")]
    public string? SignatureUrl { get; init; }

    public string? ManifestFileName { get; init; }

    public ImmutableArray<byte> Ed25519PublicKey { get; init; } = [];

    public string? DefaultTag { get; init; }
}

/// <summary>
/// Result of synchronizing and verifying a single feed source.
/// </summary>
public sealed record FeedSyncItemResult(
    string FeedId,
    string FeedName,
    FeedKind Kind,
    FeedVerificationStatus VerificationStatus,
    IReadOnlyList<string> BypassDomains,
    IReadOnlyList<DnsServerEntry> DiscoveredServers,
    string DiagnosticMessage)
{
    public IReadOnlyList<string> DiscoveredIpRanges { get; init; } = [];
}

/// <summary>
/// Aggregated results from syncing one or more remote feeds.
/// </summary>
public sealed record FeedSyncSummary(
    FeedVerificationMode ModeUsed,
    IReadOnlyList<FeedSyncItemResult> Items,
    IReadOnlyList<string> AggregatedBypassDomains,
    IReadOnlyList<DnsServerEntry> AggregatedServers)
{
    public IReadOnlyList<string> AggregatedIpRanges { get; init; } = [];
}

/// <summary>
/// Persisted offline snapshot of synced bypass domains and discovered community servers
/// (compatible with mobile <c>dynamic_bypass_domains_cache.json</c> semantics).
/// </summary>
public sealed record FeedCacheSnapshot(
    DateTimeOffset SavedAtUtc,
    IReadOnlyList<string> BypassDomains,
    IReadOnlyList<DnsServerEntry> DiscoveredServers);

/// <summary>
/// Combined startup feed sync result including offline cache fallback and updated domain/server totals.
/// </summary>
public sealed record FeedStartupSyncResult(
    FeedSyncSummary? NetworkSummary,
    IReadOnlyList<string> EffectiveBypassDomains,
    IReadOnlyList<DnsServerEntry> EffectiveDiscoveredServers,
    bool LoadedFromCache,
    bool UpdatedCacheFromNetwork);

/// <summary>
/// Fetches and cryptographically verifies online domain and resolver feeds using an
/// <see cref="IBootstrapResolver"/>-backed <see cref="HttpClient"/> and <see cref="SignedManifestVerifier"/>.
/// </summary>
public sealed partial class SignedFeedSyncService : IDisposable
{
    private const int MaxCommunityIpsPerFeed = 20;
    private const int MaxFeedPayloadBytes = 4 * 1024 * 1024;
    private static readonly char[] WhitespaceSeparators = [' ', '\t'];
    private static readonly string[] LineSeparators = ["\r\n", "\n"];
    private static readonly JsonSerializerOptions CacheJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static IReadOnlyList<FeedSourceDescriptor> BuiltInFeeds { get; } =
    [
        new FeedSourceDescriptor
        {
            Id = "malw-link-hosts",
            Name = "Malw.link Bypass Hosts",
            Kind = FeedKind.BypassHosts,
            Category = FeedCategory.DomainList,
            Description = "Community bypass domain list (AI, streaming & geo-restricted hosts).",
            FeedUrl = "https://dns.malw.link/hosts",
            FallbackFeedUrl = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts",
            DefaultTag = "malw.link"
        },
        new FeedSourceDescriptor
        {
            Id = "quickdns-profiles",
            Name = "QuickDNS Catalog",
            Kind = FeedKind.QuickDnsJson,
            Category = FeedCategory.DnsServers,
            Description = "Community SmartDNS & DoH server profiles (szanko02/QuickDNS).",
            FeedUrl = "https://raw.githubusercontent.com/szanko02/QuickDNS/main/default_profiles.json",
            DefaultTag = "QuickDNS"
        },
        new FeedSourceDescriptor
        {
            Id = "hb-ai-xbox-dns",
            Name = "HB-AI Xbox DNS Community",
            Kind = FeedKind.CommunityMarkdown,
            Category = FeedCategory.DnsServers,
            Description = "SmartDNS DoH & IP endpoints for AI & gaming (neiroseti-ai/hb-ai-xbox-dns).",
            FeedUrl = "https://raw.githubusercontent.com/neiroseti-ai/hb-ai-xbox-dns/main/README.md",
            DefaultTag = "HB-AI"
        },
        new FeedSourceDescriptor
        {
            Id = "antigravity-bypass-russia",
            Name = "Antigravity Bypass Community",
            Kind = FeedKind.CommunityMarkdown,
            Category = FeedCategory.DnsServers,
            Description = "Community endpoints for Google AI & Antigravity (vezlin1/antigravity-bypass-russia).",
            FeedUrl = "https://raw.githubusercontent.com/vezlin1/antigravity-bypass-russia/main/README.md",
            DefaultTag = "Antigravity"
        }
    ];

    public static IReadOnlyList<FeedSourceDescriptor> CuratedRepositoryFeeds { get; } =
    [
        new FeedSourceDescriptor
        {
            Id = "dnscrypt-public-resolvers",
            Name = "DNSCrypt Public Resolvers v3 (DoH / DoT)",
            Kind = FeedKind.DnsCryptResolversMd,
            Category = FeedCategory.DnsServers,
            Description = "Official DNSCrypt/dnscrypt-resolvers database of verified public DoH, DoT & DNSCrypt stamps.",
            FeedUrl = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
            DefaultTag = "DNSCrypt"
        },
        new FeedSourceDescriptor
        {
            Id = "trickest-trusted-resolvers",
            Name = "Trickest Trusted Public DNS Resolvers",
            Kind = FeedKind.PlainResolverList,
            Category = FeedCategory.DnsServers,
            Description = "Curated public DNS resolver IPs from trickest/resolvers.",
            FeedUrl = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
            DefaultTag = "Trickest"
        },
        new FeedSourceDescriptor
        {
            Id = "v2fly-ai-all",
            Name = "v2fly AI Services Domains (category-ai-!cn)",
            Kind = FeedKind.DomainListCommunity,
            Category = FeedCategory.DomainList,
            Description = "Complete AI services domain list from v2fly/domain-list-community.",
            FeedUrl = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ai-!cn",
            DefaultTag = "v2fly-ai"
        },
        new FeedSourceDescriptor
        {
            Id = "v2fly-google-gemini",
            Name = "v2fly Google Gemini & AI Studio Domains",
            Kind = FeedKind.DomainListCommunity,
            Category = FeedCategory.DomainList,
            Description = "Google Gemini & AI Studio domains from v2fly/domain-list-community.",
            FeedUrl = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google-gemini",
            DefaultTag = "v2fly-gemini"
        },
        new FeedSourceDescriptor
        {
            Id = "v2fly-openai",
            Name = "v2fly OpenAI / ChatGPT Domains",
            Kind = FeedKind.DomainListCommunity,
            Category = FeedCategory.DomainList,
            Description = "OpenAI and ChatGPT domains from v2fly/domain-list-community.",
            FeedUrl = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
            DefaultTag = "v2fly-openai"
        },
        new FeedSourceDescriptor
        {
            Id = "v2fly-anthropic",
            Name = "v2fly Anthropic / Claude Domains",
            Kind = FeedKind.DomainListCommunity,
            Category = FeedCategory.DomainList,
            Description = "Anthropic and Claude domains from v2fly/domain-list-community.",
            FeedUrl = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/anthropic",
            DefaultTag = "v2fly-anthropic"
        },
        new FeedSourceDescriptor
        {
            Id = "itdoginfo-russia-domains",
            Name = "itdoginfo Allow-Domains (Russia Inside)",
            Kind = FeedKind.DomainListCommunity,
            Category = FeedCategory.DomainList,
            Description = "Popular restricted domains list from itdoginfo/allow-domains.",
            FeedUrl = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
            DefaultTag = "itdoginfo"
        },
        new FeedSourceDescriptor
        {
            Id = "refilter-domains",
            Name = "Re-filter Domains List",
            Kind = FeedKind.DomainListCommunity,
            Category = FeedCategory.DomainList,
            Description = "Community domain bypass list from 1andrevich/Re-filter-lists.",
            FeedUrl = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst",
            DefaultTag = "re-filter"
        },
        new FeedSourceDescriptor
        {
            Id = "itdoginfo-cloudflare-ips",
            Name = "itdoginfo Cloudflare IPv4 Subnets",
            Kind = FeedKind.IpCidrList,
            Category = FeedCategory.IpSubnetList,
            Description = "Cloudflare IPv4 CIDR ranges from itdoginfo/allow-domains.",
            FeedUrl = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/cloudflare.lst",
            DefaultTag = "ip-cloudflare"
        },
        new FeedSourceDescriptor
        {
            Id = "itdoginfo-discord-ips",
            Name = "itdoginfo Discord IPv4 Subnets",
            Kind = FeedKind.IpCidrList,
            Category = FeedCategory.IpSubnetList,
            Description = "Discord IPv4 CIDR ranges from itdoginfo/allow-domains.",
            FeedUrl = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/discord.lst",
            DefaultTag = "ip-discord"
        },
        new FeedSourceDescriptor
        {
            Id = "refilter-ips",
            Name = "Re-filter IPv4 / CIDR List",
            Kind = FeedKind.IpCidrList,
            Category = FeedCategory.IpSubnetList,
            Description = "Community IPv4/CIDR ranges from 1andrevich/Re-filter-lists.",
            FeedUrl = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst",
            DefaultTag = "ip-refilter"
        }
    ];

    public static IReadOnlyList<FeedSourceDescriptor> AllCuratedFeeds { get; } =
    [
        .. BuiltInFeeds,
        .. CuratedRepositoryFeeds
    ];

    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "Custom repository URLs come directly from UI text input and are validated via Uri.TryCreate.")]
    public static FeedSourceDescriptor CreateCustomUrlDescriptor(string rawUrl, FeedKind? explicitKind = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawUrl);

        string trimmed = rawUrl.Trim();
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Custom repository URL must be a valid HTTPS URL.", nameof(rawUrl));
        }

        string upperPath = uri.AbsolutePath.ToUpperInvariant();
        FeedKind inferredKind = explicitKind ?? (upperPath switch
        {
            string p when p.EndsWith(".JSON", StringComparison.Ordinal) => FeedKind.QuickDnsJson,
            string p when p.Contains("RESOLVERS", StringComparison.Ordinal) && p.EndsWith(".MD", StringComparison.Ordinal) => FeedKind.DnsCryptResolversMd,
            string p when p.Contains("RESOLVERS", StringComparison.Ordinal) && p.EndsWith(".TXT", StringComparison.Ordinal) => FeedKind.PlainResolverList,
            string p when p.EndsWith(".MD", StringComparison.Ordinal) => FeedKind.CommunityMarkdown,
            string p when p.Contains("HOSTS", StringComparison.Ordinal) => FeedKind.BypassHosts,
            string p when p.Contains("SUBNET", StringComparison.Ordinal) || p.Contains("CIDR", StringComparison.Ordinal) || p.Contains("IPSUM", StringComparison.Ordinal) || p.Contains("/IPV4/", StringComparison.Ordinal) => FeedKind.IpCidrList,
            _ => FeedKind.DomainListCommunity
        });

        FeedCategory category = inferredKind switch
        {
            FeedKind.QuickDnsJson or FeedKind.DnsCryptResolversMd or FeedKind.PlainResolverList or FeedKind.CommunityMarkdown => FeedCategory.DnsServers,
            FeedKind.IpCidrList => FeedCategory.IpSubnetList,
            _ => FeedCategory.DomainList
        };

        string hostPart = SanitizeIdPart(uri.Host);
        string filePart = SanitizeIdPart(Path.GetFileNameWithoutExtension(uri.AbsolutePath));
        string id = string.Create(CultureInfo.InvariantCulture, $"custom_{hostPart}_{filePart}");
        string displayName = string.IsNullOrWhiteSpace(filePart)
            ? uri.Host
            : string.Create(CultureInfo.InvariantCulture, $"{uri.Host}/{Path.GetFileName(uri.AbsolutePath)}");

        return new FeedSourceDescriptor
        {
            Id = id,
            Name = displayName,
            Kind = inferredKind,
            Category = category,
            Description = trimmed,
            FeedUrl = trimmed,
            DefaultTag = "CustomRepo"
        };
    }

    private readonly IBootstrapResolver _bootstrapResolver;
    private readonly SocketsHttpHandler? _ownedHandler;
    private readonly HttpClient _httpClient;
    private readonly TimeSpan _requestTimeout;
    private bool _disposed;

    public SignedFeedSyncService(
        IBootstrapResolver bootstrapResolver,
        HttpMessageHandler? customHandler = null,
        TimeSpan? requestTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(bootstrapResolver);

        _bootstrapResolver = bootstrapResolver;
        _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(10);

        if (customHandler is null)
        {
            _ownedHandler = CreateBootstrapSocketsHandler(_bootstrapResolver);
            _httpClient = new HttpClient(_ownedHandler, disposeHandler: false);
        }
        else
        {
            _httpClient = new HttpClient(customHandler, disposeHandler: false);
        }

        _httpClient.Timeout = Timeout.InfiniteTimeSpan;
    }

    public async Task<FeedSyncSummary> SyncAllAsync(
        FeedVerificationMode mode = FeedVerificationMode.RequireSigned,
        IReadOnlyList<FeedSourceDescriptor>? feeds = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        IReadOnlyList<FeedSourceDescriptor> targets = feeds ?? BuiltInFeeds;
        List<FeedSyncItemResult> results = new(targets.Count);
        HashSet<string> domainSet = new(StringComparer.OrdinalIgnoreCase);
        List<string> aggregatedDomains = [];
        HashSet<string> ipSet = new(StringComparer.OrdinalIgnoreCase);
        List<string> aggregatedIps = [];
        Dictionary<string, DnsServerEntry> serverMap = new(StringComparer.OrdinalIgnoreCase);

        foreach (FeedSourceDescriptor descriptor in targets)
        {
            FeedSyncItemResult item = await SyncSingleAsync(descriptor, mode, cancellationToken).ConfigureAwait(false);
            results.Add(item);

            foreach (string domain in item.BypassDomains)
            {
                if (domainSet.Add(domain))
                {
                    aggregatedDomains.Add(domain);
                }
            }

            foreach (string ipRange in item.DiscoveredIpRanges)
            {
                if (ipSet.Add(ipRange))
                {
                    aggregatedIps.Add(ipRange);
                }
            }

            foreach (DnsServerEntry server in item.DiscoveredServers)
            {
                serverMap.TryAdd(server.Id, server);
            }
        }

        return new FeedSyncSummary(
            mode,
            results,
            aggregatedDomains,
            [.. serverMap.Values])
        {
            AggregatedIpRanges = aggregatedIps
        };
    }

    /// <summary>
    /// Loads cached bypass domains and servers from <paramref name="cacheFilePath"/> if present,
    /// then synchronizes built-in (or custom) feeds using <paramref name="mode"/> (defaulting to
    /// <see cref="FeedVerificationMode.BuiltInCommunityTrusted"/>) and persists refreshed offline results.
    /// Never throws on individual feed network failures or corrupt cache files.
    /// </summary>
    public async Task<FeedStartupSyncResult> SyncStartupFeedsAsync(
        string? cacheFilePath,
        FeedVerificationMode mode = FeedVerificationMode.BuiltInCommunityTrusted,
        bool loadCacheFirst = true,
        IReadOnlyList<FeedSourceDescriptor>? feeds = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        FeedCacheSnapshot? cached = null;
        if (loadCacheFirst && !string.IsNullOrWhiteSpace(cacheFilePath))
        {
            cached = await LoadCachedSnapshotAsync(cacheFilePath, cancellationToken).ConfigureAwait(false);
        }

        bool loadedFromCache = cached is not null
            && (cached.BypassDomains.Count > 0 || cached.DiscoveredServers.Count > 0);

        FeedSyncSummary summary = await SyncAllAsync(mode, feeds, cancellationToken).ConfigureAwait(false);

        bool hasNetworkDomains = summary.AggregatedBypassDomains.Count > 0;
        bool hasNetworkServers = summary.AggregatedServers.Count > 0;
        bool updatedFromNetwork = hasNetworkDomains || hasNetworkServers;

        IReadOnlyList<string> effectiveDomains = hasNetworkDomains
            ? summary.AggregatedBypassDomains
            : (cached?.BypassDomains ?? []);

        IReadOnlyList<DnsServerEntry> effectiveServers = hasNetworkServers
            ? summary.AggregatedServers
            : (cached?.DiscoveredServers ?? []);

        if (updatedFromNetwork && !string.IsNullOrWhiteSpace(cacheFilePath))
        {
            FeedCacheSnapshot updatedSnapshot = new(
                DateTimeOffset.UtcNow,
                effectiveDomains,
                effectiveServers);
            await SaveCachedSnapshotAsync(cacheFilePath, updatedSnapshot, cancellationToken).ConfigureAwait(false);
        }

        return new FeedStartupSyncResult(
            summary,
            effectiveDomains,
            effectiveServers,
            loadedFromCache,
            updatedFromNetwork);
    }

    /// <summary>
    /// Reads a cached feed snapshot from <paramref name="cacheFilePath"/> (supporting both
    /// <see cref="FeedCacheSnapshot"/> JSON and mobile <c>dynamic_bypass_domains_cache.json</c> domain lists).
    /// Returns <see langword="null"/> if the file does not exist or cannot be parsed.
    /// </summary>
    public static async Task<FeedCacheSnapshot?> LoadCachedSnapshotAsync(
        string cacheFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(cacheFilePath) || !File.Exists(cacheFilePath))
        {
            return null;
        }

        try
        {
            string json = await File.ReadAllTextAsync(cacheFilePath, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            using JsonDocument doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                List<string> rawDomains = ReadStringArray(doc.RootElement);
                return new FeedCacheSnapshot(DateTimeOffset.UtcNow, rawDomains, []);
            }

            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            FeedCacheSnapshot? typed = JsonSerializer.Deserialize<FeedCacheSnapshot>(json, CacheJsonOptions);
            if (typed is not null && (typed.BypassDomains.Count > 0 || typed.DiscoveredServers.Count > 0))
            {
                return typed;
            }

            if (doc.RootElement.TryGetProperty("domains", out JsonElement domainsElement) &&
                domainsElement.ValueKind == JsonValueKind.Array)
            {
                List<string> domains = ReadStringArray(domainsElement);
                return new FeedCacheSnapshot(DateTimeOffset.UtcNow, domains, []);
            }

            return typed;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Atomically persists <paramref name="snapshot"/> as UTF-8 JSON to <paramref name="cacheFilePath"/>.
    /// </summary>
    public static async Task SaveCachedSnapshotAsync(
        string cacheFilePath,
        FeedCacheSnapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheFilePath);
        ArgumentNullException.ThrowIfNull(snapshot);

        string? directory = Path.GetDirectoryName(cacheFilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string tempPath = string.Concat(cacheFilePath, ".tmp");
        try
        {
            string json = JsonSerializer.Serialize(snapshot, CacheJsonOptions);
            await File.WriteAllTextAsync(tempPath, json, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            File.Move(tempPath, cacheFilePath, overwrite: true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (IOException)
        {
            // Ignore transient disk/lock errors during background cache persistence.
        }
        catch (UnauthorizedAccessException)
        {
            // Ignore read-only path errors during background cache persistence.
        }
    }

    public async Task<FeedSyncItemResult> SyncSingleAsync(
        FeedSourceDescriptor descriptor,
        FeedVerificationMode mode = FeedVerificationMode.RequireSigned,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(descriptor);

        bool hasPublicKey = !descriptor.Ed25519PublicKey.IsDefault && descriptor.Ed25519PublicKey.Length == 32;
        bool hasSignatureUrl = !string.IsNullOrWhiteSpace(descriptor.SignatureUrl);
        bool hasManifestUrl = !string.IsNullOrWhiteSpace(descriptor.ManifestUrl);

        if (!hasPublicKey || !hasSignatureUrl)
        {
            bool allowUnsigned = mode == FeedVerificationMode.AllowUnsignedFeeds ||
                (mode == FeedVerificationMode.BuiltInCommunityTrusted && IsTrustedBuiltInCommunityFeed(descriptor));
            if (!allowUnsigned)
            {
                return new FeedSyncItemResult(
                    descriptor.Id,
                    descriptor.Name,
                    descriptor.Kind,
                    FeedVerificationStatus.RejectedMissingSignature,
                    [],
                    [],
                    "Rejected unsigned feed in RequireSigned mode (missing Ed25519 public key or detached signature URL).");
            }
        }

        (byte[]? payloadBytes, string? usedUrl, string? fetchError) = await FetchWithFallbackAsync(
            descriptor.FeedUrl,
            descriptor.FallbackFeedUrl,
            cancellationToken).ConfigureAwait(false);

        if (payloadBytes is null || usedUrl is null)
        {
            return new FeedSyncItemResult(
                descriptor.Id,
                descriptor.Name,
                descriptor.Kind,
                FeedVerificationStatus.FetchFailed,
                [],
                [],
                fetchError ?? "Failed to fetch feed payload.");
        }

        FeedVerificationStatus status;
        if (hasPublicKey && hasSignatureUrl)
        {
            (byte[]? sigRaw, _, string? sigErr) = await FetchWithFallbackAsync(descriptor.SignatureUrl!, null, cancellationToken).ConfigureAwait(false);
            if (sigRaw is null || !TryDecodeSignatureBytes(sigRaw, out byte[] signature))
            {
                return new FeedSyncItemResult(
                    descriptor.Id,
                    descriptor.Name,
                    descriptor.Kind,
                    FeedVerificationStatus.RejectedInvalidSignature,
                    [],
                    [],
                    sigErr ?? "Detached Ed25519 signature could not be fetched or decoded.");
            }

            if (hasManifestUrl)
            {
                (byte[]? manifestBytes, _, string? manErr) = await FetchWithFallbackAsync(descriptor.ManifestUrl!, null, cancellationToken).ConfigureAwait(false);
                if (manifestBytes is null)
                {
                    return new FeedSyncItemResult(
                        descriptor.Id,
                        descriptor.Name,
                        descriptor.Kind,
                        FeedVerificationStatus.RejectedInvalidSignature,
                        [],
                        [],
                        manErr ?? "Signed manifest could not be fetched.");
                }

                if (!SignedManifestVerifier.VerifySignedManifest(
                        manifestBytes,
                        signature,
                        descriptor.Ed25519PublicKey.AsSpan(),
                        out ImmutableArray<ManifestEntry> entries))
                {
                    return new FeedSyncItemResult(
                        descriptor.Id,
                        descriptor.Name,
                        descriptor.Kind,
                        FeedVerificationStatus.RejectedInvalidSignature,
                        [],
                        [],
                        "Ed25519 signature verification failed for SHA256SUMS manifest.");
                }

                string targetName = descriptor.ManifestFileName
                    ?? Path.GetFileName(new Uri(usedUrl, UriKind.Absolute).AbsolutePath);
                ManifestEntry? matchedEntry = FindManifestEntry(entries, targetName);
                if (matchedEntry is null)
                {
                    return new FeedSyncItemResult(
                        descriptor.Id,
                        descriptor.Name,
                        descriptor.Kind,
                        FeedVerificationStatus.RejectedChecksumMismatch,
                        [],
                        [],
                        string.Create(CultureInfo.InvariantCulture, $"Manifest does not contain checksum entry for '{targetName}'."));
                }

                using MemoryStream payloadStream = new(payloadBytes, writable: false);
                if (!await SignedManifestVerifier.VerifyManifestEntryAsync(payloadStream, matchedEntry, cancellationToken).ConfigureAwait(false))
                {
                    return new FeedSyncItemResult(
                        descriptor.Id,
                        descriptor.Name,
                        descriptor.Kind,
                        FeedVerificationStatus.RejectedChecksumMismatch,
                        [],
                        [],
                        string.Create(CultureInfo.InvariantCulture, $"SHA-256 checksum mismatch for '{targetName}'."));
                }

                status = FeedVerificationStatus.VerifiedSigned;
            }
            else
            {
                byte[] expectedSha256 = SHA256.HashData(payloadBytes);
                if (!SignedManifestVerifier.VerifySignedPayload(
                        payloadBytes,
                        signature,
                        descriptor.Ed25519PublicKey.AsSpan(),
                        expectedSha256))
                {
                    return new FeedSyncItemResult(
                        descriptor.Id,
                        descriptor.Name,
                        descriptor.Kind,
                        FeedVerificationStatus.RejectedInvalidSignature,
                        [],
                        [],
                        "Detached Ed25519 signature verification failed for feed payload.");
                }

                status = FeedVerificationStatus.VerifiedSigned;
            }
        }
        else
        {
            status = FeedVerificationStatus.UnsignedAcceptedOptIn;
        }

        string text = Encoding.UTF8.GetString(payloadBytes);
        IReadOnlyList<string> domains = [];
        IReadOnlyList<DnsServerEntry> servers = [];
        IReadOnlyList<string> ipRanges = [];

        switch (descriptor.Kind)
        {
            case FeedKind.BypassHosts:
                domains = ParseBypassHosts(text);
                break;
            case FeedKind.QuickDnsJson:
                servers = ParseQuickDnsProfiles(text, descriptor.DefaultTag);
                break;
            case FeedKind.CommunityMarkdown:
                servers = ParseCommunityMarkdown(text, descriptor.DefaultTag);
                break;
            case FeedKind.DnsCryptResolversMd:
                servers = ParseDnsCryptResolversMarkdown(text, descriptor.DefaultTag);
                break;
            case FeedKind.DomainListCommunity:
                domains = ParseDomainListCommunity(text);
                break;
            case FeedKind.IpCidrList:
                ipRanges = ParseIpCidrList(text);
                break;
            case FeedKind.PlainResolverList:
                servers = ParsePlainResolverList(text, descriptor.DefaultTag);
                break;
        }

        string message = status == FeedVerificationStatus.VerifiedSigned
            ? string.Create(CultureInfo.InvariantCulture, $"Verified signed feed ({domains.Count} domains, {servers.Count} servers, {ipRanges.Count} IPs).")
            : string.Create(CultureInfo.InvariantCulture, $"Synced community feed ({domains.Count} domains, {servers.Count} servers, {ipRanges.Count} IPs).");

        return new FeedSyncItemResult(
            descriptor.Id,
            descriptor.Name,
            descriptor.Kind,
            status,
            domains,
            servers,
            message)
        {
            DiscoveredIpRanges = ipRanges
        };
    }

    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "DNS hostnames are canonically lowercase.")]
    public static IReadOnlyList<string> ParseBypassHosts(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        List<string> domains = [];

        string[] lines = content.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);
        foreach (string rawLine in lines)
        {
            int commentIdx = rawLine.IndexOf('#', StringComparison.Ordinal);
            string line = (commentIdx >= 0 ? rawLine[..commentIdx] : rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string[] tokens = line.Split(WhitespaceSeparators, StringSplitOptions.RemoveEmptyEntries);
            int startIndex = 0;
            if (tokens.Length >= 2 && IPAddress.TryParse(tokens[0], out _))
            {
                startIndex = 1;
            }

            for (int i = startIndex; i < tokens.Length; i++)
            {
                string candidate = tokens[i].Trim().TrimEnd('.');
                if (IsIgnoredHostToken(candidate))
                {
                    continue;
                }

                if (Uri.CheckHostName(candidate) == UriHostNameType.Dns && seen.Add(candidate))
                {
                    domains.Add(candidate.ToLowerInvariant());
                }
            }
        }

        return domains;
    }

    public static IReadOnlyList<DnsServerEntry> ParseQuickDnsProfiles(string jsonContent, string? defaultTag = "QuickDNS")
    {
        ArgumentNullException.ThrowIfNull(jsonContent);

        List<DnsServerEntry> servers = [];
        HashSet<string> seenIds = new(StringComparer.OrdinalIgnoreCase);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(jsonContent);
            JsonElement root = doc.RootElement;
            JsonElement arrayElement;

            if (root.ValueKind == JsonValueKind.Array)
            {
                arrayElement = root;
            }
            else if (root.ValueKind == JsonValueKind.Object &&
                     (root.TryGetProperty("profiles", out arrayElement) ||
                      root.TryGetProperty("servers", out arrayElement)) &&
                     arrayElement.ValueKind == JsonValueKind.Array)
            {
                // Found inner array
            }
            else
            {
                return servers;
            }

            int index = 0;
            foreach (JsonElement item in arrayElement.EnumerateArray())
            {
                index++;
                if (item.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string name = ReadJsonString(item, "name") ?? string.Create(CultureInfo.InvariantCulture, $"QuickDNS #{index}");
                string provider = ReadJsonString(item, "provider") ?? "QuickDNS";
                string? rawEndpoint = ReadJsonString(item, "dohUrl")
                    ?? ReadJsonString(item, "doh")
                    ?? ReadJsonString(item, "url")
                    ?? ReadJsonString(item, "endpoint");
                string? primaryIp = ReadJsonString(item, "primaryIp") ?? ReadJsonString(item, "ip");
                string country = ReadJsonString(item, "country") ?? "GLOBAL";
                bool supportsBypass = ReadJsonBool(item, "supportsBypass") ?? true;

                string? validDohUrl = null;
                string? dotHost = null;
                string? stampUri = null;
                DnsProtocol protocol = DnsProtocol.DoH;

                if (!string.IsNullOrWhiteSpace(rawEndpoint) && EndpointUriParser.TryParse(rawEndpoint, out ParsedEndpoint? parsed))
                {
                    if (parsed.Kind == EndpointKind.DoH)
                    {
                        validDohUrl = parsed.NormalizedEndpoint;
                        dotHost = parsed.Host;
                        protocol = DnsProtocol.DoH;
                    }
                    else if (parsed.Kind == EndpointKind.DoT)
                    {
                        dotHost = parsed.Host;
                        protocol = DnsProtocol.DoT;
                    }
                    else if (parsed.Kind == EndpointKind.DnsStamp)
                    {
                        stampUri = parsed.NormalizedEndpoint;
                    }
                }

                if (primaryIp is not null && !IpSafetyInspector.IsPublicRoutable(primaryIp))
                {
                    primaryIp = null;
                }

                if (validDohUrl is null && dotHost is null && stampUri is null && primaryIp is null)
                {
                    continue;
                }

                if (validDohUrl is null && dotHost is null && stampUri is null && primaryIp is not null)
                {
                    protocol = DnsProtocol.Udp;
                }

                string id = string.Create(CultureInfo.InvariantCulture, $"feed_quickdns_{index}_{SanitizeIdPart(name)}");
                if (!seenIds.Add(id))
                {
                    continue;
                }

                List<string> tags = ["feed"];
                if (!string.IsNullOrWhiteSpace(defaultTag))
                {
                    tags.Add(defaultTag);
                }

                servers.Add(new DnsServerEntry
                {
                    Id = id,
                    Name = name,
                    Provider = provider,
                    Protocol = protocol,
                    TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                    PrimaryIp = primaryIp ?? string.Empty,
                    DohUrl = validDohUrl,
                    DotHost = dotHost,
                    DnsStampUri = stampUri,
                    BootstrapIps = primaryIp is not null ? [primaryIp] : [],
                    Category = supportsBypass ? "Smart-DNS" : "Скоростные",
                    Country = country,
                    Tags = tags,
                    Description = "Imported from QuickDNS community feed.",
                    SupportsBypass = supportsBypass,
                    IsBuiltin = false
                });
            }
        }
        catch (JsonException)
        {
            return [];
        }

        return servers;
    }

    public static IReadOnlyList<DnsServerEntry> ParseCommunityMarkdown(string markdownContent, string? tag)
    {
        ArgumentNullException.ThrowIfNull(markdownContent);

        List<DnsServerEntry> servers = [];
        HashSet<string> seenEndpoints = new(StringComparer.OrdinalIgnoreCase);

        MatchCollection dohMatches = DohEndpointRegex().Matches(markdownContent);
        int dohIndex = 0;
        foreach (Match match in dohMatches)
        {
            if (!EndpointUriParser.TryParse(match.Value, out ParsedEndpoint? parsed) || parsed.Kind != EndpointKind.DoH)
            {
                continue;
            }

            if (!seenEndpoints.Add(parsed.NormalizedEndpoint))
            {
                continue;
            }

            dohIndex++;
            string label = string.IsNullOrWhiteSpace(tag) ? "Community" : tag.Trim();
            servers.Add(new DnsServerEntry
            {
                Id = string.Create(CultureInfo.InvariantCulture, $"feed_{SanitizeIdPart(label)}_doh_{dohIndex}"),
                Name = string.Create(CultureInfo.InvariantCulture, $"{label} DoH ({parsed.Host})"),
                Provider = label,
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                DohUrl = parsed.NormalizedEndpoint,
                DotHost = parsed.Host,
                Category = "Smart-DNS",
                Country = "GLOBAL",
                Tags = ["feed", label, "doh"],
                Description = string.Create(CultureInfo.InvariantCulture, $"Community DoH endpoint from {label} feed."),
                SupportsBypass = true,
                IsBuiltin = false
            });
        }

        MatchCollection ipMatches = Ipv4Regex().Matches(markdownContent);
        int ipCount = 0;
        foreach (Match match in ipMatches)
        {
            if (ipCount >= MaxCommunityIpsPerFeed)
            {
                break;
            }

            if (!IPAddress.TryParse(match.Value, out IPAddress? ip) || !IpSafetyInspector.IsPublicRoutable(ip))
            {
                continue;
            }

            string ipText = ip.ToString();
            if (!seenEndpoints.Add(ipText))
            {
                continue;
            }

            ipCount++;
            string label = string.IsNullOrWhiteSpace(tag) ? "Community" : tag.Trim();
            servers.Add(new DnsServerEntry
            {
                Id = string.Create(CultureInfo.InvariantCulture, $"feed_{SanitizeIdPart(label)}_ip_{ipText.Replace('.', '_')}"),
                Name = string.Create(CultureInfo.InvariantCulture, $"{label} DNS {ipText}"),
                Provider = label,
                Protocol = DnsProtocol.Udp,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                PrimaryIp = ipText,
                BootstrapIps = [ipText],
                Category = "Smart-DNS",
                Country = "GLOBAL",
                Tags = ["feed", label, "udp53"],
                Description = string.Create(CultureInfo.InvariantCulture, $"Community IP endpoint from {label} feed."),
                SupportsBypass = true,
                IsBuiltin = false
            });
        }

        return servers;
    }

    public static IReadOnlyList<DnsServerEntry> ParseDnsCryptResolversMarkdown(
        string markdownContent,
        string? defaultTag = "DNSCrypt",
        int maxServers = 80)
    {
        ArgumentNullException.ThrowIfNull(markdownContent);

        List<DnsServerEntry> servers = [];
        HashSet<string> seenIds = new(StringComparer.OrdinalIgnoreCase);
        string[] lines = markdownContent.Split(LineSeparators, StringSplitOptions.None);
        string currentHeading = string.Empty;
        string currentDescription = string.Empty;
        string label = string.IsNullOrWhiteSpace(defaultTag) ? "DNSCrypt" : defaultTag.Trim();

        foreach (string rawLine in lines)
        {
            if (servers.Count >= maxServers)
            {
                break;
            }

            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                currentHeading = line[3..].Trim();
                currentDescription = string.Empty;
                continue;
            }

            if (!line.StartsWith("sdns://", StringComparison.OrdinalIgnoreCase))
            {
                if (currentDescription.Length == 0 && !line.StartsWith('#'))
                {
                    currentDescription = line;
                }

                continue;
            }

            string stampToken = line.Split(WhitespaceSeparators, StringSplitOptions.RemoveEmptyEntries)[0];
            if (!DnsStampCodec.TryParse(stampToken, out DnsStamp? stamp))
            {
                continue;
            }

            DnsProtocol? mappedProtocol = stamp.Protocol switch
            {
                DnsStampProtocol.DoH => DnsProtocol.DoH,
                DnsStampProtocol.DoT => DnsProtocol.DoT,
                DnsStampProtocol.DoQ => DnsProtocol.DoQ,
                DnsStampProtocol.DnsCrypt => DnsProtocol.DnsCrypt,
                _ => null
            };

            if (mappedProtocol is not DnsProtocol protocol)
            {
                continue;
            }

            string? host = string.IsNullOrWhiteSpace(stamp.HostName) ? null : stamp.HostName.Trim();
            string? dohUrl = null;
            if (protocol == DnsProtocol.DoH && !string.IsNullOrWhiteSpace(host))
            {
                string path = string.IsNullOrWhiteSpace(stamp.Path)
                    ? "/dns-query"
                    : (stamp.Path.StartsWith('/') ? stamp.Path : string.Concat("/", stamp.Path));
                dohUrl = string.Create(CultureInfo.InvariantCulture, $"https://{host}{path}");
            }

            string primaryIp = ExtractIpFromServerAddress(stamp.ServerAddress);
            if (primaryIp.Length > 0 && !IpSafetyInspector.IsPublicRoutable(primaryIp))
            {
                primaryIp = string.Empty;
            }

            List<string> bootstrapIps = [];
            if (primaryIp.Length > 0)
            {
                bootstrapIps.Add(primaryIp);
            }

            foreach (string bs in stamp.BootstrapIps)
            {
                if (IpSafetyInspector.IsPublicRoutable(bs) && !bootstrapIps.Contains(bs, StringComparer.OrdinalIgnoreCase))
                {
                    bootstrapIps.Add(bs);
                }
            }

            string name = !string.IsNullOrWhiteSpace(currentHeading)
                ? currentHeading
                : (!string.IsNullOrWhiteSpace(host) ? host : string.Create(CultureInfo.InvariantCulture, $"{label} #{servers.Count + 1}"));

            string id = string.Create(CultureInfo.InvariantCulture, $"feed_dnscrypt_{SanitizeIdPart(name)}");
            if (id.Length <= "feed_dnscrypt_".Length || !seenIds.Add(id))
            {
                continue;
            }

            servers.Add(new DnsServerEntry
            {
                Id = id,
                Name = name,
                Provider = label,
                Protocol = protocol,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                PrimaryIp = primaryIp,
                DohUrl = dohUrl,
                DotHost = host,
                DnsStampUri = stampToken,
                BootstrapIps = bootstrapIps,
                Category = "Скоростные",
                Country = "GLOBAL",
                Tags = ["feed", label, protocol.ToString()],
                Description = string.IsNullOrWhiteSpace(currentDescription)
                    ? "Public encrypted resolver from DNSCrypt resolvers database."
                    : currentDescription,
                SupportsBypass = false,
                IsBuiltin = false
            });
        }

        return servers;
    }

    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "DNS hostnames are canonically lowercase.")]
    public static IReadOnlyList<string> ParseDomainListCommunity(string content, int maxDomains = 4000)
    {
        ArgumentNullException.ThrowIfNull(content);

        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        List<string> domains = [];
        string[] lines = content.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);

        foreach (string rawLine in lines)
        {
            if (domains.Count >= maxDomains)
            {
                break;
            }

            int commentIdx = rawLine.IndexOf('#', StringComparison.Ordinal);
            string line = (commentIdx >= 0 ? rawLine[..commentIdx] : rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string token = line.Split(WhitespaceSeparators, StringSplitOptions.RemoveEmptyEntries)[0];
            if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("regexp:", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("keyword:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (token.StartsWith("domain:", StringComparison.OrdinalIgnoreCase))
            {
                token = token[7..];
            }
            else if (token.StartsWith("full:", StringComparison.OrdinalIgnoreCase))
            {
                token = token[5..];
            }

            token = token.Trim().TrimStart('*').TrimStart('.').TrimEnd('.');
            if (IsIgnoredHostToken(token) || !token.Contains('.', StringComparison.Ordinal))
            {
                continue;
            }

            if (Uri.CheckHostName(token) == UriHostNameType.Dns && seen.Add(token))
            {
                domains.Add(token.ToLowerInvariant());
            }
        }

        return domains;
    }

    public static IReadOnlyList<string> ParseIpCidrList(string content, int maxEntries = 2000)
    {
        ArgumentNullException.ThrowIfNull(content);

        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        List<string> results = [];
        string[] lines = content.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);

        foreach (string rawLine in lines)
        {
            if (results.Count >= maxEntries)
            {
                break;
            }

            int commentIdx = rawLine.IndexOf('#', StringComparison.Ordinal);
            string line = (commentIdx >= 0 ? rawLine[..commentIdx] : rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string token = line.Split(WhitespaceSeparators, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
            int slashIdx = token.IndexOf('/', StringComparison.Ordinal);
            if (slashIdx > 0)
            {
                string ipPart = token[..slashIdx];
                string prefixPart = token[(slashIdx + 1)..];
                if (IPAddress.TryParse(ipPart, out IPAddress? cidrIp) &&
                    cidrIp.AddressFamily == AddressFamily.InterNetwork &&
                    IpSafetyInspector.IsPublicRoutable(cidrIp) &&
                    int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) &&
                    prefix is >= 8 and <= 32)
                {
                    string normalized = string.Create(CultureInfo.InvariantCulture, $"{cidrIp}/{prefix}");
                    if (seen.Add(normalized))
                    {
                        results.Add(normalized);
                    }
                }
            }
            else if (IPAddress.TryParse(token, out IPAddress? ip) &&
                     ip.AddressFamily == AddressFamily.InterNetwork &&
                     IpSafetyInspector.IsPublicRoutable(ip))
            {
                string normalized = ip.ToString();
                if (seen.Add(normalized))
                {
                    results.Add(normalized);
                }
            }
        }

        return results;
    }

    public static IReadOnlyList<DnsServerEntry> ParsePlainResolverList(
        string content,
        string? defaultTag = "Resolvers",
        int maxServers = 60)
    {
        ArgumentNullException.ThrowIfNull(content);

        List<DnsServerEntry> servers = [];
        HashSet<string> seenKeys = new(StringComparer.OrdinalIgnoreCase);
        string[] lines = content.Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries);
        string label = string.IsNullOrWhiteSpace(defaultTag) ? "Resolvers" : defaultTag.Trim();

        foreach (string rawLine in lines)
        {
            if (servers.Count >= maxServers)
            {
                break;
            }

            int commentIdx = rawLine.IndexOf('#', StringComparison.Ordinal);
            string line = (commentIdx >= 0 ? rawLine[..commentIdx] : rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string token = line.Split(WhitespaceSeparators, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
            if (token.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                Uri.TryCreate(token, UriKind.Absolute, out Uri? dohUri) &&
                !string.IsNullOrWhiteSpace(dohUri.Host) &&
                seenKeys.Add(dohUri.AbsoluteUri))
            {
                string dohId = string.Create(CultureInfo.InvariantCulture, $"feed_{SanitizeIdPart(label)}_doh_{SanitizeIdPart(dohUri.Host)}");
                servers.Add(new DnsServerEntry
                {
                    Id = dohId,
                    Name = string.Create(CultureInfo.InvariantCulture, $"{label} DoH ({dohUri.Host})"),
                    Provider = label,
                    Protocol = DnsProtocol.DoH,
                    TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                    DohUrl = dohUri.AbsoluteUri,
                    DotHost = dohUri.Host,
                    Category = "Скоростные",
                    Country = "GLOBAL",
                    Tags = ["feed", label, "DoH"],
                    Description = string.Create(CultureInfo.InvariantCulture, $"Public DoH resolver imported from {label}."),
                    SupportsBypass = false,
                    IsBuiltin = false
                });
                continue;
            }

            if (token.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
            {
                string dotHost = token[6..].Trim().TrimEnd('/');
                int portIdx = dotHost.IndexOf(':', StringComparison.Ordinal);
                if (portIdx > 0)
                {
                    dotHost = dotHost[..portIdx];
                }

                if (!string.IsNullOrWhiteSpace(dotHost) &&
                    Uri.CheckHostName(dotHost) == UriHostNameType.Dns &&
                    seenKeys.Add(string.Create(CultureInfo.InvariantCulture, $"tls://{dotHost}")))
                {
                    string dotId = string.Create(CultureInfo.InvariantCulture, $"feed_{SanitizeIdPart(label)}_dot_{SanitizeIdPart(dotHost)}");
                    servers.Add(new DnsServerEntry
                    {
                        Id = dotId,
                        Name = string.Create(CultureInfo.InvariantCulture, $"{label} DoT ({dotHost})"),
                        Provider = label,
                        Protocol = DnsProtocol.DoT,
                        TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                        DotHost = dotHost,
                        Category = "Скоростные",
                        Country = "GLOBAL",
                        Tags = ["feed", label, "DoT"],
                        Description = string.Create(CultureInfo.InvariantCulture, $"Public DoT resolver imported from {label}."),
                        SupportsBypass = false,
                        IsBuiltin = false
                    });
                }

                continue;
            }

            if (!IPAddress.TryParse(token, out IPAddress? ip) ||
                ip.AddressFamily != AddressFamily.InterNetwork ||
                !IpSafetyInspector.IsPublicRoutable(ip))
            {
                continue;
            }

            string ipText = ip.ToString();
            if (!seenKeys.Add(ipText))
            {
                continue;
            }

            servers.Add(new DnsServerEntry
            {
                Id = string.Create(CultureInfo.InvariantCulture, $"feed_{SanitizeIdPart(label)}_{ipText.Replace('.', '_')}"),
                Name = string.Create(CultureInfo.InvariantCulture, $"{label} DNS {ipText}"),
                Provider = label,
                Protocol = DnsProtocol.Udp,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                PrimaryIp = ipText,
                BootstrapIps = [ipText],
                Category = "Скоростные",
                Country = "GLOBAL",
                Tags = ["feed", label, "udp53"],
                Description = string.Create(CultureInfo.InvariantCulture, $"Public DNS resolver imported from {label}."),
                SupportsBypass = false,
                IsBuiltin = false
            });
        }

        return servers;
    }

    private static string ExtractIpFromServerAddress(string? serverAddress)
    {
        if (string.IsNullOrWhiteSpace(serverAddress))
        {
            return string.Empty;
        }

        string trimmed = serverAddress.Trim();
        if (IPAddress.TryParse(trimmed, out IPAddress? direct))
        {
            return direct.ToString();
        }

        if (trimmed.StartsWith('['))
        {
            int closeBracket = trimmed.IndexOf(']', StringComparison.Ordinal);
            if (closeBracket > 1)
            {
                string v6 = trimmed[1..closeBracket];
                return IPAddress.TryParse(v6, out IPAddress? parsedV6) ? parsedV6.ToString() : string.Empty;
            }

            return string.Empty;
        }

        int colonIdx = trimmed.LastIndexOf(':');
        if (colonIdx > 0)
        {
            string ipCandidate = trimmed[..colonIdx];
            if (IPAddress.TryParse(ipCandidate, out IPAddress? parsedV4))
            {
                return parsedV4.ToString();
            }
        }

        return string.Empty;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _httpClient.Dispose();
        _ownedHandler?.Dispose();
    }

    private async Task<(byte[]? Bytes, string? UsedUrl, string? Error)> FetchWithFallbackAsync(
        string primaryUrl,
        string? fallbackUrl,
        CancellationToken cancellationToken)
    {
        (byte[]? bytes, string? err) = await FetchSingleUrlAsync(primaryUrl, cancellationToken).ConfigureAwait(false);
        if (bytes is not null)
        {
            return (bytes, primaryUrl, null);
        }

        if (!string.IsNullOrWhiteSpace(fallbackUrl))
        {
            (byte[]? fbBytes, string? fbErr) = await FetchSingleUrlAsync(fallbackUrl, cancellationToken).ConfigureAwait(false);
            if (fbBytes is not null)
            {
                return (fbBytes, fallbackUrl, null);
            }

            return (null, null, fbErr ?? err);
        }

        return (null, null, err);
    }

    private async Task<(byte[]? Bytes, string? Error)> FetchSingleUrlAsync(
        string rawUrl,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out Uri? uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return (null, "Feed URL must be a valid HTTPS absolute URI.");
        }

        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_requestTimeout);

        using HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("DnsPulse", "2.0"));

        try
        {
            using HttpResponseMessage response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cts.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return (null, string.Create(CultureInfo.InvariantCulture, $"HTTP {(int)response.StatusCode} from {uri.Host}."));
            }

            await using Stream stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            using MemoryStream ms = new();
            byte[] buffer = new byte[16384];
            int totalRead = 0;

            while (true)
            {
                int read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                totalRead += read;
                if (totalRead > MaxFeedPayloadBytes)
                {
                    return (null, "Feed payload exceeded maximum allowed size.");
                }

                await ms.WriteAsync(buffer.AsMemory(0, read), cts.Token).ConfigureAwait(false);
            }

            return (ms.ToArray(), null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException ex)
        {
            return (null, ex.Message);
        }
        catch (IOException ex)
        {
            return (null, ex.Message);
        }
        catch (SocketException ex)
        {
            return (null, ex.Message);
        }
        catch (OperationCanceledException)
        {
            return (null, "Feed download timed out.");
        }
    }

    private static SocketsHttpHandler CreateBootstrapSocketsHandler(IBootstrapResolver bootstrapResolver)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 4,
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = async (context, ct) =>
            {
                IReadOnlyList<IPAddress> candidateIps;
                if (IPAddress.TryParse(context.DnsEndPoint.Host, out IPAddress? literalIp))
                {
                    candidateIps = [literalIp];
                }
                else
                {
                    candidateIps = await bootstrapResolver.ResolveHostAsync(context.DnsEndPoint.Host, ct).ConfigureAwait(false);
                }

                SocketException? lastSocketEx = null;
                foreach (IPAddress ip in candidateIps)
                {
                    if (!IpSafetyInspector.IsPublicRoutable(ip))
                    {
                        continue;
                    }

                    Socket socket = new(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                    {
                        NoDelay = true
                    };

                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(ip, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (SocketException ex)
                    {
                        lastSocketEx = ex;
                        socket.Dispose();
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                throw lastSocketEx ?? new SocketException((int)SocketError.HostNotFound);
            }
        };
    }

    private static bool TryDecodeSignatureBytes(byte[] rawBytes, out byte[] signature)
    {
        if (rawBytes.Length == 64)
        {
            signature = rawBytes;
            return true;
        }

        string text = Encoding.UTF8.GetString(rawBytes).Trim();
        if (text.Length == 128)
        {
            try
            {
                byte[] hexBytes = Convert.FromHexString(text);
                if (hexBytes.Length == 64)
                {
                    signature = hexBytes;
                    return true;
                }
            }
            catch (FormatException)
            {
            }
        }

        try
        {
            string normalized = text.Replace('-', '+').Replace('_', '/');
            int mod = normalized.Length % 4;
            if (mod == 2)
            {
                normalized = string.Concat(normalized, "==");
            }
            else if (mod == 3)
            {
                normalized = string.Concat(normalized, "=");
            }

            byte[] b64 = Convert.FromBase64String(normalized);
            if (b64.Length == 64)
            {
                signature = b64;
                return true;
            }
        }
        catch (FormatException)
        {
        }

        signature = [];
        return false;
    }

    private static ManifestEntry? FindManifestEntry(ImmutableArray<ManifestEntry> entries, string targetFileName)
    {
        foreach (ManifestEntry entry in entries)
        {
            if (entry.FileName.Equals(targetFileName, StringComparison.Ordinal) ||
                Path.GetFileName(entry.FileName).Equals(targetFileName, StringComparison.Ordinal))
            {
                return entry;
            }
        }

        return null;
    }

    private static bool IsIgnoredHostToken(string token)
    {
        return string.IsNullOrWhiteSpace(token) ||
               token.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               token.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase) ||
               token.Equals("broadcasthost", StringComparison.OrdinalIgnoreCase) ||
               token.Equals("0.0.0.0", StringComparison.Ordinal) ||
               token.Equals("127.0.0.1", StringComparison.Ordinal) ||
               token.Equals("::1", StringComparison.Ordinal) ||
               token.Equals("::", StringComparison.Ordinal);
    }

    private static string? ReadJsonString(JsonElement obj, string propertyName)
    {
        if (obj.TryGetProperty(propertyName, out JsonElement prop) && prop.ValueKind == JsonValueKind.String)
        {
            string? value = prop.GetString();
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }

        return null;
    }

    private static bool? ReadJsonBool(JsonElement obj, string propertyName)
    {
        if (obj.TryGetProperty(propertyName, out JsonElement prop))
        {
            if (prop.ValueKind == JsonValueKind.True)
            {
                return true;
            }

            if (prop.ValueKind == JsonValueKind.False)
            {
                return false;
            }
        }

        return null;
    }

    private static string SanitizeIdPart(string value)
    {
        StringBuilder sb = new(value.Length);
        foreach (char c in value)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                sb.Append(char.ToLowerInvariant(c));
            }
            else if (sb.Length > 0 && sb[^1] != '_')
            {
                sb.Append('_');
            }
        }

        return sb.ToString().Trim('_');
    }

    private static bool IsTrustedBuiltInCommunityFeed(FeedSourceDescriptor descriptor)
    {
        if (!Uri.TryCreate(descriptor.FeedUrl, UriKind.Absolute, out Uri? feedUri) ||
            !feedUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (FeedSourceDescriptor builtIn in AllCuratedFeeds)
        {
            if (string.Equals(descriptor.Id, builtIn.Id, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(descriptor.FeedUrl, builtIn.FeedUrl, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(descriptor.FallbackFeedUrl, builtIn.FallbackFeedUrl, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static List<string> ReadStringArray(JsonElement arrayElement)
    {
        List<string> items = [];
        foreach (JsonElement element in arrayElement.EnumerateArray())
        {
            if (element.ValueKind == JsonValueKind.String)
            {
                string? val = element.GetString();
                if (!string.IsNullOrWhiteSpace(val))
                {
                    items.Add(val.Trim());
                }
            }
        }

        return items;
    }

    [GeneratedRegex(@"https://[A-Za-z0-9.\-]+(?::\d{1,5})?/[^\s)\]`""'<>]*dns-query[^\s)\]`""'<>]*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DohEndpointRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Regex();
}
