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
    AllowUnsignedFeeds = 1
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
/// Format of an online community or signed DNS/bypass feed.
/// </summary>
public enum FeedKind
{
    BypassHosts = 0,
    QuickDnsJson = 1,
    CommunityMarkdown = 2
}

/// <summary>
/// Descriptor identifying a remote feed endpoint and optional Ed25519 + SHA-256 manifest verification material.
/// </summary>
public sealed record FeedSourceDescriptor
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required FeedKind Kind { get; init; }

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
    string DiagnosticMessage);

/// <summary>
/// Aggregated results from syncing one or more remote feeds.
/// </summary>
public sealed record FeedSyncSummary(
    FeedVerificationMode ModeUsed,
    IReadOnlyList<FeedSyncItemResult> Items,
    IReadOnlyList<string> AggregatedBypassDomains,
    IReadOnlyList<DnsServerEntry> AggregatedServers);

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

    public static IReadOnlyList<FeedSourceDescriptor> BuiltInFeeds { get; } =
    [
        new FeedSourceDescriptor
        {
            Id = "malw-link-hosts",
            Name = "Malw.link Bypass Hosts",
            Kind = FeedKind.BypassHosts,
            FeedUrl = "https://dns.malw.link/hosts",
            FallbackFeedUrl = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts",
            DefaultTag = "malw.link"
        },
        new FeedSourceDescriptor
        {
            Id = "quickdns-profiles",
            Name = "QuickDNS Catalog",
            Kind = FeedKind.QuickDnsJson,
            FeedUrl = "https://raw.githubusercontent.com/szanko02/QuickDNS/main/default_profiles.json",
            DefaultTag = "QuickDNS"
        },
        new FeedSourceDescriptor
        {
            Id = "hb-ai-xbox-dns",
            Name = "HB-AI Xbox DNS Community",
            Kind = FeedKind.CommunityMarkdown,
            FeedUrl = "https://raw.githubusercontent.com/neiroseti-ai/hb-ai-xbox-dns/main/README.md",
            DefaultTag = "HB-AI"
        },
        new FeedSourceDescriptor
        {
            Id = "antigravity-bypass-russia",
            Name = "Antigravity Bypass Community",
            Kind = FeedKind.CommunityMarkdown,
            FeedUrl = "https://raw.githubusercontent.com/vezlin1/antigravity-bypass-russia/main/README.md",
            DefaultTag = "Antigravity"
        }
    ];

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

            foreach (DnsServerEntry server in item.DiscoveredServers)
            {
                serverMap.TryAdd(server.Id, server);
            }
        }

        return new FeedSyncSummary(
            mode,
            results,
            aggregatedDomains,
            [.. serverMap.Values]);
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

        if ((!hasPublicKey || !hasSignatureUrl) && mode == FeedVerificationMode.RequireSigned)
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
        }

        string message = status == FeedVerificationStatus.VerifiedSigned
            ? string.Create(CultureInfo.InvariantCulture, $"Verified signed feed ({domains.Count} domains, {servers.Count} servers).")
            : string.Create(CultureInfo.InvariantCulture, $"Accepted unsigned community feed via explicit opt-in ({domains.Count} domains, {servers.Count} servers).");

        return new FeedSyncItemResult(
            descriptor.Id,
            descriptor.Name,
            descriptor.Kind,
            status,
            domains,
            servers,
            message);
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

    [GeneratedRegex(@"https://[A-Za-z0-9.\-]+(?::\d{1,5})?/[^\s)\]`""'<>]*dns-query[^\s)\]`""'<>]*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DohEndpointRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Regex();
}
