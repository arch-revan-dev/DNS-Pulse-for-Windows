using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using DnsPulse.Core.Models;
using DnsPulse.Core.Security;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Diagnostics;

namespace DnsPulse.Engine.Discovery;

/// <summary>
/// Domain service classification matching v1.5.3 category, service tag, and purpose labels.
/// </summary>
public sealed record DomainClassification(
    string Category,
    string ServiceTag,
    string PurposeLabel,
    bool RequiresBypass);

/// <summary>
/// Explicit opt-in request for the Advanced Network Lab subnet scanner.
/// </summary>
public sealed record SubnetScanRequest
{
    public required string TargetDomain { get; init; }

    /// <summary>
    /// Must be explicitly set to <see langword="true"/> by user action. Background/startup auto-scans are forbidden.
    /// </summary>
    public bool UserOptedIn { get; init; }

    public IReadOnlyList<string> CandidateTargets { get; init; } = [];

    /// <summary>
    /// Concurrent probe limit, strictly clamped to <c>[1, 24]</c>.
    /// </summary>
    public int MaxConcurrency { get; init; } = 16;

    public double PermitsPerSecond { get; init; } = 30.0;

    public int BurstCapacity { get; init; } = 12;

    public int Port { get; init; } = 443;

    public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromMilliseconds(2000);

    /// <summary>
    /// Maximum expanded hosts per custom CIDR, strictly clamped to <c>[1, 1200]</c>.
    /// </summary>
    public int MaxCidrHosts { get; init; } = 1200;

    public IReadOnlyList<X509Certificate2>? AdditionalTrustedRoots { get; init; }

    /// <summary>
    /// Optional test hook redirecting validated public candidate IPs to an in-process mock TLS endpoint.
    /// </summary>
    public Func<IPAddress, IPEndPoint>? EndpointOverride { get; init; }
}

/// <summary>
/// Incremental progress emitted by <see cref="AdvancedSubnetScannerService"/>.
/// </summary>
public sealed record SubnetScanProgress(
    int ProbedCount,
    int TotalCandidateCount,
    int ExcludedPrivateOrBogonCount,
    int AcceptedCount,
    DnsServerEntry? AcceptedNode);

/// <summary>
/// Token-bucket rate limiter protecting scan throughput without busy-waiting.
/// </summary>
public sealed class TokenBucketRateLimiter
{
    private readonly Lock _sync = new();
    private readonly double _permitsPerSecond;
    private readonly double _capacity;
    private readonly TimeProvider _timeProvider;
    private double _availableTokens;
    private long _lastTimestamp;

    public TokenBucketRateLimiter(
        double permitsPerSecond,
        int burstCapacity,
        TimeProvider? timeProvider = null)
    {
        if (permitsPerSecond <= 0 || double.IsNaN(permitsPerSecond) || double.IsInfinity(permitsPerSecond))
        {
            throw new ArgumentOutOfRangeException(nameof(permitsPerSecond), "PermitsPerSecond must be finite and positive.");
        }

        if (burstCapacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(burstCapacity), "BurstCapacity must be at least 1.");
        }

        _permitsPerSecond = permitsPerSecond;
        _capacity = burstCapacity;
        _availableTokens = burstCapacity;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lastTimestamp = _timeProvider.GetTimestamp();
    }

    public async ValueTask WaitAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        TimeSpan delay;
        lock (_sync)
        {
            long now = _timeProvider.GetTimestamp();
            double elapsedSeconds = _timeProvider.GetElapsedTime(_lastTimestamp, now).TotalSeconds;
            _lastTimestamp = now;

            if (elapsedSeconds > 0)
            {
                _availableTokens = Math.Min(_capacity, _availableTokens + elapsedSeconds * _permitsPerSecond);
            }

            if (_availableTokens >= 1.0)
            {
                _availableTokens -= 1.0;
                delay = TimeSpan.Zero;
            }
            else
            {
                _availableTokens -= 1.0;
                double waitSeconds = (-_availableTokens) / _permitsPerSecond;
                delay = TimeSpan.FromSeconds(waitSeconds);
            }
        }

        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, _timeProvider, cancellationToken).ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Opt-in Advanced Network Lab subnet scanner enforcing rate limiting, concurrency cap (&lt;= 24),
/// private/bogon target exclusion, mandatory Layer 4 X.509 validation, and strict <see cref="TrustTier.Tier4ExperimentalLab"/> labeling.
/// </summary>
public sealed class AdvancedSubnetScannerService
{
    public const int HardMaxConcurrencyCap = 24;
    public const int HardMaxCidrHostCap = 1200;

    public static IReadOnlyList<string> DefaultCuratedPrefixes { get; } =
    [
        "192.255.159",
        "192.3.233",
        "107.175.76",
        "5.175.161",
        "143.20.64",
        "37.221.93",
        "185.236.10",
        "82.47.171",
        "163.5.63",
        "5.10.223",
        "185.194.177",
        "87.229.95",
        "179.254.166",
        "83.220.169",
        "212.109.195",
        "111.88.96"
    ];

    public static IReadOnlyList<int> KnownClusterOctets { get; } =
    [
        1, 2, 3, 5, 10, 20, 21, 37, 40, 54,
        77, 81, 93, 104, 112, 120, 134, 141, 149, 155,
        171, 177, 190, 192, 200, 221, 240, 241, 252, 253, 254
    ];

    private static readonly string[] GamingDomainKeywords =
    [
        "xbox", "live.com", "brawlstars", "supercell", "clashroyale",
        "clashofclans", "geforcenow", "nvidiagrid", "playstation", "parsec",
        "steam", "epicgames", "riot", "valorant", "leagueoflegends",
        "battlenet", "ea.com", "origin.com", "ubisoft", "rockstar",
        "roblox", "minecraft", "twitch", "discord", "curseforge"
    ];

    private readonly TimeProvider _timeProvider;

    public AdvancedSubnetScannerService(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Classifies a target domain into its v1.5.3 category, service tag, and purpose label.
    /// </summary>
    public static DomainClassification ClassifyTargetDomain(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        string normalized = DnsQuestion.Create(domain, DnsRecordType.A).Name;
        string serviceTag = ResolveServiceTag(normalized);

        foreach (string gamingKeyword in GamingDomainKeywords)
        {
            if (normalized.Contains(gamingKeyword, StringComparison.OrdinalIgnoreCase))
            {
                return new DomainClassification("Игры и Регионы", serviceTag, "Игры и консоли", RequiresBypass: true);
            }
        }

        if (IsBypassTargetDomain(normalized))
        {
            return new DomainClassification("Smart-DNS", serviceTag, "Smart-DNS обход", RequiresBypass: true);
        }

        return new DomainClassification("Скоростные", "CleanPing", "Чистая скорость", RequiresBypass: false);
    }

    /// <summary>
    /// Resolves the canonical service tag for a domain across the 13 flagship v1.5.3 services.
    /// </summary>
    public static string ResolveServiceTag(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        string d = domain.Trim();
        if (d.Contains("aistudio", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("alkalimakersuite", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("makersuite", StringComparison.OrdinalIgnoreCase))
        {
            return "AIStudio";
        }

        if (d.Contains("gemini", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("bard.google", StringComparison.OrdinalIgnoreCase))
        {
            return "Gemini";
        }

        if (d.Contains("chatgpt", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("openai", StringComparison.OrdinalIgnoreCase))
        {
            return "ChatGPT";
        }

        if (d.Contains("claude", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("anthropic", StringComparison.OrdinalIgnoreCase))
        {
            return "Claude";
        }

        if (d.Contains("copilot", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("sydney.bing", StringComparison.OrdinalIgnoreCase))
        {
            return "Copilot";
        }

        if (d.Contains("spotify", StringComparison.OrdinalIgnoreCase))
        {
            return "Spotify";
        }

        if (d.Contains("youtube", StringComparison.OrdinalIgnoreCase))
        {
            return "YouTube";
        }

        if (d.Contains("twitch", StringComparison.OrdinalIgnoreCase))
        {
            return "Twitch";
        }

        if (d.Contains("netflix", StringComparison.OrdinalIgnoreCase))
        {
            return "Netflix";
        }

        if (d.Contains("xbox", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("login.live.com", StringComparison.OrdinalIgnoreCase))
        {
            return "Xbox";
        }

        if (d.Contains("brawlstars", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("supercell", StringComparison.OrdinalIgnoreCase))
        {
            return "BrawlStars";
        }

        if (d.Contains("steampowered", StringComparison.OrdinalIgnoreCase) ||
            d.Contains("steamcommunity", StringComparison.OrdinalIgnoreCase))
        {
            return "Steam";
        }

        if (d.Contains("epicgames", StringComparison.OrdinalIgnoreCase))
        {
            return "EpicGames";
        }

        return "Custom";
    }

    /// <summary>
    /// Expands raw IP, <c>/24</c> prefix, or CIDR entries while strictly excluding private and bogon targets.
    /// </summary>
    public static IReadOnlyList<IPAddress> FilterAndExpandCandidates(
        IReadOnlyList<string>? inputs,
        int maxCidrHosts,
        out int excludedPrivateOrBogonCount)
    {
        int hostCap = Math.Clamp(maxCidrHosts, 1, HardMaxCidrHostCap);
        List<IPAddress> candidates = [];
        HashSet<IPAddress> seen = [];
        excludedPrivateOrBogonCount = 0;

        if (inputs is null || inputs.Count == 0)
        {
            foreach (string prefix in DefaultCuratedPrefixes)
            {
                foreach (int octet in KnownClusterOctets)
                {
                    AddIfPublic(string.Create(CultureInfo.InvariantCulture, $"{prefix}.{octet}"), candidates, seen, ref excludedPrivateOrBogonCount);
                }

                for (int octet = 1; octet <= 254; octet += 4)
                {
                    AddIfPublic(string.Create(CultureInfo.InvariantCulture, $"{prefix}.{octet}"), candidates, seen, ref excludedPrivateOrBogonCount);
                }
            }

            return candidates;
        }

        foreach (string raw in inputs)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            string trimmed = raw.Trim();
            if (trimmed.Contains('/', StringComparison.Ordinal))
            {
                ExpandIpv4Cidr(trimmed, hostCap, candidates, seen, ref excludedPrivateOrBogonCount);
            }
            else if (trimmed.AsSpan().Count('.') == 2 && IPAddress.TryParse(string.Concat(trimmed, ".1"), out _))
            {
                for (int octet = 1; octet <= 254 && candidates.Count < hostCap; octet++)
                {
                    AddIfPublic(string.Create(CultureInfo.InvariantCulture, $"{trimmed}.{octet}"), candidates, seen, ref excludedPrivateOrBogonCount);
                }
            }
            else
            {
                AddIfPublic(trimmed, candidates, seen, ref excludedPrivateOrBogonCount);
            }
        }

        return candidates;
    }

    /// <summary>
    /// Streams opt-in subnet scan progress and verified <see cref="TrustTier.Tier4ExperimentalLab"/> nodes.
    /// </summary>
    public async IAsyncEnumerable<SubnetScanProgress> ScanStreamAsync(
        SubnetScanRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.TargetDomain);

        if (!request.UserOptedIn)
        {
            throw new InvalidOperationException(
                "Advanced Network Lab scanning requires explicit user opt-in and must never run automatically at startup.");
        }

        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Port must be between 1 and 65535.");
        }

        string normalizedDomain = DnsQuestion.Create(request.TargetDomain, DnsRecordType.A).Name;
        DomainClassification classification = ClassifyTargetDomain(normalizedDomain);

        IReadOnlyList<IPAddress> publicCandidates = FilterAndExpandCandidates(
            request.CandidateTargets,
            request.MaxCidrHosts,
            out int excludedCount);

        if (publicCandidates.Count == 0)
        {
            yield break;
        }

        int concurrency = Math.Clamp(request.MaxConcurrency, 1, HardMaxConcurrencyCap);
        TokenBucketRateLimiter limiter = new(request.PermitsPerSecond, Math.Max(1, request.BurstCapacity), _timeProvider);

        Channel<SubnetScanProgress> channel = Channel.CreateUnbounded<SubnetScanProgress>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });

        int probedCounter = 0;
        int acceptedCounter = 0;

        Task producerTask = Task.Run(
            async () =>
            {
                try
                {
                    ParallelOptions parallelOptions = new()
                    {
                        MaxDegreeOfParallelism = concurrency,
                        CancellationToken = cancellationToken
                    };

                    await Parallel.ForEachAsync(
                        publicCandidates,
                        parallelOptions,
                        async (candidate, ct) =>
                        {
                            await ProbeCandidateAsync(
                                candidate,
                                normalizedDomain,
                                classification,
                                request,
                                publicCandidates.Count,
                                excludedCount,
                                limiter,
                                channel.Writer,
                                () => Interlocked.Increment(ref probedCounter),
                                () => Interlocked.Increment(ref acceptedCounter),
                                () => Volatile.Read(ref acceptedCounter),
                                ct).ConfigureAwait(false);
                        }).ConfigureAwait(false);

                    channel.Writer.TryComplete();
                }
                catch (OperationCanceledException ex)
                {
                    channel.Writer.TryComplete(ex);
                }
                catch (InvalidOperationException ex)
                {
                    channel.Writer.TryComplete(ex);
                }
                catch (ArgumentException ex)
                {
                    channel.Writer.TryComplete(ex);
                }
            },
            cancellationToken);

        await foreach (SubnetScanProgress item in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return item;
        }

        await producerTask.ConfigureAwait(false);
    }

    /// <summary>
    /// Executes an opt-in subnet scan and returns all verified <see cref="TrustTier.Tier4ExperimentalLab"/> nodes.
    /// </summary>
    public async Task<IReadOnlyList<DnsServerEntry>> ScanAsync(
        SubnetScanRequest request,
        IProgress<SubnetScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        List<DnsServerEntry> accepted = [];

        await foreach (SubnetScanProgress item in ScanStreamAsync(request, cancellationToken).ConfigureAwait(false))
        {
            progress?.Report(item);
            if (item.AcceptedNode is not null)
            {
                accepted.Add(item.AcceptedNode);
            }
        }

        return accepted;
    }

    private static async Task ProbeCandidateAsync(
        IPAddress candidateIp,
        string domain,
        DomainClassification classification,
        SubnetScanRequest request,
        int totalCandidates,
        int excludedCount,
        TokenBucketRateLimiter limiter,
        ChannelWriter<SubnetScanProgress> writer,
        Func<int> incrementProbed,
        Func<int> incrementAccepted,
        Func<int> readAccepted,
        CancellationToken cancellationToken)
    {
        await limiter.WaitAsync(cancellationToken).ConfigureAwait(false);

        (bool validCert, double? latencyMs, string reason) = await ProbeTlsLayer4Async(
            candidateIp,
            domain,
            request,
            cancellationToken).ConfigureAwait(false);

        int probed = incrementProbed();
        DnsServerEntry? node = null;
        int acceptedCount;

        if (validCert && latencyMs is double rtt)
        {
            acceptedCount = incrementAccepted();
            string ipText = candidateIp.ToString();
            node = new DnsServerEntry
            {
                Id = string.Create(CultureInfo.InvariantCulture, $"auto_proxy_{ipText.Replace('.', '_').Replace(':', '_')}"),
                Name = string.Create(CultureInfo.InvariantCulture, $"Lab SNI {ipText}"),
                Provider = "Advanced Network Lab",
                Protocol = DnsProtocol.SniProxy,
                TrustTier = TrustTier.Tier4ExperimentalLab,
                PrimaryIp = ipText,
                DohUrl = string.Concat("smartproxy://", ipText),
                SmartProxyIp = ipText,
                BootstrapIps = [ipText],
                Port = request.Port,
                Category = classification.Category,
                Country = "LAB",
                Tags = ["lab-scan", "tier4", "sni443", classification.ServiceTag],
                Description = string.Create(CultureInfo.InvariantCulture, $"{classification.PurposeLabel} (Tier 4 experimental lab node)"),
                SupportsBypass = classification.RequiresBypass,
                IsBuiltin = false,
                IsFavorite = false,
                IsSubscription = false,
                IsFreeUnlimited = true,
                LastLatencyMs = rtt,
                LatencyP50Ms = rtt,
                LatencyP95Ms = rtt,
                Port443Ok = true,
                Verdict = DiagnosticVerdict.Healthy,
                VerdictReason = reason,
                LastCheckedDomain = domain,
                LastCheckedAt = DateTimeOffset.UtcNow
            };
        }
        else
        {
            acceptedCount = readAccepted();
        }

        await writer.WriteAsync(
            new SubnetScanProgress(probed, totalCandidates, excludedCount, acceptedCount, node),
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(bool Valid, double? LatencyMs, string Reason)> ProbeTlsLayer4Async(
        IPAddress candidateIp,
        string domain,
        SubnetScanRequest request,
        CancellationToken cancellationToken)
    {
        if (IpSafetyInspector.IsPrivateOrBogon(candidateIp))
        {
            return (false, null, "Excluded private or bogon candidate IP.");
        }

        IPEndPoint targetEndpoint = request.EndpointOverride is not null
            ? request.EndpointOverride(candidateIp)
            : new IPEndPoint(candidateIp, request.Port);

        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(request.ProbeTimeout);

        using Socket socket = new(targetEndpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.NoDelay = true;

        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            await socket.ConnectAsync(targetEndpoint, cts.Token).ConfigureAwait(false);

            using NetworkStream networkStream = new(socket, ownsSocket: false);
            using SslStream sslStream = new(networkStream, leaveInnerStreamOpen: true);

            SslClientAuthenticationOptions sslOptions = new()
            {
                TargetHost = domain,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
            };

            if (request.AdditionalTrustedRoots is { Count: > 0 } roots)
            {
                sslOptions.RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                    SixLayerDiagnosticEngine.ValidateCertificateWithCustomRoots(certificate, sslPolicyErrors, roots);
            }

            await sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, Math.Max(0.1, sw.Elapsed.TotalMilliseconds), "Layer 4 X.509 certificate and SAN verified.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AuthenticationException ex)
        {
            return (false, null, ex.Message);
        }
        catch (SocketException ex)
        {
            return (false, null, ex.Message);
        }
        catch (IOException ex)
        {
            return (false, null, ex.Message);
        }
        catch (OperationCanceledException)
        {
            return (false, null, "Timed out.");
        }
    }

    private static void ExpandIpv4Cidr(
        string cidr,
        int hostCap,
        List<IPAddress> candidates,
        HashSet<IPAddress> seen,
        ref int excludedCount)
    {
        string[] parts = cidr.Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out IPAddress? baseIp) ||
            baseIp.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) ||
            prefix is < 16 or > 32)
        {
            return;
        }

        Span<byte> bytes = stackalloc byte[4];
        if (!baseIp.TryWriteBytes(bytes, out _))
        {
            return;
        }

        uint ipInt = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint network = ipInt & mask;
        uint broadcast = network | ~mask;

        uint first = prefix >= 31 ? network : network + 1;
        uint last = prefix >= 31 ? broadcast : broadcast - 1;

        int addedFromCidr = 0;
        for (uint current = first; current <= last && addedFromCidr < hostCap; current++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes, current);
            IPAddress ip = new(bytes);
            if (IpSafetyInspector.IsPrivateOrBogon(ip))
            {
                excludedCount++;
                continue;
            }

            if (seen.Add(ip))
            {
                candidates.Add(ip);
                addedFromCidr++;
            }

            if (current == uint.MaxValue)
            {
                break;
            }
        }
    }

    private static void AddIfPublic(
        string ipText,
        List<IPAddress> candidates,
        HashSet<IPAddress> seen,
        ref int excludedCount)
    {
        if (!IPAddress.TryParse(ipText.AsSpan().Trim(), out IPAddress? ip))
        {
            return;
        }

        if (IpSafetyInspector.IsPrivateOrBogon(ip))
        {
            excludedCount++;
            return;
        }

        if (seen.Add(ip))
        {
            candidates.Add(ip);
        }
    }

    private static bool IsBypassTargetDomain(string domain)
    {
        if (AntiDirectAndGeoSignatures.IsStrictGoogleAiDomain(domain))
        {
            return true;
        }

        foreach (string builtin in BuiltInCatalogPresets.AllBuiltinBypassDomains)
        {
            if (domain.Equals(builtin, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith(string.Concat(".", builtin), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
