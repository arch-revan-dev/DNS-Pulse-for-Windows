using System.Collections.Immutable;
using System.Globalization;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Feeds;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Discovery;

public sealed class SignedFeedSyncServiceTests
{
    private static readonly string[] ExpectedSignedDomains = ["gemini.google.com", "aistudio.google.com"];
    private static readonly string[] ExpectedParsedDomains = ["aistudio.google.com", "openai.com", "claude.ai"];
    private static readonly string[] ExpectedParsedIps = ["104.18.0.0/16", "162.159.135.232"];
    private static readonly string[] ExpectedBuiltInFeedUrls =
    [
        "https://dns.malw.link/hosts",
        "https://raw.githubusercontent.com/szanko02/QuickDNS/main/default_profiles.json",
        "https://raw.githubusercontent.com/neiroseti-ai/hb-ai-xbox-dns/main/README.md",
        "https://raw.githubusercontent.com/vezlin1/antigravity-bypass-russia/main/README.md"
    ];

    // RFC 8032 Section 7.1 Test Vector 1 keypair
    private const string Vector1SecretKeyHex =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    private const string Vector1PublicKeyHex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    [Fact]
    public async Task SyncSingleAsync_ValidSignedManifestAndPayload_VerifiesAndParsesDomains()
    {
        byte[] secretKey = Convert.FromHexString(Vector1SecretKeyHex);
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);

        byte[] hostsPayload = """
            # Malw.link hosts feed
            0.0.0.0 localhost
            179.254.166.171 gemini.google.com
            179.254.166.171 aistudio.google.com
            """u8.ToArray();

        string shaHex = Convert.ToHexStringLower(SHA256.HashData(hostsPayload));
        byte[] manifestBytes = Encoding.UTF8.GetBytes($"{shaHex}  hosts\n");
        byte[] manifestSig = TestEd25519Sign(secretKey, publicKey, manifestBytes);

        using MockHttpMessageHandler handler = new(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["https://dns.malw.link/hosts"] = hostsPayload,
            ["https://dns.malw.link/SHA256SUMS.txt"] = manifestBytes,
            ["https://dns.malw.link/SHA256SUMS.txt.sig"] = manifestSig
        });

        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        using SignedFeedSyncService service = new(bootstrap, handler);

        FeedSourceDescriptor descriptor = new()
        {
            Id = "signed-hosts",
            Name = "Signed Hosts",
            Kind = FeedKind.BypassHosts,
            FeedUrl = "https://dns.malw.link/hosts",
            ManifestUrl = "https://dns.malw.link/SHA256SUMS.txt",
            SignatureUrl = "https://dns.malw.link/SHA256SUMS.txt.sig",
            ManifestFileName = "hosts",
            Ed25519PublicKey = ImmutableArray.Create(publicKey)
        };

        FeedSyncItemResult result = await service.SyncSingleAsync(descriptor, FeedVerificationMode.RequireSigned);

        result.VerificationStatus.Should().Be(FeedVerificationStatus.VerifiedSigned);
        result.BypassDomains.Should().BeEquivalentTo(ExpectedSignedDomains);
    }

    [Fact]
    public async Task SyncSingleAsync_TamperedManifestSignature_RejectsEvenInAllowUnsignedMode()
    {
        byte[] secretKey = Convert.FromHexString(Vector1SecretKeyHex);
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);

        byte[] hostsPayload = "179.254.166.171 gemini.google.com\n"u8.ToArray();
        string shaHex = Convert.ToHexStringLower(SHA256.HashData(hostsPayload));
        byte[] manifestBytes = Encoding.UTF8.GetBytes($"{shaHex}  hosts\n");
        byte[] tamperedSig = TestEd25519Sign(secretKey, publicKey, manifestBytes);
        tamperedSig[0] ^= 0xFF;

        using MockHttpMessageHandler handler = new(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["https://dns.malw.link/hosts"] = hostsPayload,
            ["https://dns.malw.link/SHA256SUMS.txt"] = manifestBytes,
            ["https://dns.malw.link/SHA256SUMS.txt.sig"] = tamperedSig
        });

        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        using SignedFeedSyncService service = new(bootstrap, handler);

        FeedSourceDescriptor descriptor = new()
        {
            Id = "tampered-sig",
            Name = "Tampered Sig Feed",
            Kind = FeedKind.BypassHosts,
            FeedUrl = "https://dns.malw.link/hosts",
            ManifestUrl = "https://dns.malw.link/SHA256SUMS.txt",
            SignatureUrl = "https://dns.malw.link/SHA256SUMS.txt.sig",
            ManifestFileName = "hosts",
            Ed25519PublicKey = ImmutableArray.Create(publicKey)
        };

        FeedSyncItemResult result = await service.SyncSingleAsync(descriptor, FeedVerificationMode.AllowUnsignedFeeds);

        result.VerificationStatus.Should().Be(FeedVerificationStatus.RejectedInvalidSignature);
        result.BypassDomains.Should().BeEmpty();
    }

    [Fact]
    public async Task SyncSingleAsync_TamperedPayloadChecksumMismatch_RejectsFeed()
    {
        byte[] secretKey = Convert.FromHexString(Vector1SecretKeyHex);
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);

        byte[] originalPayload = "179.254.166.171 gemini.google.com\n"u8.ToArray();
        byte[] tamperedPayload = "179.254.166.171 evil-spoof.example\n"u8.ToArray();
        string shaHex = Convert.ToHexStringLower(SHA256.HashData(originalPayload));
        byte[] manifestBytes = Encoding.UTF8.GetBytes($"{shaHex}  hosts\n");
        byte[] manifestSig = TestEd25519Sign(secretKey, publicKey, manifestBytes);

        using MockHttpMessageHandler handler = new(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["https://dns.malw.link/hosts"] = tamperedPayload,
            ["https://dns.malw.link/SHA256SUMS.txt"] = manifestBytes,
            ["https://dns.malw.link/SHA256SUMS.txt.sig"] = manifestSig
        });

        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        using SignedFeedSyncService service = new(bootstrap, handler);

        FeedSourceDescriptor descriptor = new()
        {
            Id = "tampered-payload",
            Name = "Tampered Payload Feed",
            Kind = FeedKind.BypassHosts,
            FeedUrl = "https://dns.malw.link/hosts",
            ManifestUrl = "https://dns.malw.link/SHA256SUMS.txt",
            SignatureUrl = "https://dns.malw.link/SHA256SUMS.txt.sig",
            ManifestFileName = "hosts",
            Ed25519PublicKey = ImmutableArray.Create(publicKey)
        };

        FeedSyncItemResult result = await service.SyncSingleAsync(descriptor, FeedVerificationMode.RequireSigned);

        result.VerificationStatus.Should().Be(FeedVerificationStatus.RejectedChecksumMismatch);
        result.BypassDomains.Should().BeEmpty();
    }

    [Fact]
    public async Task SyncSingleAsync_UnsignedCommunityFeed_RejectedInRequireSignedAndAcceptedInOptInMode()
    {
        byte[] markdown = """
            # HB-AI Community DNS
            - DoH: https://dns.malw.link/dns-query
            - IPv4: 179.254.166.171
            - Ignore private IP: 192.168.1.1
            """u8.ToArray();

        using MockHttpMessageHandler handler = new(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["https://raw.githubusercontent.com/neiroseti-ai/hb-ai-xbox-dns/main/README.md"] = markdown
        });

        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        using SignedFeedSyncService service = new(bootstrap, handler);

        FeedSourceDescriptor unsignedFeed = SignedFeedSyncService.BuiltInFeeds[2];

        FeedSyncItemResult rejected = await service.SyncSingleAsync(unsignedFeed, FeedVerificationMode.RequireSigned);
        rejected.VerificationStatus.Should().Be(FeedVerificationStatus.RejectedMissingSignature);
        rejected.DiscoveredServers.Should().BeEmpty();

        FeedSyncItemResult accepted = await service.SyncSingleAsync(unsignedFeed, FeedVerificationMode.AllowUnsignedFeeds);
        accepted.VerificationStatus.Should().Be(FeedVerificationStatus.UnsignedAcceptedOptIn);
        accepted.DiscoveredServers.Should().HaveCount(2);
        accepted.DiscoveredServers.Should().NotContain(s => s.PrimaryIp == "192.168.1.1");
    }

    [Fact]
    public void BuiltInFeeds_ContainExpectedV153Urls()
    {
        SignedFeedSyncService.BuiltInFeeds.Should().HaveCount(4);
        SignedFeedSyncService.BuiltInFeeds.Select(f => f.FeedUrl).Should().Contain(ExpectedBuiltInFeedUrls);
    }

    [Fact]
    public void CuratedRepositoryFeedsAndParsers_ExtractDnsServersDomainsAndIpCidrs()
    {
        SignedFeedSyncService.AllCuratedFeeds.Should().HaveCountGreaterThanOrEqualTo(15);
        SignedFeedSyncService.CuratedRepositoryFeeds.Should().Contain(static f => f.Category == FeedCategory.DnsServers);
        SignedFeedSyncService.CuratedRepositoryFeeds.Should().Contain(static f => f.Category == FeedCategory.DomainList);
        SignedFeedSyncService.CuratedRepositoryFeeds.Should().Contain(static f => f.Category == FeedCategory.IpSubnetList);

        string domainContent = """
            # v2fly geosite style
            full:aistudio.google.com
            domain:openai.com
            claude.ai @ads
            include:ignored-ref
            """;
        IReadOnlyList<string> parsedDomains = SignedFeedSyncService.ParseDomainListCommunity(domainContent);
        parsedDomains.Should().Contain(ExpectedParsedDomains);
        parsedDomains.Should().NotContain(static d => d.Contains("include:", StringComparison.OrdinalIgnoreCase));

        string ipContent = """
            # Public IPv4 ranges and bogon filter
            104.18.0.0/16
            127.0.0.1
            192.168.1.0/24
            162.159.135.232
            """;
        IReadOnlyList<string> parsedIps = SignedFeedSyncService.ParseIpCidrList(ipContent);
        parsedIps.Should().Contain(ExpectedParsedIps);
        parsedIps.Should().NotContain(static ip => ip.StartsWith("127.", StringComparison.Ordinal) || ip.StartsWith("192.168.", StringComparison.Ordinal));

        string plainResolvers = """
            # Public resolver list
            1.1.1.1
            https://dns.quad9.net/dns-query
            tls://dns.adguard-dns.com
            192.168.0.1
            """;
        IReadOnlyList<DnsServerEntry> parsedResolvers = SignedFeedSyncService.ParsePlainResolverList(plainResolvers, "PublicList");
        parsedResolvers.Should().HaveCount(3);
        parsedResolvers.Should().NotContain(static s => s.PrimaryIp == "192.168.0.1");

        FeedSourceDescriptor customIpDesc = SignedFeedSyncService.CreateCustomUrlDescriptor("https://raw.githubusercontent.com/example/repo/main/cidr-ips.txt");
        customIpDesc.Category.Should().Be(FeedCategory.IpSubnetList);
        customIpDesc.Kind.Should().Be(FeedKind.IpCidrList);
    }

    [Fact]
    public async Task SyncStartupFeedsAsync_BuiltInCommunityTrusted_SavesAndFallsBackToOfflineCache_WhileRejectingUntrustedUnsigned()
    {
        byte[] hostsPayload = Encoding.UTF8.GetBytes("185.236.10.37 gemini.google.com\n185.236.10.37 aistudio.google.com\n");
        byte[] quickDnsPayload = Encoding.UTF8.GetBytes("""
            {
              "profiles": [
                { "name": "Geo Node", "primary_ip": "192.255.159.240", "doh_url": "https://smart.example/dns-query" }
              ]
            }
            """);
        byte[] mdPayload = Encoding.UTF8.GetBytes("Mirror: https://mirror.example/dns-query\n");

        Dictionary<string, byte[]> onlineResponses = new(StringComparer.Ordinal)
        {
            [SignedFeedSyncService.BuiltInFeeds[0].FeedUrl] = hostsPayload,
            [SignedFeedSyncService.BuiltInFeeds[1].FeedUrl] = quickDnsPayload,
            [SignedFeedSyncService.BuiltInFeeds[2].FeedUrl] = mdPayload,
            [SignedFeedSyncService.BuiltInFeeds[3].FeedUrl] = mdPayload
        };

        string cacheFile = Path.Combine(Path.GetTempPath(), $"dnspulse_feed_cache_{Guid.NewGuid():N}.json");
        try
        {
            IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();

            using (MockHttpMessageHandler onlineHandler = new(onlineResponses))
            using (SignedFeedSyncService onlineService = new(bootstrap, customHandler: onlineHandler))
            {
                FeedStartupSyncResult startup = await onlineService.SyncStartupFeedsAsync(
                    cacheFile,
                    FeedVerificationMode.BuiltInCommunityTrusted);

                startup.UpdatedCacheFromNetwork.Should().BeTrue();
                startup.EffectiveBypassDomains.Should().Contain(["gemini.google.com", "aistudio.google.com"]);
                startup.EffectiveDiscoveredServers.Should().HaveCountGreaterThanOrEqualTo(2);

                // BuiltInCommunityTrusted MUST still fail closed on unknown unsigned third-party feeds!
                FeedSourceDescriptor rogueUnsigned = new()
                {
                    Id = "rogue-unsigned",
                    Name = "Rogue",
                    Kind = FeedKind.BypassHosts,
                    FeedUrl = "https://rogue.example/hosts"
                };
                FeedSyncItemResult rogueResult = await onlineService.SyncSingleAsync(
                    rogueUnsigned,
                    FeedVerificationMode.BuiltInCommunityTrusted);
                rogueResult.VerificationStatus.Should().Be(FeedVerificationStatus.RejectedMissingSignature);
            }

            // Offline startup loads cached domains and servers cleanly when network returns 404.
            using MockHttpMessageHandler offlineHandler = new(new Dictionary<string, byte[]>());
            using SignedFeedSyncService offlineService = new(bootstrap, customHandler: offlineHandler);
            FeedStartupSyncResult offlineStartup = await offlineService.SyncStartupFeedsAsync(
                cacheFile,
                FeedVerificationMode.BuiltInCommunityTrusted);

            offlineStartup.LoadedFromCache.Should().BeTrue();
            offlineStartup.UpdatedCacheFromNetwork.Should().BeFalse();
            offlineStartup.EffectiveBypassDomains.Should().Contain(["gemini.google.com", "aistudio.google.com"]);
            offlineStartup.EffectiveDiscoveredServers.Should().HaveCountGreaterThanOrEqualTo(2);
        }
        finally
        {
            if (File.Exists(cacheFile))
            {
                File.Delete(cacheFile);
            }
        }
    }

    private sealed class MockHttpMessageHandler(IReadOnlyDictionary<string, byte[]> responses) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri?.AbsoluteUri ?? string.Empty;
            if (responses.TryGetValue(url, out byte[]? body))
            {
                HttpResponseMessage ok = new(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(body)
                };
                return Task.FromResult(ok);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private static byte[] TestEd25519Sign(
        ReadOnlySpan<byte> secretKey,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message)
    {
        BigInteger p = (BigInteger.One << 255) - 19;
        BigInteger l = (BigInteger.One << 252)
            + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
        BigInteger d = Mod(-121665 * BigInteger.ModPow(121666, p - 2, p), p);
        BigInteger sqrtM1 = BigInteger.ModPow(2, (p - 1) / 4, p);

        BigInteger by = Mod(4 * BigInteger.ModPow(5, p - 2, p), p);
        BigInteger bx = RecoverX(by, p, d, sqrtM1);

        byte[] h = SHA512.HashData(secretKey);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;

        BigInteger a = new(h.AsSpan(0, 32), isUnsigned: true, isBigEndian: false);

        byte[] rDigest = new byte[64];
        using (IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
        {
            sha.AppendData(h.AsSpan(32, 32));
            sha.AppendData(message);
            sha.GetHashAndReset(rDigest);
        }

        BigInteger r = new BigInteger(rDigest, isUnsigned: true, isBigEndian: false) % l;
        (BigInteger rx, BigInteger ry) = ScalarMul(r, bx, by, p, d);
        byte[] rEncoded = EncodePoint(rx, ry);

        byte[] kDigest = new byte[64];
        using (IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
        {
            sha.AppendData(rEncoded);
            sha.AppendData(publicKey);
            sha.AppendData(message);
            sha.GetHashAndReset(kDigest);
        }

        BigInteger k = new BigInteger(kDigest, isUnsigned: true, isBigEndian: false) % l;
        BigInteger s = (r + k * a) % l;

        byte[] signature = new byte[64];
        rEncoded.CopyTo(signature, 0);
        s.TryWriteBytes(signature.AsSpan(32, 32), out _, isUnsigned: true, isBigEndian: false);
        return signature;
    }

    private static byte[] EncodePoint(BigInteger x, BigInteger y)
    {
        byte[] encoded = new byte[32];
        y.TryWriteBytes(encoded, out _, isUnsigned: true, isBigEndian: false);
        if ((x & BigInteger.One) == BigInteger.One)
        {
            encoded[31] |= 0x80;
        }

        return encoded;
    }

    private static (BigInteger X, BigInteger Y) ScalarMul(
        BigInteger scalar,
        BigInteger bx,
        BigInteger by,
        BigInteger p,
        BigInteger d)
    {
        BigInteger x = BigInteger.Zero;
        BigInteger y = BigInteger.One;
        BigInteger curX = bx;
        BigInteger curY = by;

        while (!scalar.IsZero)
        {
            if ((scalar & BigInteger.One) == BigInteger.One)
            {
                (x, y) = EdwardsAdd(x, y, curX, curY, p, d);
            }

            (curX, curY) = EdwardsAdd(curX, curY, curX, curY, p, d);
            scalar >>= 1;
        }

        return (x, y);
    }

    private static (BigInteger X, BigInteger Y) EdwardsAdd(
        BigInteger x1,
        BigInteger y1,
        BigInteger x2,
        BigInteger y2,
        BigInteger p,
        BigInteger d)
    {
        BigInteger x1x2 = Mod(x1 * x2, p);
        BigInteger y1y2 = Mod(y1 * y2, p);
        BigInteger dxxyy = Mod(d * Mod(x1x2 * y1y2, p), p);
        BigInteger x3 = Mod(Mod(x1 * y2 + x2 * y1, p) * BigInteger.ModPow(Mod(BigInteger.One + dxxyy, p), p - 2, p), p);
        BigInteger y3 = Mod(Mod(y1y2 + x1x2, p) * BigInteger.ModPow(Mod(BigInteger.One - dxxyy, p), p - 2, p), p);
        return (x3, y3);
    }

    private static BigInteger RecoverX(BigInteger y, BigInteger p, BigInteger d, BigInteger sqrtM1)
    {
        BigInteger y2 = Mod(y * y, p);
        BigInteger u = Mod(y2 - 1, p);
        BigInteger v = Mod(d * y2 + 1, p);
        BigInteger x = Mod(u * BigInteger.ModPow(v, 3, p) * BigInteger.ModPow(Mod(u * BigInteger.ModPow(v, 7, p), p), (p - 5) / 8, p), p);
        if (Mod(v * x * x, p) != u)
        {
            x = Mod(x * sqrtM1, p);
        }

        if ((x & BigInteger.One) == BigInteger.One)
        {
            x = p - x;
        }

        return x;
    }

    private static BigInteger Mod(BigInteger v, BigInteger p)
    {
        BigInteger r = v % p;
        return r.Sign < 0 ? r + p : r;
    }
}
