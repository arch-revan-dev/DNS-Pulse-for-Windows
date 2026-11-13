using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Pipeline;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Pipeline;

public sealed class PulseCoreDnsEngineTests
{
    private static readonly byte[] SampleEchPayload = [0xFE, 0x0D, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04];

    [Fact]
    public async Task ResolveAsync_Zone1LocalAndCorporate_RoutesToLocalBypassAndAllowsPrivateIps()
    {
        using OptimisticDnsCache cache = new();
        SplitNamespaceRouter router = new(new SplitNamespaceRouterConfig
        {
            LocalBypassProfileId = "corp-dns",
            CorporateBypassDomains = ["corp.internal.example"],
            GeoUnlockRules = [new GeoUnlockRule("corp.internal.example", "sni-us")],
            BlockRules = ["||corp.internal.example^"]
        });

        DnsServerEntry localServer = new()
        {
            Id = "corp-dns",
            Name = "Corp LAN DNS",
            Protocol = DnsProtocol.Udp,
            TrustTier = TrustTier.Tier3CustomOrSelfHosted,
            PrimaryIp = "192.168.1.1"
        };
        DnsServerEntry zone4Server = CreateTier1Doh("cf-doh", "1.1.1.1", 10);

        IDnsUpstreamClient udpClient = Substitute.For<IDnsUpstreamClient>();
        udpClient.Protocol.Returns(DnsProtocol.Udp);
        udpClient.QueryAsync(Arg.Any<DnsMessage>(), localServer, Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                DnsMessage resp = CreateAResponse(q, "10.20.30.40");
                return new UpstreamQueryResult(resp, TimeSpan.FromMilliseconds(2), "192.168.1.1:53", DnsProtocol.Udp);
            });

        IDnsUpstreamClient dohClient = Substitute.For<IDnsUpstreamClient>();
        dohClient.Protocol.Returns(DnsProtocol.DoH);

        UpstreamPoolManager pool = new([zone4Server]);
        PulseCoreDnsEngine engine = new(
            router,
            cache,
            pool,
            new Dictionary<DnsProtocol, IDnsUpstreamClient>
            {
                [DnsProtocol.Udp] = udpClient,
                [DnsProtocol.DoH] = dohClient
            },
            new PulseCoreEngineOptions
            {
                LocalBypassUpstreams = [localServer]
            });

        DnsMessage query = DnsMessage.CreateQuery(42, "api.corp.internal.example", DnsRecordType.A);
        DnsMessage response = await engine.ResolveAsync(query);

        response.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        response.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("10.20.30.40")));
        await udpClient.Received(1).QueryAsync(Arg.Any<DnsMessage>(), localServer, Arg.Any<CancellationToken>());
        await dohClient.DidNotReceive().QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResolveAsync_Zone2BlockAndSecurityPinning_EnforcesPrecedence()
    {
        using OptimisticDnsCache cache = new();
        SplitNamespaceRouter router = new(new SplitNamespaceRouterConfig
        {
            BlockRules = ["||ads.tracker.example^", "||github.com^"],
            GeoUnlockRules = [new GeoUnlockRule("github.com", "sni-us")]
        });

        DnsServerEntry tier1Doh = CreateTier1Doh("quad9", "9.9.9.9", 15);
        IDnsUpstreamClient dohClient = Substitute.For<IDnsUpstreamClient>();
        dohClient.Protocol.Returns(DnsProtocol.DoH);
        dohClient.QueryAsync(Arg.Any<DnsMessage>(), tier1Doh, Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                return new UpstreamQueryResult(
                    CreateAResponse(q, "140.82.121.4"),
                    TimeSpan.FromMilliseconds(12),
                    tier1Doh.DohUrl!,
                    DnsProtocol.DoH);
            });

        UpstreamPoolManager pool = new([tier1Doh]);
        PulseCoreDnsEngine engine = new(
            router,
            cache,
            pool,
            new Dictionary<DnsProtocol, IDnsUpstreamClient> { [DnsProtocol.DoH] = dohClient });

        // Blocked domain returns NXDOMAIN without upstream call.
        DnsMessage blockedResponse = await engine.ResolveAsync(DnsMessage.CreateQuery(10, "ads.tracker.example", DnsRecordType.A));
        blockedResponse.EffectiveResponseCode.Should().Be(DnsResponseCode.NxDomain);
        blockedResponse.Answers.Should().BeEmpty();

        // Security-pinned domain overrides both blocklist and GeoUnlock and uses Zone 4 Tier-1 DoH.
        DnsMessage pinnedResponse = await engine.ResolveAsync(DnsMessage.CreateQuery(11, "api.github.com", DnsRecordType.A));
        pinnedResponse.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        pinnedResponse.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("140.82.121.4")));
        await dohClient.Received(1).QueryAsync(Arg.Any<DnsMessage>(), tier1Doh, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResolveAsync_Zone4RejectsTier4LabServerAndUsesOnlyTier1()
    {
        using OptimisticDnsCache cache = new();
        SplitNamespaceRouter router = new();

        DnsServerEntry tier4Lab = new()
        {
            Id = "lab-tier4",
            Name = "Experimental Lab",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier4ExperimentalLab,
            PrimaryIp = "198.51.100.10",
            DohUrl = "https://lab.example/dns-query",
            LastLatencyMs = 2
        };
        DnsServerEntry tier1Trusted = CreateTier1Doh("trusted-tier1", "1.1.1.1", 25);

        IDnsUpstreamClient dohClient = Substitute.For<IDnsUpstreamClient>();
        dohClient.Protocol.Returns(DnsProtocol.DoH);
        dohClient.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                DnsServerEntry upstream = callInfo.Arg<DnsServerEntry>();
                return new UpstreamQueryResult(
                    CreateAResponse(q, "93.184.216.34"),
                    TimeSpan.FromMilliseconds(15),
                    upstream.DohUrl!,
                    DnsProtocol.DoH);
            });

        UpstreamPoolManager pool = new([tier4Lab, tier1Trusted]);
        PulseCoreDnsEngine engine = new(
            router,
            cache,
            pool,
            new Dictionary<DnsProtocol, IDnsUpstreamClient> { [DnsProtocol.DoH] = dohClient });

        DnsMessage response = await engine.ResolveAsync(DnsMessage.CreateQuery(55, "example.org", DnsRecordType.A));

        response.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        await dohClient.DidNotReceive().QueryAsync(Arg.Any<DnsMessage>(), tier4Lab, Arg.Any<CancellationToken>());
        await dohClient.Received(1).QueryAsync(Arg.Any<DnsMessage>(), tier1Trusted, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResolveAsync_Zone3SniProxySynthesizesAAndStripsAaaaAndHttps_WhileZone4PreservesEch()
    {
        using OptimisticDnsCache cache = new();
        SplitNamespaceRouter router = new(new SplitNamespaceRouterConfig
        {
            GeoUnlockRules =
            [
                new GeoUnlockRule("gemini.google.com", "sni-de"),
                new GeoUnlockRule("smart.streaming.example", "smart-doh")
            ]
        });

        DnsServerEntry sniProxy = new()
        {
            Id = "sni-de",
            Name = "SNI Proxy DE",
            Protocol = DnsProtocol.SniProxy,
            TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
            PrimaryIp = "203.0.113.50",
            SmartProxyIp = "203.0.113.50"
        };

        DnsServerEntry smartDoh = new()
        {
            Id = "smart-doh",
            Name = "Smart GeoUnlock DoH",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
            PrimaryIp = "198.51.100.77",
            DohUrl = "https://smart.example/dns-query"
        };

        DnsServerEntry tier1Doh = CreateTier1Doh("cf-tier1", "1.1.1.1", 10);

        IDnsUpstreamClient dohClient = Substitute.For<IDnsUpstreamClient>();
        dohClient.Protocol.Returns(DnsProtocol.DoH);
        dohClient.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                DnsServerEntry upstream = callInfo.Arg<DnsServerEntry>();
                string domain = q.Questions[0].Name;
                DnsResourceRecord httpsRecord = DnsResourceRecord.CreateHttps(
                    domain,
                    1,
                    ".",
                    [
                        SvcParam.CreateAlpn(["h3", "h2"]),
                        SvcParam.CreateIpv4Hint([IPAddress.Parse("93.184.216.20")]),
                        SvcParam.CreateEch(SampleEchPayload),
                        SvcParam.CreateIpv6Hint([IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946")])
                    ],
                    ttl: 300);

                DnsMessage resp = new()
                {
                    Header = new DnsHeader
                    {
                        Id = q.Header.Id,
                        IsResponse = true,
                        ResponseCode = DnsResponseCode.NoError,
                        QuestionCount = 1,
                        AnswerCount = 2
                    },
                    Questions = q.Questions,
                    Answers =
                    [
                        DnsResourceRecord.CreateAaaa(domain, IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946"), 300),
                        httpsRecord
                    ]
                };

                return new UpstreamQueryResult(resp, TimeSpan.FromMilliseconds(10), upstream.DohUrl!, DnsProtocol.DoH);
            });

        UpstreamPoolManager pool = new([tier1Doh]);
        PulseCoreDnsEngine engine = new(
            router,
            cache,
            pool,
            new Dictionary<DnsProtocol, IDnsUpstreamClient> { [DnsProtocol.DoH] = dohClient },
            new PulseCoreEngineOptions
            {
                GeoUnlockUpstreams = [sniProxy, smartDoh]
            });

        // 1. SNI-Proxy synthesizes A and strips AAAA / HTTPS(65) to NOERROR NODATA.
        DnsMessage sniA = await engine.ResolveAsync(DnsMessage.CreateQuery(1, "gemini.google.com", DnsRecordType.A));
        sniA.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        sniA.Answers.Should().ContainSingle(a => a.RecordType == DnsRecordType.A && Equals(a.Address, IPAddress.Parse("203.0.113.50")));

        DnsMessage sniAaaa = await engine.ResolveAsync(DnsMessage.CreateQuery(2, "gemini.google.com", DnsRecordType.AAAA));
        sniAaaa.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        sniAaaa.Answers.Should().BeEmpty();

        DnsMessage sniHttps = await engine.ResolveAsync(DnsMessage.CreateQuery(3, "gemini.google.com", DnsRecordType.HTTPS));
        sniHttps.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        sniHttps.Answers.Should().BeEmpty();

        // 2. Smart-DNS Zone 3 rewrites HTTPS(65): strips AAAA, ipv4hint, ipv6hint, and h3 while keeping h2.
        DnsMessage smartHttps = await engine.ResolveAsync(DnsMessage.CreateQuery(4, "smart.streaming.example", DnsRecordType.HTTPS));
        smartHttps.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        smartHttps.Answers.Should().ContainSingle(r => r.RecordType == DnsRecordType.HTTPS);
        DnsResourceRecord rewrittenHttps = smartHttps.Answers[0];
        rewrittenHttps.SvcParams.Select(p => p.KnownKey).Should().NotContain(SvcParamKey.Ipv4Hint);
        rewrittenHttps.SvcParams.Select(p => p.KnownKey).Should().NotContain(SvcParamKey.Ipv6Hint);
        rewrittenHttps.SvcParams.Single(p => p.KnownKey == SvcParamKey.Alpn).ParseAlpnIds().Should().ContainSingle().Which.Should().Be("h2");

        // 3. Zone 4 Direct preserves HTTPS(65), AAAA, hints, h3, and ECH intact.
        DnsMessage zone4Https = await engine.ResolveAsync(DnsMessage.CreateQuery(5, "cloudflare.com", DnsRecordType.HTTPS));
        zone4Https.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        zone4Https.Answers.Should().Contain(r => r.RecordType == DnsRecordType.AAAA);
        DnsResourceRecord zone4Record = zone4Https.Answers.Single(r => r.RecordType == DnsRecordType.HTTPS);
        zone4Record.SvcParams.Should().Contain(p => p.KnownKey == SvcParamKey.Ech);
        zone4Record.SvcParams.Should().Contain(p => p.KnownKey == SvcParamKey.Ipv4Hint);
    }

    [Fact]
    public async Task ResolveAsync_Zone4Rebinding127001Answer_IsRejectedAndNotCached()
    {
        using OptimisticDnsCache cache = new();
        SplitNamespaceRouter router = new();
        DnsServerEntry tier1Doh = CreateTier1Doh("cf", "1.1.1.1", 10);

        IDnsUpstreamClient dohClient = Substitute.For<IDnsUpstreamClient>();
        dohClient.Protocol.Returns(DnsProtocol.DoH);
        dohClient.QueryAsync(Arg.Any<DnsMessage>(), tier1Doh, Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                return new UpstreamQueryResult(
                    CreateAResponse(q, "127.0.0.1"),
                    TimeSpan.FromMilliseconds(5),
                    tier1Doh.DohUrl!,
                    DnsProtocol.DoH);
            });

        UpstreamPoolManager pool = new([tier1Doh]);
        PulseCoreDnsEngine engine = new(
            router,
            cache,
            pool,
            new Dictionary<DnsProtocol, IDnsUpstreamClient> { [DnsProtocol.DoH] = dohClient });

        DnsMessage response = await engine.ResolveAsync(DnsMessage.CreateQuery(99, "rebind.attacker.example", DnsRecordType.A));

        response.EffectiveResponseCode.Should().Be(DnsResponseCode.ServFail);
        response.Answers.Should().BeEmpty();
        cache.Count.Should().Be(0);
    }

    [Fact]
    public async Task ResolveAsync_Zone4ParallelStrategy_RacesTop2AndRejectsPoisonedWinner()
    {
        using OptimisticDnsCache cache = new();
        SplitNamespaceRouter router = new();
        DnsServerEntry fastPoisoned = CreateTier1Doh("fast-poison", "1.1.1.1", 5);
        DnsServerEntry cleanBackup = CreateTier1Doh("clean-backup", "8.8.8.8", 15);

        IDnsUpstreamClient dohClient = Substitute.For<IDnsUpstreamClient>();
        dohClient.Protocol.Returns(DnsProtocol.DoH);
        dohClient.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(async callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                DnsServerEntry upstream = callInfo.Arg<DnsServerEntry>();
                CancellationToken ct = callInfo.Arg<CancellationToken>();

                if (upstream.Id == "fast-poison")
                {
                    return new UpstreamQueryResult(
                        CreateAResponse(q, "127.0.0.1"),
                        TimeSpan.FromMilliseconds(2),
                        upstream.DohUrl!,
                        DnsProtocol.DoH);
                }

                await Task.Delay(25, ct).ConfigureAwait(false);
                return new UpstreamQueryResult(
                    CreateAResponse(q, "93.184.216.34"),
                    TimeSpan.FromMilliseconds(25),
                    upstream.DohUrl!,
                    DnsProtocol.DoH);
            });

        UpstreamPoolManager pool = new([fastPoisoned, cleanBackup]);
        PulseCoreDnsEngine engine = new(
            router,
            cache,
            pool,
            new Dictionary<DnsProtocol, IDnsUpstreamClient> { [DnsProtocol.DoH] = dohClient },
            new PulseCoreEngineOptions
            {
                Zone4Strategy = PoolSelectionStrategy.Parallel
            });

        DnsMessage response = await engine.ResolveAsync(DnsMessage.CreateQuery(77, "parallel.example.com", DnsRecordType.A));

        response.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        response.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("93.184.216.34")));
        engine.Telemetry.Count.Should().Be(1);

        // Second identical query is served from cache without calling upstream.
        DnsMessage cached = await engine.ResolveAsync(DnsMessage.CreateQuery(78, "parallel.example.com", DnsRecordType.A));
        cached.Header.Id.Should().Be(78);
        cached.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("93.184.216.34")));
        await dohClient.Received(2).QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>());
    }

    private static DnsServerEntry CreateTier1Doh(string id, string ip, double latencyMs)
    {
        return new DnsServerEntry
        {
            Id = id,
            Name = id,
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            PrimaryIp = ip,
            DohUrl = $"https://{id}.example/dns-query",
            LastLatencyMs = latencyMs
        };
    }

    private static DnsMessage CreateAResponse(DnsMessage query, string ip)
    {
        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = query.Header.Id,
                IsResponse = true,
                RecursionDesired = query.Header.RecursionDesired,
                RecursionAvailable = true,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = (ushort)query.Questions.Count,
                AnswerCount = 1
            },
            Questions = query.Questions,
            Answers = [DnsResourceRecord.CreateA(query.Questions[0].Name, IPAddress.Parse(ip), 120)]
        };
    }
}
