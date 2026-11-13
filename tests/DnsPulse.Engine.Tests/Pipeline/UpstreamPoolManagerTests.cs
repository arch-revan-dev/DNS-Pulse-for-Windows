using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Pipeline;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Pipeline;

public sealed class UpstreamPoolManagerTests
{
    [Fact]
    public void Zone4Pool_RejectsTier2Tier3Tier4AndUnencryptedServers()
    {
        DnsServerEntry validDoh = CreateEntry("cf-doh", DnsProtocol.DoH, TrustTier.Tier1EncryptedTrusted, latencyMs: 12);
        DnsServerEntry validDot = CreateEntry("quad9-dot", DnsProtocol.DoT, TrustTier.Tier1EncryptedTrusted, latencyMs: 20);
        DnsServerEntry tier4Lab = CreateEntry("lab-doh", DnsProtocol.DoH, TrustTier.Tier4ExperimentalLab, latencyMs: 5);
        DnsServerEntry tier2Geo = CreateEntry("geo-doh", DnsProtocol.DoH, TrustTier.Tier2VerifiedGeoUnlock, latencyMs: 5);
        DnsServerEntry tier3Custom = CreateEntry("custom-doh", DnsProtocol.DoH, TrustTier.Tier3CustomOrSelfHosted, latencyMs: 5);
        DnsServerEntry plainUdp = CreateEntry("plain-udp", DnsProtocol.Udp, TrustTier.Tier1EncryptedTrusted, latencyMs: 3);
        DnsServerEntry sniProxy = CreateEntry("sni-proxy", DnsProtocol.SniProxy, TrustTier.Tier1EncryptedTrusted, latencyMs: 3);

        UpstreamPoolManager pool = new([validDoh, tier4Lab, tier2Geo, tier3Custom, plainUdp, sniProxy, validDot]);

        pool.Zone4Servers.Select(s => s.Id).Should().Equal("cf-doh", "quad9-dot");
        pool.RejectedZone4Servers.Select(s => s.Id).Should().Equal(
            "lab-doh", "geo-doh", "custom-doh", "plain-udp", "sni-proxy");

        pool.TryAddZone4Server(tier4Lab).Should().BeFalse();
        Action act = () => pool.AddZone4Server(tier4Lab);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void SelectCandidates_FastestAndLoadBalance_OrderProperly()
    {
        DnsServerEntry s1 = CreateEntry("s1", DnsProtocol.DoH, TrustTier.Tier1EncryptedTrusted, latencyMs: 40);
        DnsServerEntry s2 = CreateEntry("s2", DnsProtocol.DoH, TrustTier.Tier1EncryptedTrusted, latencyMs: 10);
        DnsServerEntry s3 = CreateEntry("s3", DnsProtocol.DoT, TrustTier.Tier1EncryptedTrusted, latencyMs: 25);

        UpstreamPoolManager pool = new([s1, s2, s3]);
        pool.RecordSuccess(s1, 60);
        pool.RecordSuccess(s2, 8);
        pool.RecordSuccess(s3, 20);

        IReadOnlyList<DnsServerEntry> fastest = pool.SelectCandidates(pool.Zone4Servers, PoolSelectionStrategy.Fastest);
        fastest.Select(s => s.Id).Should().ContainInOrder("s2", "s3", "s1");

        IReadOnlyList<DnsServerEntry> rr1 = pool.SelectCandidates(pool.Zone4Servers, PoolSelectionStrategy.LoadBalance);
        IReadOnlyList<DnsServerEntry> rr2 = pool.SelectCandidates(pool.Zone4Servers, PoolSelectionStrategy.LoadBalance);
        rr1[0].Id.Should().NotBe(rr2[0].Id);
    }

    [Fact]
    public async Task QueryZone4Async_ParallelRace_SelectsFirstValidNonPoisonedAnswer()
    {
        DnsServerEntry fastPoisoned = CreateEntry("fast-poison", DnsProtocol.DoH, TrustTier.Tier1EncryptedTrusted, latencyMs: 5);
        DnsServerEntry cleanBackup = CreateEntry("clean-backup", DnsProtocol.DoH, TrustTier.Tier1EncryptedTrusted, latencyMs: 15);
        UpstreamPoolManager pool = new([fastPoisoned, cleanBackup]);

        DnsMessage poisonedAnswer = CreateAResponse("example.com", "127.0.0.1");
        DnsMessage cleanAnswer = CreateAResponse("example.com", "93.184.216.34");

        PoolExecutionResult outcome = await pool.QueryZone4Async(
            PoolSelectionStrategy.Parallel,
            async (server, ct) =>
            {
                if (server.Id == "fast-poison")
                {
                    return new UpstreamQueryResult(poisonedAnswer, TimeSpan.FromMilliseconds(2), server.EndpointLabel, server.Protocol);
                }

                await Task.Delay(25, ct).ConfigureAwait(false);
                return new UpstreamQueryResult(cleanAnswer, TimeSpan.FromMilliseconds(25), server.EndpointLabel, server.Protocol);
            },
            responseValidator: (res, _) => !res.Response.Answers.Any(a => IPAddress.IsLoopback(a.Address!)));

        outcome.Succeeded.Should().BeTrue();
        outcome.ServerUsed!.Id.Should().Be("clean-backup");
        outcome.QueryResult!.Response.Answers[0].Address.Should().Be(IPAddress.Parse("93.184.216.34"));
    }

    private static DnsServerEntry CreateEntry(string id, DnsProtocol protocol, TrustTier tier, double latencyMs)
    {
        return new DnsServerEntry
        {
            Id = id,
            Name = id,
            Protocol = protocol,
            TrustTier = tier,
            PrimaryIp = "1.1.1.1",
            DohUrl = protocol == DnsProtocol.DoH ? $"https://{id}.example/dns-query" : null,
            DotHost = protocol == DnsProtocol.DoT ? $"{id}.example" : null,
            LastLatencyMs = latencyMs
        };
    }

    private static DnsMessage CreateAResponse(string domain, string ip)
    {
        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = 1,
                IsResponse = true,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = 1,
                AnswerCount = 1
            },
            Questions = [DnsQuestion.Create(domain, DnsRecordType.A)],
            Answers = [DnsResourceRecord.CreateA(domain, IPAddress.Parse(ip), 60)]
        };
    }
}
