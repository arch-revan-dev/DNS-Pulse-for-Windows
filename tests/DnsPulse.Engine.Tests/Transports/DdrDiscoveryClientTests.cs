using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class DdrDiscoveryClientTests
{
    [Fact]
    public void ParseSvcbResponse_ExtractsDoH3DoHDoTDoQCandidatesOrderedByPriority()
    {
        DnsMessage response = new()
        {
            Header = new DnsHeader
            {
                Id = 99,
                IsResponse = true,
                QuestionCount = 1,
                AnswerCount = 3,
                AdditionalCount = 1
            },
            Questions = [DnsQuestion.Create(DdrDiscoveryClient.ResolverArpaDomain, DnsRecordType.SVCB)],
            Answers =
            [
                // AliasMode (priority 0) must be skipped
                DnsResourceRecord.CreateSvcb(DdrDiscoveryClient.ResolverArpaDomain, 0, "alias.dns.example"),
                DnsResourceRecord.CreateSvcb(
                    DdrDiscoveryClient.ResolverArpaDomain,
                    2,
                    "dns.example.net",
                    [
                        SvcParam.CreateAlpn(["dot", "doq"]),
                        SvcParam.CreatePort(8853),
                        SvcParam.CreateIpv4Hint([IPAddress.Parse("1.1.1.1")])
                    ]),
                DnsResourceRecord.CreateSvcb(
                    DdrDiscoveryClient.ResolverArpaDomain,
                    1,
                    "dns.example.net",
                    [
                        SvcParam.CreateAlpn(["h3", "h2"]),
                        SvcParam.CreateIpv4Hint([IPAddress.Parse("1.1.1.1")]),
                        SvcParam.CreateIpv6Hint([IPAddress.Parse("2606:4700:4700::1111")]),
                        SvcParam.CreateRaw(7, System.Text.Encoding.UTF8.GetBytes("/custom-dns{?dns}"))
                    ])
            ],
            Additionals =
            [
                DnsResourceRecord.CreateA("dns.example.net", IPAddress.Parse("1.0.0.1"))
            ]
        };

        IReadOnlyList<DnsServerEntry> discovered = DdrDiscoveryClient.ParseSvcbResponse(response, "Cloudflare Seed");

        discovered.Should().HaveCount(4);

        discovered[0].Protocol.Should().Be(DnsProtocol.DoH3);
        discovered[0].DohUrl.Should().Be("https://dns.example.net/custom-dns");
        discovered[0].BootstrapIps.Should().Contain(["1.1.1.1", "2606:4700:4700::1111", "1.0.0.1"]);

        discovered[1].Protocol.Should().Be(DnsProtocol.DoH);
        discovered[1].DohUrl.Should().Be("https://dns.example.net/custom-dns");

        discovered[2].Protocol.Should().Be(DnsProtocol.DoT);
        discovered[2].Port.Should().Be(8853);
        discovered[2].DotHost.Should().Be("dns.example.net");

        discovered[3].Protocol.Should().Be(DnsProtocol.DoQ);
        discovered[3].Port.Should().Be(8853);
    }

    [Fact]
    public async Task DiscoverAsync_QueriesResolverArpaSvcbAndParsesResponse()
    {
        IDnsUpstreamClient mockUpstream = Substitute.For<IDnsUpstreamClient>();
        mockUpstream.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage query = callInfo.Arg<DnsMessage>();
                query.Questions[0].Name.Should().Be(DdrDiscoveryClient.ResolverArpaDomain);
                query.Questions[0].RecordType.Should().Be(DnsRecordType.SVCB);

                DnsMessage resp = new()
                {
                    Header = new DnsHeader { Id = query.Header.Id, IsResponse = true, QuestionCount = 1, AnswerCount = 1 },
                    Questions = query.Questions,
                    Answers =
                    [
                        DnsResourceRecord.CreateSvcb(
                            DdrDiscoveryClient.ResolverArpaDomain,
                            1,
                            "one.one.one.one",
                            [SvcParam.CreateAlpn(["h2"]), SvcParam.CreateIpv4Hint([IPAddress.Parse("1.1.1.1")])])
                    ]
                };

                return Task.FromResult(new UpstreamQueryResult(resp, TimeSpan.FromMilliseconds(5), "1.1.1.1:53", DnsProtocol.Udp));
            });

        DnsServerEntry seed = new() { Id = "seed", Name = "Seed", Protocol = DnsProtocol.Udp, PrimaryIp = "1.1.1.1" };
        IReadOnlyList<DnsServerEntry> candidates = await DdrDiscoveryClient.DiscoverAsync(seed, mockUpstream);

        candidates.Should().ContainSingle();
        candidates[0].Protocol.Should().Be(DnsProtocol.DoH);
        candidates[0].DohUrl.Should().Be("https://one.one.one.one/dns-query");
    }
}
