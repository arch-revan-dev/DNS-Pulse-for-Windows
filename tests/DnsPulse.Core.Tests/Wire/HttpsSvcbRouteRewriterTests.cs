using System.Net;
using DnsPulse.Core.Wire;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Wire;

public sealed class HttpsSvcbRouteRewriterTests
{
    [Fact]
    public void Rewrite_DirectMode_ShouldPreserveAaaaAndHttpsWithEchIntact()
    {
        byte[] echBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        DnsMessage message = CreateSampleResponse(echBytes, includeA: true);

        DnsMessage rewritten = HttpsSvcbRouteRewriter.Rewrite(message, geoUnlockIpv4Only: false);

        rewritten.Answers.Should().HaveCount(3);
        rewritten.Answers.Should().Contain(r => r.RecordType == DnsRecordType.AAAA);

        DnsResourceRecord https = rewritten.Answers.Single(r => r.RecordType == DnsRecordType.HTTPS);
        https.SvcParams.Should().Contain(p => p.KnownKey == SvcParamKey.Ech);
        https.SvcParams.Should().Contain(p => p.KnownKey == SvcParamKey.Ipv4Hint);
        https.SvcParams.Should().Contain(p => p.KnownKey == SvcParamKey.Ipv6Hint);
        https.SvcParams.Single(p => p.KnownKey == SvcParamKey.Alpn)
            .ParseAlpnIds().Should().ContainInOrder("h3", "h2", "http/1.1");
    }

    [Fact]
    public void Rewrite_GeoUnlockIpv4Only_ShouldStripAaaaHintsAndH3WhilePreservingH2Http11AndEch()
    {
        byte[] echBytes = [0xAA, 0xBB, 0xCC, 0xDD];
        DnsMessage message = CreateSampleResponse(echBytes, includeA: true);

        DnsMessage rewritten = HttpsSvcbRouteRewriter.Rewrite(message, geoUnlockIpv4Only: true);

        rewritten.Header.AnswerCount.Should().Be(2);
        rewritten.Answers.Should().NotContain(r => r.RecordType == DnsRecordType.AAAA);
        rewritten.Answers.Should().Contain(r => r.RecordType == DnsRecordType.A);

        DnsResourceRecord https = rewritten.Answers.Single(r => r.RecordType == DnsRecordType.HTTPS);
        https.SvcParams.Should().NotContain(p => p.KnownKey == SvcParamKey.Ipv4Hint);
        https.SvcParams.Should().NotContain(p => p.KnownKey == SvcParamKey.Ipv6Hint);
        https.SvcParams.Should().Contain(p => p.KnownKey == SvcParamKey.Ech);

        IReadOnlyList<string> alpnIds = https.SvcParams.Single(p => p.KnownKey == SvcParamKey.Alpn).ParseAlpnIds();
        alpnIds.Should().NotContain("h3");
        alpnIds.Should().ContainInOrder("h2", "http/1.1");

        // Mandatory keys must have ipv4hint/ipv6hint pruned while keeping alpn
        IReadOnlyList<ushort> mandatory = https.SvcParams.Single(p => p.KnownKey == SvcParamKey.Mandatory).ParseMandatoryKeys();
        mandatory.Should().ContainSingle().Which.Should().Be((ushort)SvcParamKey.Alpn);

        // Ensure rewritten packet roundtrips cleanly through DnsWireCodec
        byte[] wire = DnsWireCodec.Serialize(rewritten);
        DnsMessage reparsed = DnsWireCodec.Parse(wire);
        reparsed.Answers.Should().HaveCount(2);
        reparsed.Answers.Single(r => r.RecordType == DnsRecordType.HTTPS)
            .SvcParams.Single(p => p.KnownKey == SvcParamKey.Alpn)
            .ParseAlpnIds().Should().ContainInOrder("h2", "http/1.1");
    }

    [Fact]
    public void Rewrite_GeoUnlockIpv4Only_WhenOnlyAaaaExists_ShouldReturnValidNoErrorNoData()
    {
        DnsMessage aaaaOnly = new()
        {
            Header = new DnsHeader
            {
                Id = 77,
                IsResponse = true,
                RecursionDesired = true,
                RecursionAvailable = true,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = 1,
                AnswerCount = 1,
                AdditionalCount = 1
            },
            Questions = [DnsQuestion.Create("gemini.google.com", DnsRecordType.AAAA)],
            Answers = [DnsResourceRecord.CreateAaaa("gemini.google.com", IPAddress.Parse("2a00:1450:4001:827::200e"), 60)],
            Additionals = [DnsResourceRecord.CreateOpt(1232, dnssecOk: false)]
        };

        DnsMessage rewritten = HttpsSvcbRouteRewriter.Rewrite(aaaaOnly, geoUnlockIpv4Only: true);

        rewritten.Header.ResponseCode.Should().Be(DnsResponseCode.NoError);
        rewritten.Header.AnswerCount.Should().Be(0);
        rewritten.Answers.Should().BeEmpty();
        rewritten.Additionals.Should().ContainSingle(r => r.RecordType == DnsRecordType.OPT);
    }

    [Fact]
    public void Rewrite_GeoUnlockIpv4Only_WhenSvcbHasOnlyH3Alpn_ShouldRemoveAlpnAndPruneMandatory()
    {
        DnsMessage message = new()
        {
            Header = new DnsHeader { Id = 88, IsResponse = true, QuestionCount = 1, AnswerCount = 1 },
            Questions = [DnsQuestion.Create("svc.example.com", DnsRecordType.SVCB)],
            Answers =
            [
                DnsResourceRecord.CreateSvcb(
                    "svc.example.com",
                    1,
                    "target.example.com",
                    [
                        SvcParam.CreateMandatory([(ushort)SvcParamKey.Alpn, (ushort)SvcParamKey.Port]),
                        SvcParam.CreateAlpn(["h3", "h3-29"]),
                        SvcParam.CreatePort(443),
                        SvcParam.CreateIpv4Hint([IPAddress.Parse("203.0.113.5")])
                    ])
            ]
        };

        DnsMessage rewritten = HttpsSvcbRouteRewriter.Rewrite(message, geoUnlockIpv4Only: true);

        DnsResourceRecord svcb = rewritten.Answers.Single();
        svcb.SvcParams.Should().NotContain(p => p.KnownKey == SvcParamKey.Alpn);
        svcb.SvcParams.Should().NotContain(p => p.KnownKey == SvcParamKey.Ipv4Hint);
        svcb.SvcParams.Single(p => p.KnownKey == SvcParamKey.Port).ParsePort().Should().Be(443);
        svcb.SvcParams.Single(p => p.KnownKey == SvcParamKey.Mandatory).ParseMandatoryKeys()
            .Should().ContainSingle().Which.Should().Be((ushort)SvcParamKey.Port);
    }

    private static DnsMessage CreateSampleResponse(byte[] echBytes, bool includeA)
    {
        List<DnsResourceRecord> answers = [];
        if (includeA)
        {
            answers.Add(DnsResourceRecord.CreateA("gemini.google.com", IPAddress.Parse("142.250.74.46"), 120));
        }

        answers.Add(DnsResourceRecord.CreateAaaa("gemini.google.com", IPAddress.Parse("2a00:1450:4001:827::200e"), 120));
        answers.Add(DnsResourceRecord.CreateHttps(
            "gemini.google.com",
            1,
            string.Empty,
            [
                SvcParam.CreateMandatory([(ushort)SvcParamKey.Alpn, (ushort)SvcParamKey.Ipv4Hint, (ushort)SvcParamKey.Ipv6Hint]),
                SvcParam.CreateAlpn(["h3", "h2", "http/1.1"]),
                SvcParam.CreateIpv4Hint([IPAddress.Parse("142.250.74.46")]),
                SvcParam.CreateEch(echBytes),
                SvcParam.CreateIpv6Hint([IPAddress.Parse("2a00:1450:4001:827::200e")])
            ],
            120));

        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = 0x55AA,
                IsResponse = true,
                RecursionDesired = true,
                RecursionAvailable = true,
                AuthenticData = true,
                QuestionCount = 1,
                AnswerCount = (ushort)answers.Count,
                AdditionalCount = 1
            },
            Questions = [DnsQuestion.Create("gemini.google.com", DnsRecordType.HTTPS)],
            Answers = answers,
            Additionals = [DnsResourceRecord.CreateOpt(1232, dnssecOk: true)]
        };
    }
}
