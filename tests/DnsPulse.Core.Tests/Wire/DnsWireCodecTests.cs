using System.Net;
using DnsPulse.Core.Wire;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Wire;

public sealed class DnsWireCodecTests
{
    [Fact]
    public void Roundtrip_ShouldPreserveAllTwelveRecordTypesAndHeaderFlags()
    {
        byte[] echConfig = [0x00, 0x20, 0xFE, 0x0D, 0x00, 0x1C, 0xAA, 0xBB, 0xCC, 0xDD];

        DnsMessage original = new()
        {
            Header = new DnsHeader
            {
                Id = 0x42AF,
                IsResponse = true,
                OpCode = 0,
                AuthoritativeAnswer = true,
                Truncated = true,
                RecursionDesired = true,
                RecursionAvailable = true,
                AuthenticData = true,
                CheckingDisabled = false,
                ResponseCode = DnsResponseCode.NoError
            },
            Questions =
            [
                DnsQuestion.Create("gemini.google.com", DnsRecordType.HTTPS)
            ],
            Answers =
            [
                DnsResourceRecord.CreateA("gemini.google.com", IPAddress.Parse("142.250.74.46"), 120),
                DnsResourceRecord.CreateAaaa("gemini.google.com", IPAddress.Parse("2a00:1450:4001:827::200e"), 120),
                DnsResourceRecord.CreateCname("www.gemini.google.com", "gemini.google.com", 300),
                DnsResourceRecord.CreateNs("google.com", "ns1.google.com", 86400),
                DnsResourceRecord.CreatePtr("46.74.250.142.in-addr.arpa", "fra16s51-in-f14.1e100.net", 3600),
                DnsResourceRecord.CreateMx("google.com", 10, "smtp.google.com", 600),
                DnsResourceRecord.CreateTxt("google.com", ["v=spf1 include:_spf.google.com ~all", "dns-pulse=ok"], 300),
                DnsResourceRecord.CreateSoa("google.com", "ns1.google.com", "dns-admin.google.com", 2026111301, 900, 900, 1800, 60, 60),
                DnsResourceRecord.CreateSrv("_https._tcp.example.com", 10, 5, 443, "edge.example.com", 300),
                DnsResourceRecord.CreateSvcb(
                    "svc.example.com",
                    1,
                    "edge.example.com",
                    [
                        SvcParam.CreateMandatory([(ushort)SvcParamKey.Alpn, (ushort)SvcParamKey.Port]),
                        SvcParam.CreateAlpn(["h2", "http/1.1"]),
                        SvcParam.CreateNoDefaultAlpn(),
                        SvcParam.CreatePort(8443),
                        SvcParam.CreateIpv4Hint([IPAddress.Parse("198.51.100.10")]),
                        SvcParam.CreateIpv6Hint([IPAddress.Parse("2001:db8::10")])
                    ],
                    300),
                DnsResourceRecord.CreateHttps(
                    "gemini.google.com",
                    1,
                    string.Empty,
                    [
                        SvcParam.CreateAlpn(["h3", "h2"]),
                        SvcParam.CreateIpv4Hint([IPAddress.Parse("142.250.74.46"), IPAddress.Parse("142.250.74.78")]),
                        SvcParam.CreateEch(echConfig),
                        SvcParam.CreateIpv6Hint([IPAddress.Parse("2a00:1450:4001:827::200e")])
                    ],
                    300)
            ],
            Additionals =
            [
                DnsResourceRecord.CreateOpt(udpPayloadSize: 1232, dnssecOk: true, extendedRcode: 0, ednsVersion: 0)
            ]
        };

        byte[] wire = DnsWireCodec.Serialize(original, enableCompression: true);
        DnsMessage parsed = DnsWireCodec.Parse(wire);

        parsed.Header.Id.Should().Be(0x42AF);
        parsed.Header.IsResponse.Should().BeTrue();
        parsed.Header.AuthoritativeAnswer.Should().BeTrue();
        parsed.IsTruncated.Should().BeTrue();
        parsed.Header.RecursionDesired.Should().BeTrue();
        parsed.Header.RecursionAvailable.Should().BeTrue();
        parsed.IsAuthenticData.Should().BeTrue();
        parsed.Header.CheckingDisabled.Should().BeFalse();
        parsed.Header.ResponseCode.Should().Be(DnsResponseCode.NoError);

        parsed.Questions.Should().HaveCount(1);
        parsed.Questions[0].Name.Should().Be("gemini.google.com");
        parsed.Questions[0].RecordType.Should().Be(DnsRecordType.HTTPS);

        parsed.Answers.Should().HaveCount(11);
        parsed.Answers[0].Address.Should().Be(IPAddress.Parse("142.250.74.46"));
        parsed.Answers[1].Address.Should().Be(IPAddress.Parse("2a00:1450:4001:827::200e"));
        parsed.Answers[2].TargetName.Should().Be("gemini.google.com");
        parsed.Answers[3].TargetName.Should().Be("ns1.google.com");
        parsed.Answers[4].TargetName.Should().Be("fra16s51-in-f14.1e100.net");
        parsed.Answers[5].Preference.Should().Be(10);
        parsed.Answers[5].TargetName.Should().Be("smtp.google.com");
        parsed.Answers[6].TxtStrings.Should().ContainInOrder("v=spf1 include:_spf.google.com ~all", "dns-pulse=ok");
        parsed.Answers[7].SoaMName.Should().Be("ns1.google.com");
        parsed.Answers[7].SoaRName.Should().Be("dns-admin.google.com");
        parsed.Answers[7].SoaSerial.Should().Be(2026111301u);
        parsed.Answers[8].Priority.Should().Be(10);
        parsed.Answers[8].Weight.Should().Be(5);
        parsed.Answers[8].Port.Should().Be(443);
        parsed.Answers[8].TargetName.Should().Be("edge.example.com");

        DnsResourceRecord svcb = parsed.Answers[9];
        svcb.RecordType.Should().Be(DnsRecordType.SVCB);
        svcb.SvcPriority.Should().Be(1);
        svcb.TargetName.Should().Be("edge.example.com");
        svcb.SvcParams.Should().HaveCount(6);
        svcb.SvcParams[0].ParseMandatoryKeys().Should().ContainInOrder((ushort)SvcParamKey.Alpn, (ushort)SvcParamKey.Port);
        svcb.SvcParams[1].ParseAlpnIds().Should().ContainInOrder("h2", "http/1.1");
        svcb.SvcParams[2].KnownKey.Should().Be(SvcParamKey.NoDefaultAlpn);
        svcb.SvcParams[3].ParsePort().Should().Be(8443);
        svcb.SvcParams[4].ParseIpv4Hints().Should().ContainSingle().Which.Should().Be(IPAddress.Parse("198.51.100.10"));
        svcb.SvcParams[5].ParseIpv6Hints().Should().ContainSingle().Which.Should().Be(IPAddress.Parse("2001:db8::10"));

        DnsResourceRecord https = parsed.Answers[10];
        https.RecordType.Should().Be(DnsRecordType.HTTPS);
        https.TargetName.Should().BeEmpty();
        https.SvcParams.First(p => p.KnownKey == SvcParamKey.Ech).Value.Span.ToArray().Should().BeEquivalentTo(echConfig);

        parsed.HasEdns0.Should().BeTrue();
        parsed.EdnsUdpPayloadSize.Should().Be(1232);
        parsed.IsDnssecOk.Should().BeTrue();
    }

    [Fact]
    public void Compression_ShouldShrinkWireOutputAndDecompressPointersCorrectly()
    {
        DnsMessage message = new()
        {
            Header = new DnsHeader { Id = 1001, IsResponse = true, RecursionDesired = true, RecursionAvailable = true },
            Questions = [DnsQuestion.Create("sub.example.com", DnsRecordType.A)],
            Answers =
            [
                DnsResourceRecord.CreateCname("sub.example.com", "cdn.example.com", 60),
                DnsResourceRecord.CreateA("cdn.example.com", IPAddress.Parse("93.184.216.34"), 60)
            ]
        };

        byte[] uncompressed = DnsWireCodec.Serialize(message, enableCompression: false);
        byte[] compressed = DnsWireCodec.Serialize(message, enableCompression: true);

        compressed.Length.Should().BeLessThan(uncompressed.Length);

        DnsMessage parsed = DnsWireCodec.Parse(compressed);
        parsed.Answers[0].Name.Should().Be("sub.example.com");
        parsed.Answers[0].TargetName.Should().Be("cdn.example.com");
        parsed.Answers[1].Name.Should().Be("cdn.example.com");
        parsed.Answers[1].Address.Should().Be(IPAddress.Parse("93.184.216.34"));
    }

    [Fact]
    public void SerializePooledAndSpan_ShouldWorkWithZeroHeapAllocationPaths()
    {
        DnsMessage query = DnsMessage.CreateQuery(
            id: 0x1234,
            domain: "aistudio.google.com",
            recordType: DnsRecordType.A,
            enableEdns0: true,
            ednsUdpPayloadSize: 4096,
            dnssecOk: true,
            authenticData: true);

        Span<byte> stackBuffer = stackalloc byte[512];
        int written = DnsWireCodec.Serialize(query, stackBuffer);
        written.Should().BeGreaterThan(12);

        using PooledDnsPacket pooled = DnsWireCodec.SerializePooled(query);
        pooled.Length.Should().Be(written);
        pooled.Span.SequenceEqual(stackBuffer[..written]).Should().BeTrue();

        DnsMessage parsed = DnsWireCodec.Parse(pooled.Span);
        parsed.Header.Id.Should().Be(0x1234);
        parsed.IsAuthenticData.Should().BeTrue();
        parsed.IsDnssecOk.Should().BeTrue();
        parsed.EdnsUdpPayloadSize.Should().Be(4096);
    }

    [Fact]
    public void Parse_ShouldRejectSelfReferentialAndCyclicCompressionPointersSafely()
    {
        // Self-loop at offset 12: 0xC0 0x0C
        byte[] selfLoop =
        [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01
        ];

        DnsWireCodec.TryParse(selfLoop, out _).Should().BeFalse();
        Action selfLoopAct = () => DnsWireCodec.Parse(selfLoop);
        selfLoopAct.Should().Throw<FormatException>();

        // 2-node mutual cycle: offset 12 -> 14, offset 14 -> 12
        byte[] twoNodeCycle =
        [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0E,
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01
        ];

        DnsWireCodec.TryParse(twoNodeCycle, out _).Should().BeFalse();
        Action twoNodeAct = () => DnsWireCodec.Parse(twoNodeCycle);
        twoNodeAct.Should().Throw<FormatException>();

        // Pointer into DNS header (offset 0)
        byte[] headerPointer =
        [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00,
            0x00, 0x01, 0x00, 0x01
        ];

        DnsWireCodec.TryParse(headerPointer, out _).Should().BeFalse();

        // Out-of-bounds pointer
        byte[] oobPointer =
        [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x7F,
            0x00, 0x01, 0x00, 0x01
        ];

        DnsWireCodec.TryParse(oobPointer, out _).Should().BeFalse();

        // Unsupported label type (0b01 = 0x41)
        byte[] invalidLabelType =
        [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x41, 0x61, 0x00,
            0x00, 0x01, 0x00, 0x01
        ];

        DnsWireCodec.TryParse(invalidLabelType, out _).Should().BeFalse();
    }

    [Fact]
    public void Parse_ShouldHandleTruncatedAndFuzzedPacketsWithoutUnhandledExceptions()
    {
        DnsMessage valid = DnsMessage.CreateQuery(99, "chatgpt.com", DnsRecordType.A);
        byte[] validWire = DnsWireCodec.Serialize(valid);

        for (int len = 0; len < validWire.Length; len++)
        {
            DnsWireCodec.TryParse(validWire.AsSpan(0, len), out _).Should().BeFalse();
        }

        uint state = 20261113u;
        byte[] fuzzBuffer = new byte[128];
        for (int iteration = 0; iteration < 500; iteration++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            int sliceLen = (int)(state % (uint)(fuzzBuffer.Length + 1));

            for (int byteIdx = 0; byteIdx < sliceLen; byteIdx++)
            {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                fuzzBuffer[byteIdx] = (byte)(state & 0xFF);
            }

            // Force plausible header sizes occasionally to hit deep parser paths
            if (sliceLen >= 12)
            {
                fuzzBuffer[4] = 0;
                fuzzBuffer[5] = (byte)(state % 4u);
                fuzzBuffer[6] = 0;
                fuzzBuffer[7] = (byte)((state >> 8) % 4u);
            }

            _ = DnsWireCodec.TryParse(fuzzBuffer.AsSpan(0, sliceLen), out _);
        }
    }
}
