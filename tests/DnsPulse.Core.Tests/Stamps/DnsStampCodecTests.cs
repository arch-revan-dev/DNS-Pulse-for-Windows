using System.Collections.Immutable;
using DnsPulse.Core.Stamps;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Stamps;

public sealed class DnsStampCodecTests
{
    private const string CloudflareDohStamp =
        "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk";

    [Fact]
    public void Parse_OfficialCloudflareDohStamp_DecodesHashesHostPathAndFlags()
    {
        DnsStamp stamp = DnsStampCodec.Parse(CloudflareDohStamp);

        stamp.Protocol.Should().Be(DnsStampProtocol.DoH);
        stamp.Properties.Should().Be(DnsStampFlags.DnsSec | DnsStampFlags.NoLog | DnsStampFlags.NoFilter);
        stamp.ServerAddress.Should().Be("1.0.0.1");
        stamp.Hashes.Should().HaveCount(2);
        stamp.Hashes[0].Length.Should().Be(32);
        stamp.Hashes[1].Length.Should().Be(32);
        stamp.HostName.Should().Be("dns.cloudflare.com");
        stamp.Path.Should().Be("/dns-query");
        stamp.BootstrapIps.Should().BeEmpty();

        string reencoded = DnsStampCodec.Encode(stamp);
        reencoded.Should().Be(CloudflareDohStamp);
    }

    [Theory]
    [InlineData(
        "sdns://AAcAAAAAAAAABzEuMS4xLjE",
        DnsStampProtocol.Plain,
        DnsStampFlags.DnsSec | DnsStampFlags.NoLog | DnsStampFlags.NoFilter,
        "1.1.1.1",
        "",
        "")]
    [InlineData(
        "sdns://AwIAAAAAAAAADDk0LjE0MC4xNC4xNAATZG5zLmFkZ3VhcmQtZG5zLmNvbQ",
        DnsStampProtocol.DoT,
        DnsStampFlags.NoLog,
        "94.140.14.14",
        "dns.adguard-dns.com",
        "")]
    [InlineData(
        "sdns://BAIAAAAAAAAAEDk0LjE0MC4xNC4xNDo4NTMAE2Rucy5hZGd1YXJkLWRucy5jb20",
        DnsStampProtocol.DoQ,
        DnsStampFlags.NoLog,
        "94.140.14.14:853",
        "dns.adguard-dns.com",
        "")]
    [InlineData(
        "sdns://BQYAAAAAAAAAF29kb2guY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk",
        DnsStampProtocol.ObliviousDoHTarget,
        DnsStampFlags.NoLog | DnsStampFlags.NoFilter,
        "",
        "odoh.cloudflare-dns.com",
        "/dns-query")]
    [InlineData(
        "sdns://gRMxNDkuMjAyLjk3LjE1Mjo4NDQz",
        DnsStampProtocol.AnonymizedDnsCryptRelay,
        DnsStampFlags.None,
        "149.202.97.152:8443",
        "",
        "")]
    [InlineData(
        "sdns://hQIAAAAAAAAAEjE0OS4yMDIuOTcuMTUyOjQ0MwANcmVsYXkuZXhhbXBsZQYvcHJveHk",
        DnsStampProtocol.ObliviousDoHRelay,
        DnsStampFlags.NoLog,
        "149.202.97.152:443",
        "relay.example",
        "/proxy")]
    public void Parse_KnownVectors_RoundtripsIdentically(
        string stampText,
        DnsStampProtocol expectedProtocol,
        DnsStampFlags expectedFlags,
        string expectedAddr,
        string expectedHost,
        string expectedPath)
    {
        DnsStamp parsed = DnsStampCodec.Parse(stampText);

        parsed.Protocol.Should().Be(expectedProtocol);
        parsed.Properties.Should().Be(expectedFlags);
        parsed.ServerAddress.Should().Be(expectedAddr);
        parsed.HostName.Should().Be(expectedHost);
        parsed.Path.Should().Be(expectedPath);

        string reencoded = DnsStampCodec.Encode(parsed);
        reencoded.Should().Be(stampText);
    }

    [Fact]
    public void Parse_Quad9DohWithVlpBootstrapIps_DecodesAndRoundtrips()
    {
        const string quad9Stamp =
            "sdns://AgMAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeYc5LjkuOS45DzE0OS4xMTIuMTEyLjExMg";

        DnsStamp parsed = DnsStampCodec.Parse(quad9Stamp);

        parsed.Protocol.Should().Be(DnsStampProtocol.DoH);
        parsed.Properties.Should().Be(DnsStampFlags.DnsSec | DnsStampFlags.NoLog);
        parsed.ServerAddress.Should().Be("9.9.9.9");
        parsed.Hashes.Should().BeEmpty();
        parsed.HostName.Should().Be("dns.quad9.net");
        parsed.Path.Should().Be("/dns-query");
        parsed.BootstrapIps.Should().Equal("9.9.9.9", "149.112.112.112");

        DnsStampCodec.Encode(parsed).Should().Be(quad9Stamp);
    }

    [Fact]
    public void Parse_DnsCryptStamp_DecodesPublicKeyAndProviderName()
    {
        const string dnsCryptStamp =
            "sdns://AQcAAAAAAAAADDkuOS45Ljk6ODQ0MyAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHxkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0";

        DnsStamp parsed = DnsStampCodec.Parse(dnsCryptStamp);

        parsed.Protocol.Should().Be(DnsStampProtocol.DnsCrypt);
        parsed.Properties.Should().Be(DnsStampFlags.DnsSec | DnsStampFlags.NoLog | DnsStampFlags.NoFilter);
        parsed.ServerAddress.Should().Be("9.9.9.9:8443");
        parsed.PublicKey.Should().HaveCount(32);
        parsed.PublicKey.Should().Equal(Enumerable.Range(0, 32).Select(static i => (byte)i));
        parsed.ProviderName.Should().Be("2.dnscrypt-cert.quad9.net");

        DnsStampCodec.Encode(parsed).Should().Be(dnsCryptStamp);
    }

    [Fact]
    public void EncodeDecode_AllEightProtocolsWithIpv6AndHashes_RoundtripsCleanly()
    {
        ImmutableArray<byte> hash1 = ImmutableArray.Create(Enumerable.Repeat((byte)0xAB, 32).ToArray());
        ImmutableArray<byte> hash2 = ImmutableArray.Create(Enumerable.Repeat((byte)0xCD, 32).ToArray());
        ImmutableArray<byte> pk = ImmutableArray.Create(Enumerable.Repeat((byte)0x42, 32).ToArray());

        DnsStamp[] stamps =
        [
            new DnsStamp
            {
                Protocol = DnsStampProtocol.Plain,
                Properties = DnsStampFlags.DnsSec,
                ServerAddress = "[2606:4700:4700::1111]:53"
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.DnsCrypt,
                Properties = DnsStampFlags.NoLog | DnsStampFlags.NoFilter,
                ServerAddress = "1.2.3.4:443",
                PublicKey = pk,
                ProviderName = "2.dnscrypt-cert.example.org"
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.DoH,
                Properties = DnsStampFlags.DnsSec | DnsStampFlags.NoLog,
                ServerAddress = "[2620:fe::fe]:443",
                Hashes = [hash1, hash2],
                HostName = "dns.example.org",
                Path = "/dns-query",
                BootstrapIps = ["9.9.9.9", "2620:fe::9"]
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.DoT,
                Properties = DnsStampFlags.NoLog,
                ServerAddress = "1.1.1.1:853",
                Hashes = [hash1],
                HostName = "one.one.one.one",
                BootstrapIps = ["1.0.0.1"]
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.DoQ,
                Properties = DnsStampFlags.DnsSec | DnsStampFlags.NoFilter,
                ServerAddress = "94.140.14.14:853",
                Hashes = [hash2],
                HostName = "dns.adguard-dns.com"
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.ObliviousDoHTarget,
                Properties = DnsStampFlags.NoLog,
                HostName = "odoh.example.net",
                Path = "/target"
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.AnonymizedDnsCryptRelay,
                ServerAddress = "[2001:db8::1]:443"
            },
            new DnsStamp
            {
                Protocol = DnsStampProtocol.ObliviousDoHRelay,
                Properties = DnsStampFlags.NoLog | DnsStampFlags.NoFilter,
                ServerAddress = "198.51.100.10:443",
                Hashes = [hash1],
                HostName = "relay.example.net",
                Path = "/proxy",
                BootstrapIps = ["198.51.100.1"]
            }
        ];

        foreach (DnsStamp original in stamps)
        {
            string encoded = DnsStampCodec.Encode(original);
            encoded.Should().StartWith("sdns://");
            string payload = encoded["sdns://".Length..];
            payload.Should().NotContain("=");
            payload.Should().NotContain("+");
            payload.Should().NotContain("/");

            DnsStamp decoded = DnsStampCodec.Parse(encoded);
            decoded.Should().Be(original);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("https://dns.google/dns-query")]
    [InlineData("sdns://")]
    [InlineData("sdns://A")]
    [InlineData("sdns://Agc=")]
    [InlineData("sdns://Agc+")]
    [InlineData("sdns://Agc/")]
    [InlineData("sdns://AA")]
    [InlineData("sdns://_wAAAAAAAAA")]
    [InlineData("sdns://AAcAAAAAAAAABzEuMS4xLjE=")]
    [InlineData("sdns://AAcAAAAAAAAACTEuMS4xLjE")]
    [InlineData("sdns://gQ8xLjIuMy40")]
    [InlineData("sdns://AgcAAAAAAAAABzEuMC4wLjGg")]
    public void Parse_MalformedOrTruncatedStamps_ThrowsFormatExceptionAndTryParseReturnsFalse(string malformed)
    {
        bool ok = DnsStampCodec.TryParse(malformed, out DnsStamp? parsed);
        ok.Should().BeFalse();
        parsed.Should().BeNull();

        Action act = () => DnsStampCodec.Parse(malformed);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Parse_FuzzTruncatedPrefixesOfValidStamp_NeverThrowsUnhandledExceptions()
    {
        for (int len = 0; len < CloudflareDohStamp.Length; len++)
        {
            string prefix = CloudflareDohStamp[..len];
            bool ok = DnsStampCodec.TryParse(prefix, out DnsStamp? result);
            ok.Should().BeFalse();
            result.Should().BeNull();
        }
    }

    [Fact]
    public void Parse_TrailingGarbageByte_ThrowsFormatException()
    {
        byte[] raw = [0x00, 0, 0, 0, 0, 0, 0, 0, 0, 7, (byte)'1', (byte)'.', (byte)'1', (byte)'.', (byte)'1', (byte)'.', (byte)'1', 0xFF];
        string encoded = "sdns://" + ToBase64Url(raw);

        DnsStampCodec.TryParse(encoded, out _).Should().BeFalse();
        Action act = () => DnsStampCodec.Parse(encoded);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Parse_VlpContinuationWithZeroLength_ThrowsFormatException()
    {
        // DoH with props=0, addr="", hashes VLP = [0x80] (len=0, continuation=1)
        byte[] raw = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x80, 0x01, (byte)'a', 0x01, (byte)'/'];
        string encoded = "sdns://" + ToBase64Url(raw);

        DnsStampCodec.TryParse(encoded, out _).Should().BeFalse();
    }

    [Fact]
    public void Parse_HashWithWrongLength_ThrowsFormatException()
    {
        // DoH with props=0, addr="", hash len=16 (must be 32)
        byte[] raw = new byte[1 + 8 + 1 + 1 + 16 + 2 + 2];
        raw[0] = 0x02;
        raw[10] = 16;
        raw[27] = 1;
        raw[28] = (byte)'a';
        raw[29] = 1;
        raw[30] = (byte)'/';
        string encoded = "sdns://" + ToBase64Url(raw);

        DnsStampCodec.TryParse(encoded, out _).Should().BeFalse();
    }

    private static string ToBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
