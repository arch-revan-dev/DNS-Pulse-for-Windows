using DnsPulse.Core.Stamps;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Stamps;

public sealed class EndpointUriParserTests
{
    [Theory]
    [InlineData("HTTPS://DNS.GOOGLE:443/dns-query", EndpointKind.DoH, "https://dns.google/dns-query", "dns.google", 443, "/dns-query")]
    [InlineData("https://1.1.1.1/dns-query", EndpointKind.DoH, "https://1.1.1.1/dns-query", "1.1.1.1", 443, "/dns-query")]
    [InlineData("https://[2606:4700:4700:0:0:0:0:1111]:8443/dns-query", EndpointKind.DoH, "https://[2606:4700:4700::1111]:8443/dns-query", "2606:4700:4700::1111", 8443, "/dns-query")]
    [InlineData("TLS://one.one.one.one:853", EndpointKind.DoT, "tls://one.one.one.one", "one.one.one.one", 853, null)]
    [InlineData("tls://9.9.9.9:8853", EndpointKind.DoT, "tls://9.9.9.9:8853", "9.9.9.9", 8853, null)]
    [InlineData("QUIC://dns.adguard-dns.com:853", EndpointKind.DoQ, "quic://dns.adguard-dns.com", "dns.adguard-dns.com", 853, null)]
    [InlineData("quic://dns.adguard-dns.com:784", EndpointKind.DoQ, "quic://dns.adguard-dns.com:784", "dns.adguard-dns.com", 784, null)]
    [InlineData("odoh://odoh.cloudflare-dns.com:443/dns-query", EndpointKind.ObliviousDoH, "odoh://odoh.cloudflare-dns.com/dns-query", "odoh.cloudflare-dns.com", 443, "/dns-query")]
    [InlineData("smartproxy://192.255.159.240:443", EndpointKind.SmartProxy, "smartproxy://192.255.159.240", "192.255.159.240", 443, null)]
    [InlineData("smartproxy://[2001:db8::42]:8443", EndpointKind.SmartProxy, "smartproxy://[2001:db8::42]:8443", "2001:db8::42", 8443, null)]
    [InlineData("http://127.0.0.1:8080/dns-query", EndpointKind.PlainHttpLoopback, "http://127.0.0.1:8080/dns-query", "127.0.0.1", 8080, "/dns-query")]
    [InlineData("http://[::1]:80/dns-query", EndpointKind.PlainHttpLoopback, "http://[::1]/dns-query", "::1", 80, "/dns-query")]
    [InlineData("http://localhost:5053/dns-query", EndpointKind.PlainHttpLoopback, "http://localhost:5053/dns-query", "localhost", 5053, "/dns-query")]
    [InlineData("1.1.1.1", EndpointKind.PlainIp, "1.1.1.1", "1.1.1.1", 53, null)]
    [InlineData("1.1.1.1:53", EndpointKind.PlainIp, "1.1.1.1", "1.1.1.1", 53, null)]
    [InlineData("9.9.9.9:5353", EndpointKind.PlainIp, "9.9.9.9:5353", "9.9.9.9", 5353, null)]
    [InlineData("2606:4700:4700:0:0:0:0:1111", EndpointKind.PlainIp, "[2606:4700:4700::1111]", "2606:4700:4700::1111", 53, null)]
    [InlineData("[2606:4700:4700::1111]:5353", EndpointKind.PlainIp, "[2606:4700:4700::1111]:5353", "2606:4700:4700::1111", 5353, null)]
    public void Parse_ValidEndpoints_NormalizesCorrectly(
        string input,
        EndpointKind expectedKind,
        string expectedNormalized,
        string expectedHost,
        int expectedPort,
        string? expectedPath)
    {
        ParsedEndpoint parsed = EndpointUriParser.Parse(input);

        parsed.Kind.Should().Be(expectedKind);
        parsed.NormalizedEndpoint.Should().Be(expectedNormalized);
        parsed.Host.Should().Be(expectedHost);
        parsed.Port.Should().Be(expectedPort);
        parsed.Path.Should().Be(expectedPath);
    }

    [Fact]
    public void Parse_DnsStampEndpoint_PopulatesStampAndNormalizedEndpoint()
    {
        const string stamp =
            "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk";

        ParsedEndpoint parsed = EndpointUriParser.Parse("SDNS://" + stamp["sdns://".Length..]);

        parsed.Kind.Should().Be(EndpointKind.DnsStamp);
        parsed.NormalizedEndpoint.Should().Be(stamp);
        parsed.Host.Should().Be("dns.cloudflare.com");
        parsed.Port.Should().Be(443);
        parsed.Path.Should().Be("/dns-query");
        parsed.Stamp.Should().NotBeNull();
        parsed.ParsedUri.Should().BeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a url")]
    [InlineData("dns.google")]
    [InlineData("http://1.1.1.1/dns-query")]
    [InlineData("http://dns.google/dns-query")]
    [InlineData("http://192.168.1.1/dns-query")]
    [InlineData("https://user:pass@dns.google/dns-query")]
    [InlineData("https://user@dns.google/dns-query")]
    [InlineData("https://@dns.google/dns-query")]
    [InlineData("tls://secret:token@1.1.1.1:853")]
    [InlineData("ftp://1.1.1.1/file")]
    [InlineData("https://dns.google:0/dns-query")]
    [InlineData("https://dns.google:70000/dns-query")]
    [InlineData("https://dns.google/dns-query#fragment")]
    [InlineData("tls://dns.google/unexpected-path")]
    [InlineData("quic://dns.google?query=1")]
    [InlineData("smartproxy://1.2.3.4/path")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4:0")]
    [InlineData("1.2.3.4:65536")]
    [InlineData("[::1")]
    [InlineData("[::1]:99999")]
    [InlineData("sdns://invalid!")]
    public void Parse_InvalidOrInsecureEndpoints_ThrowsFormatException(string endpoint)
    {
        EndpointUriParser.TryParse(endpoint, out ParsedEndpoint? result).Should().BeFalse();
        result.Should().BeNull();

        Action act = () => EndpointUriParser.Parse(endpoint);
        act.Should().Throw<FormatException>();
    }
}
