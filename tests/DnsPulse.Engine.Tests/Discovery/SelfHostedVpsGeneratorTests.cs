using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Engine.Discovery;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Discovery;

public sealed class SelfHostedVpsGeneratorTests
{
    [Fact]
    public void Generate_ProducesHighEntropyBearerTokenHardenedConfigsAndValidDnsStampRoundtrip()
    {
        SelfHostedVpsGenerator generator = new();
        byte[] certHash = SHA256.HashData("test-vps-cert"u8);

        SelfHostedVpsOptions options = new()
        {
            HostName = "dns.my-private-vps.example",
            ServerIpAddress = "198.51.100.42",
            AllowedClientCidrs = ["203.0.113.10/32", "198.51.100.0/28"],
            TargetGeoUnlockDomains = ["aistudio.google.com", "chatgpt.com"],
            DohPath = "/dns-query",
            HttpsPort = 443,
            DotPort = 853,
            CertificateSha256Hash = ImmutableArray.Create(certHash)
        };

        SelfHostedVpsBundle bundle1 = generator.Generate(options);
        SelfHostedVpsBundle bundle2 = generator.Generate(options);

        // 256-bit base64url bearer token (43 chars) and distinct per generation
        bundle1.BearerToken.Should().HaveLength(43);
        bundle2.BearerToken.Should().HaveLength(43);
        bundle1.BearerToken.Should().NotBe(bundle2.BearerToken);
        bundle1.BearerToken.Should().MatchRegex("^[A-Za-z0-9_-]{43}$");

        // Hardened Docker Compose & Corefile / AdGuardHome.yaml (never bound to 0.0.0.0:53)
        bundle1.DockerComposeYaml.Should().Contain("127.0.0.1:5353:5353/udp");
        bundle1.DockerComposeYaml.Should().Contain("cap_drop:");
        bundle1.DockerComposeYaml.Should().Contain("no-new-privileges:true");
        bundle1.DockerComposeYaml.Should().NotContain("0.0.0.0:53:53");

        // Nginx enforces both IP allowlist (deny all) and Bearer token authentication (403)
        bundle1.NginxConf.Should().Contain("ssl_preread on;");
        bundle1.NginxConf.Should().Contain("allow 203.0.113.10/32;");
        bundle1.NginxConf.Should().Contain("allow 198.51.100.0/28;");
        bundle1.NginxConf.Should().Contain("deny all;");
        bundle1.NginxConf.Should().Contain($"Bearer {bundle1.BearerToken}");
        bundle1.NginxConf.Should().Contain("return 403;");
        bundle1.NginxConf.Should().Contain("aistudio.google.com aistudio.google.com:443;");

        // Corefile & AdGuardHome.yaml completeness
        bundle1.Corefile.Should().Contain("bind 127.0.0.1");
        bundle1.Corefile.Should().Contain("forward . tls://1.1.1.1 tls://9.9.9.9");
        bundle1.AdGuardHomeYaml.Should().Contain("203.0.113.10/32");
        bundle1.AdGuardHomeYaml.Should().Contain("refuse_any: true");

        // UFW rules deny open port 53 and restrict 443/853 to allowlist
        bundle1.UfwRulesScript.Should().Contain("ufw default deny incoming");
        bundle1.UfwRulesScript.Should().Contain("ufw deny 53");
        bundle1.UfwRulesScript.Should().Contain("ufw allow from 203.0.113.10/32 to any port 443 proto tcp");
        bundle1.UfwRulesScript.Should().Contain("ufw allow from 198.51.100.0/28 to any port 853 proto tcp");

        // sdns:// roundtrip via DnsStampCodec.Parse
        bundle1.DnsStampUri.Should().StartWith("sdns://");
        DnsStamp parsedStamp = DnsStampCodec.Parse(bundle1.DnsStampUri);
        parsedStamp.Protocol.Should().Be(DnsStampProtocol.DoH);
        parsedStamp.HostName.Should().Be("dns.my-private-vps.example");
        parsedStamp.ServerAddress.Should().Be("198.51.100.42");
        parsedStamp.Path.Should().Be("/dns-query");
        parsedStamp.BootstrapIps.Should().ContainSingle().Which.Should().Be("198.51.100.42");
        parsedStamp.Hashes.Should().ContainSingle();
        parsedStamp.Hashes[0].AsSpan().SequenceEqual(certHash).Should().BeTrue();

        // Profile JSON contains token & stamp
        using JsonDocument profileDoc = JsonDocument.Parse(bundle1.ProfileJson);
        profileDoc.RootElement.GetProperty("bearerToken").GetString().Should().Be(bundle1.BearerToken);
        profileDoc.RootElement.GetProperty("dnsStampUri").GetString().Should().Be(bundle1.DnsStampUri);

        // ServerEntry trust tier
        bundle1.ServerEntry.TrustTier.Should().Be(TrustTier.Tier3CustomOrSelfHosted);
        bundle1.ServerEntry.Protocol.Should().Be(DnsProtocol.DoH);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    [InlineData("*")]
    [InlineData("any")]
    public void Generate_EmptyOrWildcardAllowlist_ThrowsArgumentExceptionToPreventOpenResolver(string? singleCidr)
    {
        SelfHostedVpsGenerator generator = new();
        string[] cidrs = singleCidr is null ? [] : [singleCidr];
        SelfHostedVpsOptions options = new()
        {
            HostName = "dns.example.com",
            ServerIpAddress = "198.51.100.42",
            AllowedClientCidrs = cidrs
        };

        Action act = () => generator.Generate(options);

        act.Should().Throw<ArgumentException>();
    }
}
