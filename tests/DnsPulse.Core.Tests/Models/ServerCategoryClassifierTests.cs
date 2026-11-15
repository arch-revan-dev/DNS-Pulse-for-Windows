using DnsPulse.Core.Models;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Models;

public sealed class ServerCategoryClassifierTests
{
    [Fact]
    public void Classify_XboxDnsUdp53_IsStreamingAndGaming_AndExcludedFromAiUnlock()
    {
        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();
        DnsServerEntry xboxUdp = flagships.Single(static s => s.Id == "smart_xbox_dns_udp");

        xboxUdp.Name.Should().Be("Xbox-DNS UDP 53");
        ServerCategoryClassifier.Classify(xboxUdp).Should().Be(ServerDisplayCategory.StreamingAndGaming);
        ServerCategoryClassifier.IsGamingOnlyGeoServer(xboxUdp).Should().BeTrue();
        ServerCategoryClassifier.SupportsAiDomain(xboxUdp).Should().BeFalse();
        ServerCategoryClassifier.SupportsTargetDomain(xboxUdp, "aistudio.google.com").Should().BeFalse();
        ServerCategoryClassifier.SupportsTargetDomain(xboxUdp, "gemini.google.com").Should().BeFalse();
        ServerCategoryClassifier.SupportsTargetDomain(xboxUdp, "xbox.com").Should().BeTrue();

        xboxUdp.DisplayCategory.Should().Be(ServerDisplayCategory.StreamingAndGaming);
        xboxUdp.IsGamingOnlyGeo.Should().BeTrue();
        xboxUdp.SupportsAiUnlock.Should().BeFalse();
    }

    [Fact]
    public void Classify_AiSmartDnsServers_AreAiAndGeoUnlock_WithSupportsAiDomainTrue()
    {
        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();

        DnsServerEntry comss = flagships.Single(static s => s.Id == "smart_comss_doh");
        DnsServerEntry malw = flagships.Single(static s => s.Id == "smart_malw_doh");
        List<DnsServerEntry> bezmezhauNodes =
        [
            .. flagships.Where(static s => s.Id.StartsWith("smart_bezmezhau_", StringComparison.Ordinal))
        ];

        bezmezhauNodes.Should().HaveCountGreaterThanOrEqualTo(21);

        List<DnsServerEntry> aiServers = [comss, malw, .. bezmezhauNodes];
        foreach (DnsServerEntry server in aiServers)
        {
            ServerCategoryClassifier.Classify(server).Should().Be(ServerDisplayCategory.AiAndGeoUnlock);
            ServerCategoryClassifier.SupportsAiDomain(server).Should().BeTrue();
            ServerCategoryClassifier.IsGamingOnlyGeoServer(server).Should().BeFalse();
            ServerCategoryClassifier.HasExplicitAiTag(server).Should().BeTrue();
            ServerCategoryClassifier.SupportsTargetDomain(server, "aistudio.google.com").Should().BeTrue();
            server.DisplayCategory.Should().Be(ServerDisplayCategory.AiAndGeoUnlock);
            server.SupportsAiUnlock.Should().BeTrue();
        }
    }

    [Fact]
    public void Classify_Tier1NonBypass_IsFastEncrypted_AndCustomTier3Tier4_IsCustomAndDiscovered()
    {
        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();

        DnsServerEntry cloudflare = flagships.Single(static s => s.Id == "global_cloudflare_1111");
        ServerCategoryClassifier.Classify(cloudflare).Should().Be(ServerDisplayCategory.FastEncrypted);
        ServerCategoryClassifier.SupportsAiDomain(cloudflare).Should().BeFalse();
        ServerCategoryClassifier.IsGamingOnlyGeoServer(cloudflare).Should().BeFalse();

        DnsServerEntry tier3Level3 = flagships.Single(static s => s.Id == "global_level3");
        ServerCategoryClassifier.Classify(tier3Level3).Should().Be(ServerDisplayCategory.CustomAndDiscovered);
        ServerCategoryClassifier.SupportsAiDomain(tier3Level3).Should().BeFalse();

        DnsServerEntry sniProxy = flagships.First(static s => s.Protocol == DnsProtocol.SniProxy);
        ServerCategoryClassifier.Classify(sniProxy).Should().Be(ServerDisplayCategory.AutoProxy);
        ServerCategoryClassifier.SupportsAiDomain(sniProxy).Should().BeTrue();
        ServerCategoryClassifier.SupportsTargetDomain(sniProxy, "gemini.google.com").Should().BeTrue();
        ServerCategoryClassifier.SupportsTargetDomain(sniProxy, "open.spotify.com").Should().BeTrue();
        ServerCategoryClassifier.SupportsTargetDomain(sniProxy, "discord.com").Should().BeTrue();

        DnsServerEntry dnsAutoProxy = new()
        {
            Id = "custom_autoproxy_dns",
            Name = "Auto Proxy SmartDNS",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
            Category = "Auto Proxy",
            Tags = ["auto-proxy", "ai"],
            SupportsBypass = true,
            DohUrl = "https://autoproxy.example/dns-query"
        };
        ServerCategoryClassifier.Classify(dnsAutoProxy).Should().Be(ServerDisplayCategory.AutoProxy);
        ServerCategoryClassifier.IsAutoProxyServer(dnsAutoProxy).Should().BeTrue();

        DnsServerEntry customServer = new()
        {
            Id = "custom_vps_1",
            Name = "My Custom Smart-DNS",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier3CustomOrSelfHosted,
            SupportsBypass = true,
            IsBuiltin = false,
            DohUrl = "https://dns.custom.example/dns-query"
        };

        ServerCategoryClassifier.Classify(customServer).Should().Be(ServerDisplayCategory.CustomAndDiscovered);
        ServerCategoryClassifier.SupportsAiDomain(customServer).Should().BeTrue();
    }

    [Fact]
    public void IsAiDomain_RecognizesBuiltinAiHostsAndSubdomains()
    {
        ServerCategoryClassifier.IsAiDomain("aistudio.google.com").Should().BeTrue();
        ServerCategoryClassifier.IsAiDomain("gemini.google.com").Should().BeTrue();
        ServerCategoryClassifier.IsAiDomain("clients6.aistudio.google.com").Should().BeTrue();
        ServerCategoryClassifier.IsAiDomain("chatgpt.com").Should().BeTrue();
        ServerCategoryClassifier.IsAiDomain("xbox.com").Should().BeFalse();
        ServerCategoryClassifier.IsAiDomain(null).Should().BeFalse();
        ServerCategoryClassifier.IsAiDomain("   ").Should().BeFalse();
    }

    [Fact]
    public void ClassifyTargetDomain_MapsAiStreamingGamingSocialAndGeneral()
    {
        ServerCategoryClassifier.ClassifyTargetDomain("aistudio.google.com").Should().Be(TargetDomainClass.Ai);
        ServerCategoryClassifier.ClassifyTargetDomain("open.spotify.com").Should().Be(TargetDomainClass.Streaming);
        ServerCategoryClassifier.ClassifyTargetDomain("www.youtube.com").Should().Be(TargetDomainClass.Streaming);
        ServerCategoryClassifier.ClassifyTargetDomain("login.live.com").Should().Be(TargetDomainClass.Gaming);
        ServerCategoryClassifier.ClassifyTargetDomain("discord.com").Should().Be(TargetDomainClass.Social);
        ServerCategoryClassifier.ClassifyTargetDomain("one.one.one.one").Should().Be(TargetDomainClass.General);
    }
}
