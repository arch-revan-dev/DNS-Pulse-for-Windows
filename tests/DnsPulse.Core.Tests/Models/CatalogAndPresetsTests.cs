using DnsPulse.Core.Models;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Models;

public sealed class CatalogAndPresetsTests
{
    [Fact]
    public void BuiltInPresets_ShouldContainAllLegacyV153GroupsCategoriesAnd15Presets()
    {
        BuiltInCatalogPresets.PresetGroups.Should().HaveCount(5);
        BuiltInCatalogPresets.PresetGroups.Select(g => g.Id)
            .Should().ContainInOrder("ai", "streaming", "gaming", "all", "custom");

        BuiltInCatalogPresets.AllPresets.Should().HaveCount(15);
        BuiltInCatalogPresets.AllPresets.Single(p => p.IsSelected).Domain.Should().Be("gemini.google.com");
        BuiltInCatalogPresets.AllPresets.Where(p => !p.RequiresBypass)
            .Select(p => p.Domain)
            .Should().BeEquivalentTo(["one.one.one.one", "www.google.com"]);

        BuiltInCatalogPresets.CategoryNames.Should().HaveCount(7);
        BuiltInCatalogPresets.CategoryNames.Should().Contain("Smart-DNS");
    }

    [Fact]
    public void BuiltInBypassDomains_ShouldContainAll82UniqueDomains()
    {
        BuiltInCatalogPresets.BuiltinAiDomains.Should().HaveCount(52);
        BuiltInCatalogPresets.BuiltinStreamingDomains.Should().HaveCount(12);
        BuiltInCatalogPresets.BuiltinGamingDomains.Should().HaveCount(18);
        BuiltInCatalogPresets.AllBuiltinBypassDomains.Should().HaveCount(82);
        BuiltInCatalogPresets.AllBuiltinBypassDomains.Should().Contain("gemini.google.com");
        BuiltInCatalogPresets.AllBuiltinBypassDomains.Should().Contain("open.spotify.com");
        BuiltInCatalogPresets.AllBuiltinBypassDomains.Should().Contain("game.brawlstarsgame.com");
    }

    [Fact]
    public void BuildFlagshipServers_ShouldMigrate72FlagshipsWithStrictTrustTierIsolation()
    {
        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();

        flagships.Should().HaveCount(72);
        flagships.Should().OnlyContain(s => s.IsBuiltin && !s.IsFavorite && !s.IsSubscription);

        IEnumerable<DnsServerEntry> sniNodes = flagships.Where(s => s.Protocol == DnsProtocol.SniProxy);
        sniNodes.Should().HaveCount(14);
        sniNodes.Should().OnlyContain(s =>
            s.TrustTier == TrustTier.Tier4ExperimentalLab &&
            !s.IsEligibleForDefaultInternet);

        IEnumerable<DnsServerEntry> bezmezhauNodes = flagships.Where(s => s.Id.StartsWith("smart_bezmezhau_gemini", StringComparison.Ordinal));
        bezmezhauNodes.Should().HaveCount(20);
        bezmezhauNodes.Should().OnlyContain(s => s.TrustTier == TrustTier.Tier2VerifiedGeoUnlock);

        DnsServerEntry cloudflare = flagships.Single(s => s.Id == "global_cloudflare_1111");
        cloudflare.TrustTier.Should().Be(TrustTier.Tier1EncryptedTrusted);
        cloudflare.IsEligibleForDefaultInternet.Should().BeTrue();
        cloudflare.BootstrapIps.Should().ContainInOrder("1.1.1.1", "1.0.0.1");

        DnsServerEntry level3 = flagships.Single(s => s.Id == "global_level3");
        level3.Protocol.Should().Be(DnsProtocol.Udp);
        level3.TrustTier.Should().Be(TrustTier.Tier3CustomOrSelfHosted);
        level3.IsEligibleForDefaultInternet.Should().BeFalse();
    }

    [Theory]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.DoH, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.DoT, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.DoH3, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.DoQ, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.DnsCrypt, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.AnonymizedDnsCrypt, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.ODoH, true)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.Udp, false)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.Tcp, false)]
    [InlineData(TrustTier.Tier1EncryptedTrusted, DnsProtocol.SniProxy, false)]
    [InlineData(TrustTier.Tier2VerifiedGeoUnlock, DnsProtocol.DoH, false)]
    [InlineData(TrustTier.Tier3CustomOrSelfHosted, DnsProtocol.DoH, false)]
    [InlineData(TrustTier.Tier4ExperimentalLab, DnsProtocol.DoH, false)]
    [InlineData(TrustTier.Tier4ExperimentalLab, DnsProtocol.SniProxy, false)]
    public void TrustTierPolicy_ShouldNeverAllowTier4OrUnencryptedOrSniProxyForDefaultInternet(
        TrustTier tier,
        DnsProtocol protocol,
        bool expectedEligible)
    {
        TrustTierPolicy.CanServeDefaultInternet(tier, protocol).Should().Be(expectedEligible);
    }

    [Fact]
    public void CatalogTsvLoader_ParseTsvContent_ShouldParseDeduplicateAndAssignTrustTiers()
    {
        const string sampleTsv = """
            id	name	provider	protocol	primaryIp	secondaryIp	dohUrl	dotHost	category	country	tags	description	supportsBypass
            cat_0001	Cloudflare Edge [DE-FRA]	Cloudflare	DoH	1.1.1.1	1.0.0.1	https://cloudflare-dns.com/dns-query	one.one.one.one	Скоростные	DE	скоростные,de,doh,catalog	Cloudflare DE	false
            cat_0007	DNS.SB Anycast [DE-FRA]	DNS.SB	UDP	185.222.222.222	45.11.45.11		dot.dns.sb	Скоростные	DE	скоростные,de,udp	DNS.SB UDP	false
            custom_sni	Custom SNI	Relay	SNI443	185.236.10.37			sni.example	Smart-DNS	NL	sni443,smartproxy	Test SNI	true
            custom_smart	Custom Smart	Smart	DoH	179.254.166.171		https://smart.example/dns-query		Smart-DNS	EU	smart-dns	Test Smart	true
            cat_0001	Duplicate Row	Dup	DoH	9.9.9.9		https://dup.example/dns-query		Скоростные	CH	dup	Dup	false
            malformed_row	only_two_cols
            """;

        IReadOnlyList<DnsServerEntry> parsed = CatalogTsvLoader.ParseTsvContent(sampleTsv);

        parsed.Should().HaveCount(4);

        DnsServerEntry doh = parsed[0];
        doh.Id.Should().Be("cat_0001");
        doh.Protocol.Should().Be(DnsProtocol.DoH);
        doh.TrustTier.Should().Be(TrustTier.Tier1EncryptedTrusted);
        doh.IsEligibleForDefaultInternet.Should().BeTrue();
        doh.BootstrapIps.Should().ContainInOrder("1.1.1.1", "1.0.0.1");
        doh.Tags.Should().ContainInOrder("скоростные", "de", "doh", "catalog");

        DnsServerEntry udp = parsed[1];
        udp.Protocol.Should().Be(DnsProtocol.Udp);
        udp.TrustTier.Should().Be(TrustTier.Tier3CustomOrSelfHosted);
        udp.IsEligibleForDefaultInternet.Should().BeFalse();

        DnsServerEntry sni = parsed[2];
        sni.Protocol.Should().Be(DnsProtocol.SniProxy);
        sni.TrustTier.Should().Be(TrustTier.Tier4ExperimentalLab);
        sni.SmartProxyIp.Should().Be("185.236.10.37");
        sni.Port.Should().Be(443);
        sni.IsEligibleForDefaultInternet.Should().BeFalse();

        DnsServerEntry smart = parsed[3];
        smart.Protocol.Should().Be(DnsProtocol.DoH);
        smart.TrustTier.Should().Be(TrustTier.Tier2VerifiedGeoUnlock);
        smart.SupportsBypass.Should().BeTrue();
        smart.IsEligibleForDefaultInternet.Should().BeFalse();
    }

    [Fact]
    public void CatalogTsvLoader_LoadFromFile_ShouldLoadFullRepoCatalogWhenPresent()
    {
        string? tsvPath = FindRepoCatalogPath();
        if (tsvPath is null)
        {
            return;
        }

        IReadOnlyList<DnsServerEntry> catalog = CatalogTsvLoader.LoadFromFile(tsvPath, includeFlagships: true);

        catalog.Should().HaveCount(1092);
        catalog.Select(c => c.Id).Should().OnlyHaveUniqueItems();
        catalog.Where(c => c.Protocol == DnsProtocol.SniProxy)
            .Should().OnlyContain(c => c.TrustTier == TrustTier.Tier4ExperimentalLab && !c.IsEligibleForDefaultInternet);
        catalog.Where(c => c.Protocol == DnsProtocol.Udp)
            .Should().OnlyContain(c => c.TrustTier != TrustTier.Tier1EncryptedTrusted && !c.IsEligibleForDefaultInternet);
    }

    private static string? FindRepoCatalogPath()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "assets", "dns_catalog_1000.tsv");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        return null;
    }
}
