using System.Net;
using DnsPulse.Core.Routing;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Routing;

public sealed class RuleParsersTests
{
    [Fact]
    public void ParseAdGuardRules_ParsesBlocksExceptionsAndSkipsUnsupportedLines()
    {
        const string input = """
            ! Title: Test Filter
            # Comment
            [Adblock Plus 2.0]
            ||ads.example.com^
            @@||allow.example.com^
            ||tracker.example.org^$important
            ||disabled.example.com^$badfilter
            ||rewrite.example.com^$dnsrewrite=127.0.0.1
            example.com##.banner
            /regex-rule/
            ||example.com/path/ad.js^
            """;

        IReadOnlyList<AdGuardRule> rules = RuleParsers.ParseAdGuardRules(input);

        rules.Should().HaveCount(3);
        rules[0].Should().Be(new AdGuardRule("ads.example.com", IsException: false, DomainMatchKind.Suffix));
        rules[1].Should().Be(new AdGuardRule("allow.example.com", IsException: true, DomainMatchKind.Suffix));
        rules[2].Should().Be(new AdGuardRule("tracker.example.org", IsException: false, DomainMatchKind.Suffix));
    }

    [Fact]
    public void ParseHostsFile_ParsesMultipleHostsPerLineAndInlineComments()
    {
        const string input = """
            # Sample HOSTS
            0.0.0.0 ads.one.test tracker.one.test # inline comment
            127.0.0.1   telemetry.example.org
            ::1         ipv6.sinkhole.test
            192.168.1.50 nas.home.arpa
            not-an-ip invalid.example
            """;

        IReadOnlyList<HostEntry> entries = RuleParsers.ParseHostsFile(input);

        entries.Should().HaveCount(5);
        entries[0].Should().Be(new HostEntry(IPAddress.Any, "ads.one.test"));
        entries[1].Should().Be(new HostEntry(IPAddress.Any, "tracker.one.test"));
        entries[2].Should().Be(new HostEntry(IPAddress.Loopback, "telemetry.example.org"));
        entries[3].Should().Be(new HostEntry(IPAddress.IPv6Loopback, "ipv6.sinkhole.test"));
        entries[4].Should().Be(new HostEntry(IPAddress.Parse("192.168.1.50"), "nas.home.arpa"));

        RuleParsers.IsHostsSinkholeAddress(IPAddress.Any).Should().BeTrue();
        RuleParsers.IsHostsSinkholeAddress(IPAddress.Loopback).Should().BeTrue();
        RuleParsers.IsHostsSinkholeAddress(IPAddress.IPv6Any).Should().BeTrue();
        RuleParsers.IsHostsSinkholeAddress(IPAddress.IPv6Loopback).Should().BeTrue();
        RuleParsers.IsHostsSinkholeAddress(IPAddress.Parse("192.168.1.50")).Should().BeFalse();
    }

    [Fact]
    public void ParseGeoSiteList_ParsesDomainFullWildcardAttributesAndIgnoresRegexp()
    {
        const string input = """
            # GeoSite sample
            domain:openai.com @ai
            full:api.anthropic.com
            *.spotify.com
            claude.ai
            keyword:ads
            regexp:^ad\d+\.
            """;

        IReadOnlyList<GeoSiteRule> rules = RuleParsers.ParseGeoSiteList(input);

        rules.Should().HaveCount(4);
        rules[0].Should().Be(new GeoSiteRule("openai.com", DomainMatchKind.Suffix, "ai"));
        rules[1].Should().Be(new GeoSiteRule("api.anthropic.com", DomainMatchKind.Exact, null));
        rules[2].Should().Be(new GeoSiteRule("spotify.com", DomainMatchKind.Wildcard, null));
        rules[3].Should().Be(new GeoSiteRule("claude.ai", DomainMatchKind.Suffix, null));
    }
}
