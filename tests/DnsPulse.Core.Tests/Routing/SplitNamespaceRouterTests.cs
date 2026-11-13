using DnsPulse.Core.Routing;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Routing;

public sealed class SplitNamespaceRouterTests
{
    [Theory]
    [InlineData("localhost")]
    [InlineData("localhost.")]
    [InlineData("sub.localhost")]
    [InlineData("printer.local")]
    [InlineData("router.lan")]
    [InlineData("nas.home.arpa")]
    [InlineData("vault.internal")]
    [InlineData("server.localdomain")]
    [InlineData("1.0.0.10.in-addr.arpa")]
    [InlineData("50.1.168.192.in-addr.arpa")]
    [InlineData("1.0.16.172.in-addr.arpa")]
    [InlineData("1.0.31.172.in-addr.arpa")]
    [InlineData("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa")]
    public void Route_BuiltinLocalAndPrivateReverseZones_ReturnZone1LocalBypass(string domain)
    {
        SplitNamespaceRouter router = new();

        RouteDecision decision = router.Route(domain);

        decision.Zone.Should().Be(RouteZone.Zone1LocalBypass);
        decision.IsBlocked.Should().BeFalse();
        decision.IsSecurityPinned.Should().BeFalse();
    }

    [Theory]
    [InlineData("1.0.15.172.in-addr.arpa")]
    [InlineData("1.0.32.172.in-addr.arpa")]
    public void Route_NonPrivate172ReverseZones_DoNotMatchZone1(string domain)
    {
        SplitNamespaceRouter router = new();

        RouteDecision decision = router.Route(domain);

        decision.Zone.Should().Be(RouteZone.Zone4EncryptedTrusted);
    }

    [Theory]
    [InlineData("windowsupdate.com")]
    [InlineData("fe2.update.microsoft.com")]
    [InlineData("www.msftconnecttest.com")]
    [InlineData("github.com")]
    [InlineData("api.github.com")]
    [InlineData("copilot-proxy.githubusercontent.com")]
    [InlineData("ocsp.digicert.com")]
    [InlineData("acme-v02.api.letsencrypt.org")]
    [InlineData("crl.sectigo.com")]
    [InlineData("pki.goog")]
    [InlineData("idmsa.apple.com")]
    [InlineData("ocsp.randomca.org")]
    [InlineData("crl.enterprise-ca.net")]
    [InlineData("accounts.google.com")]
    [InlineData("login.microsoftonline.com")]
    public void Route_SecurityPinnedDomains_ResistZone3HijackAndBlocklist(string domain)
    {
        SplitNamespaceRouterConfig config = new()
        {
            EncryptedTrustedProfileId = "trusted-doh",
            DefaultGeoUnlockProfileId = "smart-dns",
            BlockRules = [$"||{domain}^"],
            GeoUnlockRules = [new GeoUnlockRule(domain, "hijack-sni")]
        };
        SplitNamespaceRouter router = new(config);

        RouteDecision decision = router.Route(domain);

        decision.Zone.Should().Be(RouteZone.Zone4EncryptedTrusted);
        decision.IsSecurityPinned.Should().BeTrue();
        decision.IsBlocked.Should().BeFalse();
        decision.TargetProfileId.Should().Be("trusted-doh");
    }

    [Fact]
    public void Route_PrecedenceOrder_Zone1BeatsSecurityPinningAndBlockAndZone3()
    {
        SplitNamespaceRouterConfig config = new()
        {
            LocalBypassProfileId = "lan-dns",
            CorporateBypassDomains = ["corp.example.com"],
            BlockRules =
            [
                "||localhost^",
                "||ocsp.local^",
                "||corp.example.com^",
                "||ads.example.net^",
                "||blocked-geo.example.net^"
            ],
            GeoUnlockRules =
            [
                new GeoUnlockRule("corp.example.com", "smart-1"),
                new GeoUnlockRule("blocked-geo.example.net", "smart-1"),
                new GeoUnlockRule("gemini.google.com", "smart-ai")
            ]
        };
        SplitNamespaceRouter router = new(config);

        // Zone 1 beats Block & Zone 3 & ocsp.* prefix pin
        router.Route("ocsp.local").Zone.Should().Be(RouteZone.Zone1LocalBypass);
        router.Route("intranet.corp.example.com").Zone.Should().Be(RouteZone.Zone1LocalBypass);
        router.Route("intranet.corp.example.com").TargetProfileId.Should().Be("lan-dns");

        // Zone 2 Block beats Zone 3 GeoUnlock
        RouteDecision blockedGeo = router.Route("blocked-geo.example.net");
        blockedGeo.Zone.Should().Be(RouteZone.Zone2BlockOrProtect);
        blockedGeo.IsBlocked.Should().BeTrue();

        // Zone 3 Opt-in GeoUnlock
        RouteDecision geo = router.Route("gemini.google.com");
        geo.Zone.Should().Be(RouteZone.Zone3GeoUnlock);
        geo.IsBlocked.Should().BeFalse();
        geo.IsSecurityPinned.Should().BeFalse();
        geo.TargetProfileId.Should().Be("smart-ai");

        // Zone 4 Default Internet for unlisted domain
        RouteDecision def = router.Route("example.org");
        def.Zone.Should().Be(RouteZone.Zone4EncryptedTrusted);
        def.IsBlocked.Should().BeFalse();
        def.IsSecurityPinned.Should().BeFalse();
        def.MatchedRule.Should().Be("*");
    }

    [Fact]
    public void Route_AdGuardExceptionRule_UnblocksMatchingSubdomainIntoZone3OrZone4()
    {
        SplitNamespaceRouterConfig config = new()
        {
            BlockRules =
            [
                "||tracking.example.com^",
                "@@||safe.tracking.example.com^",
                "0.0.0.0 banner.ads.test"
            ],
            AllowExceptionRules =
            [
                "@@||banner.ads.test^"
            ],
            GeoUnlockRules =
            [
                new GeoUnlockRule("safe.tracking.example.com", "geo-1")
            ]
        };
        SplitNamespaceRouter router = new(config);

        router.Route("pixel.tracking.example.com").IsBlocked.Should().BeTrue();

        RouteDecision allowedGeo = router.Route("safe.tracking.example.com");
        allowedGeo.IsBlocked.Should().BeFalse();
        allowedGeo.Zone.Should().Be(RouteZone.Zone3GeoUnlock);

        RouteDecision allowedDefault = router.Route("banner.ads.test");
        allowedDefault.IsBlocked.Should().BeFalse();
        allowedDefault.Zone.Should().Be(RouteZone.Zone4EncryptedTrusted);
    }

    [Fact]
    public void UpdateConfiguration_AtomicallySwapsSnapshot()
    {
        SplitNamespaceRouter router = new();
        router.Route("chatgpt.com").Zone.Should().Be(RouteZone.Zone4EncryptedTrusted);

        SplitNamespaceRouterConfig updated = new()
        {
            GeoUnlockRules = [new GeoUnlockRule("chatgpt.com", "us-smart")]
        };
        router.UpdateConfiguration(updated);

        RouteDecision decision = router.Route("chatgpt.com");
        decision.Zone.Should().Be(RouteZone.Zone3GeoUnlock);
        decision.TargetProfileId.Should().Be("us-smart");
    }
}
