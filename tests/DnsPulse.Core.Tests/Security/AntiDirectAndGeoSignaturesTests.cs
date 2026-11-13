using DnsPulse.Core.Security;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Security;

public sealed class AntiDirectAndGeoSignaturesTests
{
    private static readonly string[] ExpectedAiStudioCompanions =
    [
        "alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "gemini.google.com"
    ];

    private static readonly string[] ExpectedChatGptCompanions =
    [
        "api.openai.com",
        "auth.openai.com"
    ];

    [Fact]
    public void BuiltinPrefixCatalogCounts_MatchLegacyAudit()
    {
        AntiDirectAndGeoSignatures.GoogleDirectCidrs.Should().HaveCount(18);
        AntiDirectAndGeoSignatures.AiAndVendorDirectCidrs.Should().HaveCount(19);
    }

    [Theory]
    [InlineData("142.250.185.78", "gemini.google.com", true)]
    [InlineData("34.117.59.81", "aistudio.google.com", true)]
    [InlineData("185.199.108.153", "gemini.google.com", false)]
    [InlineData("104.18.32.47", "chatgpt.com", true)]
    [InlineData("172.64.155.12", "claude.ai", true)]
    [InlineData("192.255.159.240", "chatgpt.com", false)]
    [InlineData("127.0.0.1", "example.com", true)]
    [InlineData("::ffff:142.250.1.1", "gemini.google.com", true)]
    public void IsDirectServiceIp_DetectsDirectGoogleAndVendorRanges(string ip, string domain, bool expectedDirect)
    {
        AntiDirectAndGeoSignatures.IsDirectServiceIp(ip, domain).Should().Be(expectedDirect);
    }

    [Theory]
    [InlineData(403, null, true)]
    [InlineData(451, null, true)]
    [InlineData(302, "https://ai.google.dev/available-regions", true)]
    [InlineData(302, "https://example.com/region-not-supported", true)]
    [InlineData(302, "https://www.google.com/sorry/index", true)]
    [InlineData(200, "https://aistudio.google.com/welcome", false)]
    public void IsGeoBlockedRedirect_DetectsGeoStatusAndLocations(int statusCode, string? location, bool expected)
    {
        AntiDirectAndGeoSignatures.IsGeoBlockedRedirect(statusCode, location).Should().Be(expected);
    }

    [Fact]
    public void IsGeoBlockedBody_Respects8KbInspectionLimitAndMatchesMarkers()
    {
        AntiDirectAndGeoSignatures.IsGeoBlockedBody("<html>Sorry, not available in your country</html>").Should().BeTrue();
        AntiDirectAndGeoSignatures.IsGeoBlockedBody("<html>Welcome to AI Studio</html>").Should().BeFalse();

        string padding = new('a', 9000);
        string bodyBeyond8Kb = string.Concat(padding, "available-regions");
        AntiDirectAndGeoSignatures.IsGeoBlockedBody(bodyBeyond8Kb).Should().BeFalse();
    }

    [Theory]
    [InlineData("CF-Mitigated", "challenge", true)]
    [InlineData("X-Geo-Block", "1", true)]
    [InlineData("Location", "/geo/blocked", true)]
    [InlineData("Content-Type", "text/html", false)]
    public void IsGeoBlockedResponseHeader_DetectsBlockingHeaders(string name, string value, bool expected)
    {
        AntiDirectAndGeoSignatures.IsGeoBlockedResponseHeader(name, value).Should().Be(expected);
    }

    [Fact]
    public void GetCompanionDomains_ReturnsExpectedDependencies()
    {
        AntiDirectAndGeoSignatures.GetCompanionDomains("aistudio.google.com")
            .Should()
            .Contain(ExpectedAiStudioCompanions);

        AntiDirectAndGeoSignatures.GetCompanionDomains("chatgpt.com")
            .Should()
            .BeEquivalentTo(ExpectedChatGptCompanions);

        AntiDirectAndGeoSignatures.GetCompanionDomains("example.com")
            .Should()
            .BeEmpty();
    }
}
