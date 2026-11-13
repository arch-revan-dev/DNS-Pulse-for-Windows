using System.Net;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Security;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Security;

public sealed class DnsRebindingValidatorTests
{
    [Fact]
    public void ValidateAnswer_PublicZonesRejectPrivateBogonAndIpv4MappedLoopback()
    {
        IPAddress[] answers =
        [
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("192.168.1.10"),
            IPAddress.Parse("100.64.0.5"),
            IPAddress.Parse("169.254.169.254"),
            IPAddress.Parse("::1"),
            IPAddress.Parse("fc00::1"),
            IPAddress.Parse("fe80::1"),
            IPAddress.Parse("::ffff:127.0.0.1")
        ];

        DnsRebindingValidationResult result = DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone4EncryptedTrusted,
            answers);

        result.IsSafe.Should().BeFalse();
        result.RejectionReason.Should().NotBeNullOrWhiteSpace();
        result.AcceptedAddresses.Should().ContainSingle().Which.Should().Be(IPAddress.Parse("1.1.1.1"));
        result.RejectedAddresses.Should().HaveCount(8);
    }

    [Fact]
    public void ValidateAnswer_Zone1LocalBypass_PermitsPrivateLanAddresses()
    {
        IPAddress[] answers =
        [
            IPAddress.Parse("192.168.1.50"),
            IPAddress.Parse("10.0.0.12"),
            IPAddress.Parse("fd00::50")
        ];

        DnsRebindingValidationResult result = DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone1LocalBypass,
            answers);

        result.IsSafe.Should().BeTrue();
        result.AcceptedAddresses.Should().HaveCount(3);
        result.RejectedAddresses.Should().BeEmpty();
    }

    [Fact]
    public void ValidateAnswer_CarrierAnycastException_PermittedOnlyWhenOptedInForNamedBuiltinEndpoint()
    {
        IPAddress[] carrierAnswer = [IPAddress.Parse("10.202.10.202")];
        IPAddress[] arbitraryPrivate = [IPAddress.Parse("192.168.1.1")];

        // Disabled by default: 10.202.10.202 must be rejected as RFC 1918
        DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone4EncryptedTrusted,
            carrierAnswer,
            allowCarrierAnycastExceptions: false,
            namedCarrierEndpointId: "403.online").IsSafe.Should().BeFalse();

        // Unknown endpoint name: still rejected even with flag enabled
        DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone4EncryptedTrusted,
            carrierAnswer,
            allowCarrierAnycastExceptions: true,
            namedCarrierEndpointId: "untrusted-custom").IsSafe.Should().BeFalse();

        // Arbitrary private IP: still rejected even for named carrier endpoint
        DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone4EncryptedTrusted,
            arbitraryPrivate,
            allowCarrierAnycastExceptions: true,
            namedCarrierEndpointId: "403.online").IsSafe.Should().BeFalse();

        // Explicit opt-in + named built-in carrier endpoint + 10.202.10.* -> permitted
        DnsRebindingValidationResult allowed = DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone3GeoUnlock,
            carrierAnswer,
            allowCarrierAnycastExceptions: true,
            namedCarrierEndpointId: "403.online");

        allowed.IsSafe.Should().BeTrue();
        allowed.AcceptedAddresses.Should().ContainSingle();
    }

    [Fact]
    public void IsAllowedResolverEndpointIp_EnforcesCarrierAnycastOptInRules()
    {
        IPAddress radarIp = IPAddress.Parse("10.202.10.10");

        DnsRebindingValidator.IsAllowedResolverEndpointIp(radarIp).Should().BeFalse();
        DnsRebindingValidator.IsAllowedResolverEndpointIp(radarIp, allowCarrierAnycastExceptions: true, "unknown").Should().BeFalse();
        DnsRebindingValidator.IsAllowedResolverEndpointIp(radarIp, allowCarrierAnycastExceptions: true, "radar-game").Should().BeTrue();
        DnsRebindingValidator.IsAllowedResolverEndpointIp(IPAddress.Parse("127.0.0.1"), allowCarrierAnycastExceptions: true, "radar-game").Should().BeFalse();
    }
}
