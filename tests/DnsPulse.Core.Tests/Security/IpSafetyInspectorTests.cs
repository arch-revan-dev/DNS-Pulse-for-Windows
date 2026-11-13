using System.Net;
using DnsPulse.Core.Security;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Security;

public sealed class IpSafetyInspectorTests
{
    [Theory]
    [InlineData("0.0.0.0", IpAddressCategory.Unspecified)]
    [InlineData("127.0.0.1", IpAddressCategory.Loopback)]
    [InlineData("127.255.255.254", IpAddressCategory.Loopback)]
    [InlineData("10.0.0.1", IpAddressCategory.PrivateRfc1918)]
    [InlineData("172.16.0.1", IpAddressCategory.PrivateRfc1918)]
    [InlineData("172.31.255.254", IpAddressCategory.PrivateRfc1918)]
    [InlineData("192.168.1.1", IpAddressCategory.PrivateRfc1918)]
    [InlineData("100.64.0.1", IpAddressCategory.CarrierGradeNat)]
    [InlineData("100.127.255.254", IpAddressCategory.CarrierGradeNat)]
    [InlineData("169.254.169.254", IpAddressCategory.LinkLocal)]
    [InlineData("224.0.0.1", IpAddressCategory.Multicast)]
    [InlineData("239.255.255.250", IpAddressCategory.Multicast)]
    [InlineData("240.0.0.1", IpAddressCategory.SpecialUseOrBogon)]
    [InlineData("255.255.255.255", IpAddressCategory.SpecialUseOrBogon)]
    [InlineData("192.0.2.1", IpAddressCategory.SpecialUseOrBogon)]
    [InlineData("198.18.0.1", IpAddressCategory.SpecialUseOrBogon)]
    [InlineData("203.0.113.5", IpAddressCategory.SpecialUseOrBogon)]
    [InlineData("::", IpAddressCategory.Unspecified)]
    [InlineData("::1", IpAddressCategory.Loopback)]
    [InlineData("fc00::1", IpAddressCategory.UniqueLocalIpv6)]
    [InlineData("fd12:3456:789a::1", IpAddressCategory.UniqueLocalIpv6)]
    [InlineData("fe80::1", IpAddressCategory.LinkLocal)]
    [InlineData("ff02::1", IpAddressCategory.Multicast)]
    [InlineData("2001:db8::1", IpAddressCategory.SpecialUseOrBogon)]
    public void Inspect_NonPublicAddresses_DetectedAsPrivateOrBogon(string ip, IpAddressCategory expectedCategory)
    {
        IpInspectionResult result = IpSafetyInspector.Inspect(IPAddress.Parse(ip));

        result.Category.Should().Be(expectedCategory);
        result.IsPrivateOrBogon.Should().BeTrue();
        result.IsPublicRoutable.Should().BeFalse();
        result.WasIpv4MappedIpv6.Should().BeFalse();
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("172.15.255.254")]
    [InlineData("172.32.0.1")]
    [InlineData("100.63.255.254")]
    [InlineData("100.128.0.1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888")]
    public void Inspect_PublicAddresses_ClassifiedAsPublicRoutable(string ip)
    {
        IpInspectionResult result = IpSafetyInspector.Inspect(IPAddress.Parse(ip));

        result.Category.Should().Be(IpAddressCategory.Public);
        result.IsPublicRoutable.Should().BeTrue();
        result.IsPrivateOrBogon.Should().BeFalse();
    }

    [Theory]
    [InlineData("::ffff:127.0.0.1", IpAddressCategory.Loopback, false)]
    [InlineData("::ffff:10.0.0.1", IpAddressCategory.PrivateRfc1918, false)]
    [InlineData("::ffff:192.168.1.1", IpAddressCategory.PrivateRfc1918, false)]
    [InlineData("::ffff:100.64.0.1", IpAddressCategory.CarrierGradeNat, false)]
    [InlineData("::ffff:169.254.169.254", IpAddressCategory.LinkLocal, false)]
    [InlineData("::ffff:224.0.0.1", IpAddressCategory.Multicast, false)]
    [InlineData("::ffff:8.8.8.8", IpAddressCategory.Public, true)]
    public void Inspect_Ipv4MappedIpv6_UnwrapsViaMapToIpv4AndClassifies(
        string mappedIp,
        IpAddressCategory expectedCategory,
        bool expectedPublic)
    {
        IPAddress parsed = IPAddress.Parse(mappedIp);
        parsed.IsIPv4MappedToIPv6.Should().BeTrue();

        IpInspectionResult result = IpSafetyInspector.Inspect(parsed);

        result.WasIpv4MappedIpv6.Should().BeTrue();
        result.NormalizedAddress.Should().Be(parsed.MapToIPv4());
        result.Category.Should().Be(expectedCategory);
        result.IsPublicRoutable.Should().Be(expectedPublic);
        result.IsPrivateOrBogon.Should().Be(!expectedPublic);
    }
}
