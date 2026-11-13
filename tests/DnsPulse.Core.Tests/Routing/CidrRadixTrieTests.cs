using System.Net;
using DnsPulse.Core.Routing;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Routing;

public sealed class CidrRadixTrieTests
{
    [Fact]
    public void TryMatch_Ipv4LongestPrefixMatch_SelectsMostSpecificPrefix()
    {
        CidrRadixTrieBuilder<string> builder = new();
        builder.TryAddCidr("0.0.0.0/0", "default").Should().BeTrue();
        builder.TryAddCidr("10.0.0.0/8", "rfc1918").Should().BeTrue();
        builder.TryAddCidr("10.202.10.0/24", "carrier-anycast").Should().BeTrue();
        builder.TryAddCidr("10.202.10.202/32", "exact-host").Should().BeTrue();
        CidrRadixTrie<string> trie = builder.Build();

        trie.TryMatch("8.8.8.8", out CidrMatchResult<string>? m0).Should().BeTrue();
        m0!.Value.Should().Be("default");
        m0.PrefixLength.Should().Be(0);

        trie.TryMatch("10.1.2.3", out CidrMatchResult<string>? m8).Should().BeTrue();
        m8!.Value.Should().Be("rfc1918");
        m8.PrefixLength.Should().Be(8);

        trie.TryMatch("10.202.10.10", out CidrMatchResult<string>? m24).Should().BeTrue();
        m24!.Value.Should().Be("carrier-anycast");
        m24.PrefixLength.Should().Be(24);

        trie.TryMatch("10.202.10.202", out CidrMatchResult<string>? m32).Should().BeTrue();
        m32!.Value.Should().Be("exact-host");
        m32.PrefixLength.Should().Be(32);
    }

    [Fact]
    public void TryMatch_Ipv6LongestPrefixMatch_HandlesSlash0ToSlash128()
    {
        CidrRadixTrieBuilder<string> builder = new();
        builder.TryAddCidr("::/0", "v6-default").Should().BeTrue();
        builder.TryAddCidr("fc00::/7", "ula").Should().BeTrue();
        builder.TryAddCidr("fe80::/10", "link-local").Should().BeTrue();
        builder.TryAddCidr("::1/128", "loopback").Should().BeTrue();
        CidrRadixTrie<string> trie = builder.Build();

        trie.TryMatch("2606:4700:4700::1111", out CidrMatchResult<string>? def).Should().BeTrue();
        def!.Value.Should().Be("v6-default");

        trie.TryMatch("fd12:3456:789a::1", out CidrMatchResult<string>? ula).Should().BeTrue();
        ula!.Value.Should().Be("ula");
        ula.PrefixLength.Should().Be(7);

        trie.TryMatch("fe80::1ff:fe23:4567:890a", out CidrMatchResult<string>? ll).Should().BeTrue();
        ll!.Value.Should().Be("link-local");
        ll.PrefixLength.Should().Be(10);

        trie.TryMatch("::1", out CidrMatchResult<string>? lo).Should().BeTrue();
        lo!.Value.Should().Be("loopback");
        lo.PrefixLength.Should().Be(128);
    }

    [Fact]
    public void TryAddCidr_MasksHostBitsToCanonicalNetwork()
    {
        CidrRadixTrieBuilder<string> builder = new();
        builder.TryAddCidr("192.168.1.99/24", "lan").Should().BeTrue();
        CidrRadixTrie<string> trie = builder.Build();

        trie.TryMatch("192.168.1.1", out CidrMatchResult<string>? hit).Should().BeTrue();
        hit!.MatchedCidr.Should().Be("192.168.1.0/24");
        trie.TryMatch("192.168.2.1", out _).Should().BeFalse();
    }

    [Fact]
    public void TryMatch_UnwrapIpv4Mapped_MatchesIpv4RuleWhenEnabled()
    {
        CidrRadixTrieBuilder<string> builder = new();
        builder.TryAddCidr("127.0.0.0/8", "loopback");
        CidrRadixTrie<string> trie = builder.Build();

        IPAddress mapped = IPAddress.Parse("::ffff:127.0.0.1");
        trie.TryMatch(mapped, out _, unwrapIpv4Mapped: false).Should().BeFalse();
        trie.TryMatch(mapped, out CidrMatchResult<string>? hit, unwrapIpv4Mapped: true).Should().BeTrue();
        hit!.Value.Should().Be("loopback");
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("fc00::/129")]
    [InlineData("not-an-ip/24")]
    [InlineData("")]
    public void TryAddCidr_InvalidPrefix_ReturnsFalse(string invalidCidr)
    {
        CidrRadixTrieBuilder<string> builder = new();
        builder.TryAddCidr(invalidCidr, "bad").Should().BeFalse();
    }
}
