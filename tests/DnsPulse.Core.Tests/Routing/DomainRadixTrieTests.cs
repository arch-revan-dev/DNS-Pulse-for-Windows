using DnsPulse.Core.Routing;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Routing;

public sealed class DomainRadixTrieTests
{
    [Fact]
    public void TryMatch_ExactMatch_MatchesOnlyExactDomain()
    {
        DomainRadixTrieBuilder<string> builder = new();
        builder.TryAddExact("api.example.com", "exact").Should().BeTrue();
        DomainRadixTrie<string> trie = builder.Build();

        trie.TryMatch("api.example.com", out DomainMatchResult<string>? hit).Should().BeTrue();
        hit!.Value.Should().Be("exact");
        hit.MatchKind.Should().Be(DomainMatchKind.Exact);

        trie.TryMatch("v2.api.example.com", out _).Should().BeFalse();
        trie.TryMatch("example.com", out _).Should().BeFalse();
    }

    [Fact]
    public void TryMatch_WildcardMatch_MatchesSubdomainsButNotApex()
    {
        DomainRadixTrieBuilder<string> builder = new();
        builder.TryAddPattern("*.example.com", "wild").Should().BeTrue();
        DomainRadixTrie<string> trie = builder.Build();

        trie.TryMatch("example.com", out _).Should().BeFalse();

        trie.TryMatch("sub.example.com", out DomainMatchResult<string>? hit1).Should().BeTrue();
        hit1!.Value.Should().Be("wild");
        hit1.MatchKind.Should().Be(DomainMatchKind.Wildcard);
        hit1.MatchedPattern.Should().Be("*.example.com");

        trie.TryMatch("deep.sub.example.com", out DomainMatchResult<string>? hit2).Should().BeTrue();
        hit2!.Value.Should().Be("wild");
    }

    [Fact]
    public void TryMatch_SuffixMatch_MatchesApexAndSubdomainsOnLabelBoundaries()
    {
        DomainRadixTrieBuilder<string> builder = new();
        builder.TryAddSuffix("example.com", "suffix").Should().BeTrue();
        DomainRadixTrie<string> trie = builder.Build();

        trie.TryMatch("example.com", out DomainMatchResult<string>? apex).Should().BeTrue();
        apex!.Value.Should().Be("suffix");
        apex.MatchKind.Should().Be(DomainMatchKind.Suffix);

        trie.TryMatch("a.b.example.com", out DomainMatchResult<string>? sub).Should().BeTrue();
        sub!.Value.Should().Be("suffix");

        trie.TryMatch("notexample.com", out _).Should().BeFalse();
    }

    [Fact]
    public void TryMatch_SpecificityPrecedence_ExactBeatsWildcardBeatsSuffix()
    {
        DomainRadixTrieBuilder<string> builder = new();
        builder.TryAddSuffix("example.com", "S");
        builder.TryAddWildcard("example.com", "W");
        builder.TryAddExact("api.example.com", "E");
        DomainRadixTrie<string> trie = builder.Build();

        trie.TryMatch("api.example.com", out DomainMatchResult<string>? exactHit).Should().BeTrue();
        exactHit!.Value.Should().Be("E");
        exactHit.MatchKind.Should().Be(DomainMatchKind.Exact);

        trie.TryMatch("cdn.example.com", out DomainMatchResult<string>? wildHit).Should().BeTrue();
        wildHit!.Value.Should().Be("W");
        wildHit.MatchKind.Should().Be(DomainMatchKind.Wildcard);

        trie.TryMatch("example.com", out DomainMatchResult<string>? suffixHit).Should().BeTrue();
        suffixHit!.Value.Should().Be("S");
        suffixHit.MatchKind.Should().Be(DomainMatchKind.Suffix);
    }

    [Theory]
    [InlineData("API.EXAMPLE.COM.")]
    [InlineData("  api.Example.com  ")]
    public void TryMatch_CaseInsensitiveAndTrailingDot_NormalizedCorrectly(string query)
    {
        DomainRadixTrieBuilder<string> builder = new();
        builder.TryAddExact("api.example.com", "ok");
        DomainRadixTrie<string> trie = builder.Build();

        trie.TryMatch(query, out DomainMatchResult<string>? hit).Should().BeTrue();
        hit!.Value.Should().Be("ok");
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData(".example.com")]
    [InlineData("bad..example.com")]
    [InlineData("bad domain.com")]
    public void TryMatch_InvalidDomain_ReturnsFalse(string invalidDomain)
    {
        DomainRadixTrieBuilder<string> builder = new();
        builder.TryAddSuffix("example.com", "ok");
        DomainRadixTrie<string> trie = builder.Build();

        trie.TryMatch(invalidDomain, out _).Should().BeFalse();
    }
}
