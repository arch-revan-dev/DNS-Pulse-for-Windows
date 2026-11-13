using System.Buffers;

namespace DnsPulse.Core.Routing;

/// <summary>
/// Specifies how a domain rule matched inside a <see cref="DomainRadixTrie{T}"/>.
/// Ordered by specificity from least specific to most specific.
/// </summary>
public enum DomainMatchKind
{
    /// <summary>
    /// Unassigned / no match.
    /// </summary>
    None = 0,

    /// <summary>
    /// Matches the anchor domain and all of its subdomains.
    /// </summary>
    Suffix = 1,

    /// <summary>
    /// Matches subdomains of the anchor domain (<c>*.example.com</c>), excluding the bare anchor.
    /// </summary>
    Wildcard = 2,

    /// <summary>
    /// Matches only the exact domain name.
    /// </summary>
    Exact = 3
}

/// <summary>
/// Represents a successful domain lookup result from <see cref="DomainRadixTrie{T}"/>.
/// </summary>
/// <typeparam name="T">The payload type stored for the matched rule.</typeparam>
/// <param name="Value">The stored rule payload.</param>
/// <param name="MatchKind">The match specificity kind.</param>
/// <param name="MatchedPattern">The canonical pattern string that matched.</param>
public sealed record DomainMatchResult<T>(
    T Value,
    DomainMatchKind MatchKind,
    string MatchedPattern);

/// <summary>
/// Immutable, lock-free, label-reversed domain radix/suffix trie supporting exact, wildcard (<c>*.example.com</c>),
/// and suffix (<c>example.com</c>) rules with deterministic specificity (<c>Exact &gt; Wildcard &gt; Suffix</c>).
/// </summary>
/// <typeparam name="T">The payload type associated with each rule.</typeparam>
public sealed class DomainRadixTrie<T>
{
    private static readonly SearchValues<char> AllowedLabelChars =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    private readonly TrieNode _root;

    internal DomainRadixTrie(TrieNode root, int ruleCount)
    {
        _root = root;
        RuleCount = ruleCount;
    }

    /// <summary>
    /// Initializes an empty <see cref="DomainRadixTrie{T}"/>.
    /// </summary>
    public DomainRadixTrie()
    {
        _root = new TrieNode([], false, default, null, false, default, null, false, default, null);
        RuleCount = 0;
    }

    /// <summary>
    /// Gets the total number of rules registered in this trie.
    /// </summary>
    public int RuleCount { get; }

    /// <summary>
    /// Attempts to find the most specific matching rule for <paramref name="domain"/>.
    /// </summary>
    /// <param name="domain">The queried domain name.</param>
    /// <param name="result">The most specific match result, if any.</param>
    /// <returns><c>true</c> if a rule matched; otherwise <c>false</c>.</returns>
    public bool TryMatch(string domain, out DomainMatchResult<T>? result)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return TryMatch(domain.AsSpan(), out result);
    }

    /// <summary>
    /// Attempts to find the most specific matching rule for <paramref name="domain"/> without heap allocation.
    /// </summary>
    /// <param name="domain">The queried domain span.</param>
    /// <param name="result">The most specific match result, if any.</param>
    /// <returns><c>true</c> if a rule matched; otherwise <c>false</c>.</returns>
    public bool TryMatch(ReadOnlySpan<char> domain, out DomainMatchResult<T>? result)
    {
        result = null;
        ReadOnlySpan<char> trimmed = TrimDomainSpan(domain);
        if (trimmed.IsEmpty || trimmed.Length > 253 || trimmed[0] == '.')
        {
            return false;
        }

        // Walk labels right-to-left (from TLD toward leftmost subdomain).
        TrieNode current = _root;
        DomainMatchResult<T>? bestAncestorMatch = null;

        int end = trimmed.Length;
        while (end > 0)
        {
            int dotIndex = trimmed[..end].LastIndexOf('.');
            int labelStart = dotIndex + 1;
            ReadOnlySpan<char> label = trimmed[labelStart..end];
            if (label.IsEmpty || label.Length > 63 || label.ContainsAnyExcept(AllowedLabelChars))
            {
                return false;
            }

            if (!TryFindChild(current.Children, label, out TrieNode? nextNode))
            {
                break;
            }

            current = nextNode!;
            bool isFinalLabel = dotIndex < 0;

            if (isFinalLabel)
            {
                // Exact match at the full domain has highest specificity.
                if (current.HasExact)
                {
                    result = new DomainMatchResult<T>(
                        current.ExactValue!,
                        DomainMatchKind.Exact,
                        current.ExactPattern!);
                    return true;
                }

                // Suffix match on the queried domain itself beats any shallower ancestor wildcard/suffix.
                if (current.HasSuffix)
                {
                    result = new DomainMatchResult<T>(
                        current.SuffixValue!,
                        DomainMatchKind.Suffix,
                        current.SuffixPattern!);
                    return true;
                }
            }
            else
            {
                // Strict ancestor: Wildcard beats Suffix at the same depth, and deeper anchors beat shallower ones.
                if (current.HasWildcard)
                {
                    bestAncestorMatch = new DomainMatchResult<T>(
                        current.WildcardValue!,
                        DomainMatchKind.Wildcard,
                        current.WildcardPattern!);
                }
                else if (current.HasSuffix)
                {
                    bestAncestorMatch = new DomainMatchResult<T>(
                        current.SuffixValue!,
                        DomainMatchKind.Suffix,
                        current.SuffixPattern!);
                }
            }

            if (dotIndex < 0)
            {
                break;
            }

            end = dotIndex;
        }

        if (bestAncestorMatch is not null)
        {
            result = bestAncestorMatch;
            return true;
        }

        return false;
    }

    internal static bool TryNormalizeDomain(ReadOnlySpan<char> raw, out string normalized)
    {
        normalized = string.Empty;
        ReadOnlySpan<char> span = TrimDomainSpan(raw);
        if (span.IsEmpty || span.Length > 253)
        {
            return false;
        }

        char[] rented = ArrayPool<char>.Shared.Rent(span.Length);
        try
        {
            int pos = 0;
            int start = 0;
            while (start <= span.Length)
            {
                int relativeDot = span[start..].IndexOf('.');
                ReadOnlySpan<char> label = relativeDot < 0
                    ? span[start..]
                    : span.Slice(start, relativeDot);

                if (!IsValidQueryLabel(label))
                {
                    return false;
                }

                if (pos > 0)
                {
                    rented[pos++] = '.';
                }

                for (int i = 0; i < label.Length; i++)
                {
                    rented[pos++] = char.ToLowerInvariant(label[i]);
                }

                if (relativeDot < 0)
                {
                    break;
                }

                start += relativeDot + 1;
            }

            normalized = new string(rented, 0, pos);
            return true;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rented);
        }
    }

    private static ReadOnlySpan<char> TrimDomainSpan(ReadOnlySpan<char> domain)
    {
        ReadOnlySpan<char> span = domain.Trim();
        while (span.Length > 0 && span[^1] == '.')
        {
            span = span[..^1];
        }

        return span;
    }

    private static bool IsValidQueryLabel(ReadOnlySpan<char> label)
    {
        if (label.IsEmpty || label.Length > 63)
        {
            return false;
        }

        for (int i = 0; i < label.Length; i++)
        {
            char c = label[i];
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryFindChild(ChildEntry[] children, ReadOnlySpan<char> label, out TrieNode? node)
    {
        int low = 0;
        int high = children.Length - 1;
        while (low <= high)
        {
            int mid = low + ((high - low) >> 1);
            int cmp = label.CompareTo(children[mid].Label.AsSpan(), StringComparison.OrdinalIgnoreCase);
            if (cmp == 0)
            {
                node = children[mid].Node;
                return true;
            }

            if (cmp < 0)
            {
                high = mid - 1;
            }
            else
            {
                low = mid + 1;
            }
        }

        node = null;
        return false;
    }

    internal readonly struct ChildEntry
    {
        public ChildEntry(string label, TrieNode node)
        {
            Label = label;
            Node = node;
        }

        public string Label { get; }

        public TrieNode Node { get; }
    }

    internal sealed class TrieNode
    {
        public TrieNode(
            ChildEntry[] children,
            bool hasExact,
            T? exactValue,
            string? exactPattern,
            bool hasWildcard,
            T? wildcardValue,
            string? wildcardPattern,
            bool hasSuffix,
            T? suffixValue,
            string? suffixPattern)
        {
            Children = children;
            HasExact = hasExact;
            ExactValue = exactValue;
            ExactPattern = exactPattern;
            HasWildcard = hasWildcard;
            WildcardValue = wildcardValue;
            WildcardPattern = wildcardPattern;
            HasSuffix = hasSuffix;
            SuffixValue = suffixValue;
            SuffixPattern = suffixPattern;
        }

        public ChildEntry[] Children { get; }

        public bool HasExact { get; }

        public T? ExactValue { get; }

        public string? ExactPattern { get; }

        public bool HasWildcard { get; }

        public T? WildcardValue { get; }

        public string? WildcardPattern { get; }

        public bool HasSuffix { get; }

        public T? SuffixValue { get; }

        public string? SuffixPattern { get; }
    }
}

/// <summary>
/// Mutable builder used to construct an immutable <see cref="DomainRadixTrie{T}"/>.
/// </summary>
/// <typeparam name="T">The payload type associated with each rule.</typeparam>
public sealed class DomainRadixTrieBuilder<T>
{
    private readonly MutableNode _root = new();
    private int _ruleCount;

    /// <summary>
    /// Adds a rule pattern, interpreting leading <c>*.</c> as <see cref="DomainMatchKind.Wildcard"/>
    /// and bare domain names as <see cref="DomainMatchKind.Suffix"/> unless <paramref name="defaultKind"/> overrides.
    /// </summary>
    /// <param name="pattern">The domain or wildcard pattern.</param>
    /// <param name="value">The rule payload.</param>
    /// <param name="defaultKind">The match kind when <paramref name="pattern"/> does not start with <c>*.</c>.</param>
    /// <returns><c>true</c> if the pattern was valid and added; otherwise <c>false</c>.</returns>
    public bool TryAddPattern(string pattern, T value, DomainMatchKind defaultKind = DomainMatchKind.Suffix)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        ReadOnlySpan<char> span = pattern.AsSpan().Trim();
        if (span.StartsWith("*.", StringComparison.Ordinal))
        {
            return TryAdd(span[2..], DomainMatchKind.Wildcard, value);
        }

        return TryAdd(span, defaultKind, value);
    }

    /// <summary>
    /// Adds an exact-match domain rule.
    /// </summary>
    public bool TryAddExact(string domain, T value)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return TryAdd(domain.AsSpan(), DomainMatchKind.Exact, value);
    }

    /// <summary>
    /// Adds a wildcard rule matching subdomains of <paramref name="anchorDomain"/> (<c>*.anchorDomain</c>).
    /// </summary>
    public bool TryAddWildcard(string anchorDomain, T value)
    {
        ArgumentNullException.ThrowIfNull(anchorDomain);
        ReadOnlySpan<char> span = anchorDomain.AsSpan().Trim();
        if (span.StartsWith("*.", StringComparison.Ordinal))
        {
            span = span[2..];
        }

        return TryAdd(span, DomainMatchKind.Wildcard, value);
    }

    /// <summary>
    /// Adds a suffix-inheritance rule matching <paramref name="anchorDomain"/> and all of its subdomains.
    /// </summary>
    public bool TryAddSuffix(string anchorDomain, T value)
    {
        ArgumentNullException.ThrowIfNull(anchorDomain);
        return TryAdd(anchorDomain.AsSpan(), DomainMatchKind.Suffix, value);
    }

    /// <summary>
    /// Freezes all added rules into an immutable, thread-safe <see cref="DomainRadixTrie{T}"/>.
    /// </summary>
    public DomainRadixTrie<T> Build()
    {
        DomainRadixTrie<T>.TrieNode frozenRoot = Freeze(_root);
        return new DomainRadixTrie<T>(frozenRoot, _ruleCount);
    }

    private bool TryAdd(ReadOnlySpan<char> domainSpan, DomainMatchKind matchKind, T value)
    {
        if (!DomainRadixTrie<T>.TryNormalizeDomain(domainSpan, out string normalized))
        {
            return false;
        }

        MutableNode current = _root;
        ReadOnlySpan<char> normSpan = normalized.AsSpan();
        int end = normSpan.Length;
        while (end > 0)
        {
            int dotIndex = normSpan[..end].LastIndexOf('.');
            string label = normSpan[(dotIndex + 1)..end].ToString();

            if (!current.Children.TryGetValue(label, out MutableNode? child))
            {
                child = new MutableNode();
                current.Children[label] = child;
            }

            current = child;
            if (dotIndex <= 0)
            {
                break;
            }

            end = dotIndex;
        }

        switch (matchKind)
        {
            case DomainMatchKind.Exact:
                if (!current.HasExact)
                {
                    _ruleCount++;
                }

                current.HasExact = true;
                current.ExactValue = value;
                current.ExactPattern = normalized;
                break;

            case DomainMatchKind.Wildcard:
                if (!current.HasWildcard)
                {
                    _ruleCount++;
                }

                current.HasWildcard = true;
                current.WildcardValue = value;
                current.WildcardPattern = string.Concat("*.", normalized);
                break;

            case DomainMatchKind.Suffix:
                if (!current.HasSuffix)
                {
                    _ruleCount++;
                }

                current.HasSuffix = true;
                current.SuffixValue = value;
                current.SuffixPattern = normalized;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(matchKind));
        }

        return true;
    }

    private static DomainRadixTrie<T>.TrieNode Freeze(MutableNode node)
    {
        DomainRadixTrie<T>.ChildEntry[] entries;
        if (node.Children.Count == 0)
        {
            entries = [];
        }
        else
        {
            entries = new DomainRadixTrie<T>.ChildEntry[node.Children.Count];
            int idx = 0;
            foreach (KeyValuePair<string, MutableNode> kvp in node.Children)
            {
                entries[idx++] = new DomainRadixTrie<T>.ChildEntry(kvp.Key, Freeze(kvp.Value));
            }

            Array.Sort(
                entries,
                static (left, right) => string.Compare(left.Label, right.Label, StringComparison.OrdinalIgnoreCase));
        }

        return new DomainRadixTrie<T>.TrieNode(
            entries,
            node.HasExact,
            node.ExactValue,
            node.ExactPattern,
            node.HasWildcard,
            node.WildcardValue,
            node.WildcardPattern,
            node.HasSuffix,
            node.SuffixValue,
            node.SuffixPattern);
    }

    private sealed class MutableNode
    {
        public Dictionary<string, MutableNode> Children { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool HasExact { get; set; }

        public T? ExactValue { get; set; }

        public string? ExactPattern { get; set; }

        public bool HasWildcard { get; set; }

        public T? WildcardValue { get; set; }

        public string? WildcardPattern { get; set; }

        public bool HasSuffix { get; set; }

        public T? SuffixValue { get; set; }

        public string? SuffixPattern { get; set; }
    }
}
