using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace DnsPulse.Core.Routing;

/// <summary>
/// Represents a successful longest-prefix match from <see cref="CidrRadixTrie{T}"/>.
/// </summary>
/// <typeparam name="T">The payload type stored for the matched CIDR prefix.</typeparam>
/// <param name="Value">The stored rule payload.</param>
/// <param name="PrefixLength">The matched CIDR prefix length (<c>0..32</c> for IPv4, <c>0..128</c> for IPv6).</param>
/// <param name="MatchedCidr">Canonical CIDR notation of the matched prefix.</param>
public sealed record CidrMatchResult<T>(
    T Value,
    int PrefixLength,
    string MatchedCidr);

/// <summary>
/// Immutable, lock-free bitwise CIDR prefix trie supporting IPv4 (<c>/0../32</c>) and IPv6 (<c>/0../128</c>)
/// with longest-prefix match semantics.
/// </summary>
/// <typeparam name="T">The payload type associated with each CIDR entry.</typeparam>
public sealed class CidrRadixTrie<T>
{
    private readonly TrieNode? _ipv4Root;
    private readonly TrieNode? _ipv6Root;

    internal CidrRadixTrie(TrieNode? ipv4Root, TrieNode? ipv6Root, int ruleCount)
    {
        _ipv4Root = ipv4Root;
        _ipv6Root = ipv6Root;
        RuleCount = ruleCount;
    }

    /// <summary>
    /// Initializes an empty <see cref="CidrRadixTrie{T}"/>.
    /// </summary>
    public CidrRadixTrie()
    {
        RuleCount = 0;
    }

    /// <summary>
    /// Gets the total number of CIDR entries stored in this trie.
    /// </summary>
    public int RuleCount { get; }

    /// <summary>
    /// Attempts to match an IP address string against the longest matching CIDR prefix.
    /// </summary>
    public bool TryMatch(string ipAddress, out CidrMatchResult<T>? result, bool unwrapIpv4Mapped = false)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        result = null;
        if (!IPAddress.TryParse(ipAddress.AsSpan().Trim(), out IPAddress? parsed))
        {
            return false;
        }

        return TryMatch(parsed, out result, unwrapIpv4Mapped);
    }

    /// <summary>
    /// Attempts to match an <see cref="IPAddress"/> against the longest matching CIDR prefix.
    /// </summary>
    /// <param name="address">The IPv4 or IPv6 address to test.</param>
    /// <param name="result">The longest-prefix match result, if any.</param>
    /// <param name="unwrapIpv4Mapped">
    /// When <c>true</c> and <paramref name="address"/> is an IPv4-mapped IPv6 address (<c>::ffff:a.b.c.d</c>)
    /// that does not match an explicit IPv6 rule, also checks the unwrapped IPv4 address against IPv4 rules.
    /// </param>
    /// <returns><c>true</c> if a CIDR prefix matched; otherwise <c>false</c>.</returns>
    public bool TryMatch(IPAddress address, out CidrMatchResult<T>? result, bool unwrapIpv4Mapped = false)
    {
        ArgumentNullException.ThrowIfNull(address);

        result = null;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> buffer = stackalloc byte[4];
            if (!address.TryWriteBytes(buffer, out int written) || written != 4)
            {
                return false;
            }

            return TryMatchBits(_ipv4Root, buffer, 32, out result);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Span<byte> buffer = stackalloc byte[16];
            if (!address.TryWriteBytes(buffer, out int written) || written != 16)
            {
                return false;
            }

            if (TryMatchBits(_ipv6Root, buffer, 128, out result))
            {
                return true;
            }

            if (unwrapIpv4Mapped && address.IsIPv4MappedToIPv6)
            {
                IPAddress mapped = address.MapToIPv4();
                return TryMatch(mapped, out result, unwrapIpv4Mapped: false);
            }
        }

        return false;
    }

    private static bool TryMatchBits(
        TrieNode? root,
        ReadOnlySpan<byte> bytes,
        int totalBits,
        out CidrMatchResult<T>? result)
    {
        result = null;
        if (root is null)
        {
            return false;
        }

        TrieNode? current = root;
        TrieNode? bestMatch = root.HasValue ? root : null;

        for (int bit = 0; bit < totalBits && current is not null; bit++)
        {
            int byteIndex = bit >> 3;
            int bitOffset = 7 - (bit & 7);
            int bitValue = (bytes[byteIndex] >> bitOffset) & 1;

            current = bitValue == 0 ? current.Zero : current.One;
            if (current is not null && current.HasValue)
            {
                bestMatch = current;
            }
        }

        if (bestMatch is null)
        {
            return false;
        }

        result = new CidrMatchResult<T>(
            bestMatch.Value!,
            bestMatch.PrefixLength,
            bestMatch.CanonicalCidr!);
        return true;
    }

    internal sealed class TrieNode
    {
        public TrieNode? Zero { get; set; }

        public TrieNode? One { get; set; }

        public bool HasValue { get; set; }

        public T? Value { get; set; }

        public int PrefixLength { get; set; }

        public string? CanonicalCidr { get; set; }
    }
}

/// <summary>
/// Mutable builder used to construct an immutable <see cref="CidrRadixTrie{T}"/>.
/// </summary>
/// <typeparam name="T">The payload type associated with each CIDR entry.</typeparam>
public sealed class CidrRadixTrieBuilder<T>
{
    private CidrRadixTrie<T>.TrieNode? _ipv4Root;
    private CidrRadixTrie<T>.TrieNode? _ipv6Root;
    private int _ruleCount;

    /// <summary>
    /// Parses and adds a CIDR string (e.g. <c>10.0.0.0/8</c>, <c>fc00::/7</c>, or a bare IP address).
    /// </summary>
    public bool TryAddCidr(string cidr, T value)
    {
        ArgumentNullException.ThrowIfNull(cidr);

        ReadOnlySpan<char> span = cidr.AsSpan().Trim();
        if (span.IsEmpty)
        {
            return false;
        }

        int slashIndex = span.IndexOf('/');
        IPAddress? address;
        int prefixLength;

        if (slashIndex < 0)
        {
            if (!IPAddress.TryParse(span, out address))
            {
                return false;
            }

            prefixLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        }
        else
        {
            ReadOnlySpan<char> ipPart = span[..slashIndex].Trim();
            ReadOnlySpan<char> prefixPart = span[(slashIndex + 1)..].Trim();

            if (!IPAddress.TryParse(ipPart, out address))
            {
                return false;
            }

            if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out prefixLength))
            {
                return false;
            }
        }

        return TryAdd(address, prefixLength, value);
    }

    /// <summary>
    /// Adds a CIDR prefix defined by <paramref name="network"/> and <paramref name="prefixLength"/>.
    /// Host bits beyond <paramref name="prefixLength"/> are masked off automatically.
    /// </summary>
    public bool TryAdd(IPAddress network, int prefixLength, T value)
    {
        ArgumentNullException.ThrowIfNull(network);

        if (network.AddressFamily == AddressFamily.InterNetwork)
        {
            if (prefixLength is < 0 or > 32)
            {
                return false;
            }

            Span<byte> bytes = stackalloc byte[4];
            if (!network.TryWriteBytes(bytes, out int written) || written != 4)
            {
                return false;
            }

            MaskHostBits(bytes, prefixLength);
            string canonical = string.Create(
                CultureInfo.InvariantCulture,
                $"{new IPAddress(bytes)}/{prefixLength}");

            _ipv4Root ??= new CidrRadixTrie<T>.TrieNode();
            Insert(_ipv4Root, bytes, prefixLength, value, canonical);
            return true;
        }

        if (network.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (prefixLength is < 0 or > 128)
            {
                return false;
            }

            Span<byte> bytes = stackalloc byte[16];
            if (!network.TryWriteBytes(bytes, out int written) || written != 16)
            {
                return false;
            }

            MaskHostBits(bytes, prefixLength);
            string canonical = string.Create(
                CultureInfo.InvariantCulture,
                $"{new IPAddress(bytes)}/{prefixLength}");

            _ipv6Root ??= new CidrRadixTrie<T>.TrieNode();
            Insert(_ipv6Root, bytes, prefixLength, value, canonical);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Freezes all added prefixes into an immutable <see cref="CidrRadixTrie{T}"/>.
    /// </summary>
    public CidrRadixTrie<T> Build()
    {
        return new CidrRadixTrie<T>(_ipv4Root, _ipv6Root, _ruleCount);
    }

    private void Insert(
        CidrRadixTrie<T>.TrieNode root,
        ReadOnlySpan<byte> maskedBytes,
        int prefixLength,
        T value,
        string canonicalCidr)
    {
        CidrRadixTrie<T>.TrieNode current = root;
        for (int bit = 0; bit < prefixLength; bit++)
        {
            int byteIndex = bit >> 3;
            int bitOffset = 7 - (bit & 7);
            int bitValue = (maskedBytes[byteIndex] >> bitOffset) & 1;

            if (bitValue == 0)
            {
                current.Zero ??= new CidrRadixTrie<T>.TrieNode();
                current = current.Zero;
            }
            else
            {
                current.One ??= new CidrRadixTrie<T>.TrieNode();
                current = current.One;
            }
        }

        if (!current.HasValue)
        {
            _ruleCount++;
        }

        current.HasValue = true;
        current.Value = value;
        current.PrefixLength = prefixLength;
        current.CanonicalCidr = canonicalCidr;
    }

    private static void MaskHostBits(Span<byte> bytes, int prefixLength)
    {
        int fullBytes = prefixLength >> 3;
        int remainingBits = prefixLength & 7;

        if (fullBytes < bytes.Length)
        {
            if (remainingBits > 0)
            {
                byte mask = (byte)(0xFF << (8 - remainingBits));
                bytes[fullBytes] &= mask;
                fullBytes++;
            }

            for (int i = fullBytes; i < bytes.Length; i++)
            {
                bytes[i] = 0;
            }
        }
    }
}
