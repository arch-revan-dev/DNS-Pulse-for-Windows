using System.Collections.Immutable;

namespace DnsPulse.Core.Stamps;

/// <summary>
/// Represents a parsed DNSCrypt v2 DNS stamp (<c>sdns://</c>).
/// </summary>
public sealed record DnsStamp
{
    /// <summary>Gets the stamp protocol.</summary>
    public DnsStampProtocol Protocol { get; init; }

    /// <summary>Gets the decoded server property flags.</summary>
    public DnsStampFlags Properties { get; init; }

    /// <summary>Gets the raw 64-bit properties bitmask (including any reserved bits).</summary>
    public ulong RawProperties { get; init; }

    /// <summary>Gets the server IP address (and optional port).</summary>
    public string ServerAddress { get; init; } = string.Empty;

    /// <summary>Gets the TBS certificate SHA-256 hashes (32 bytes each).</summary>
    public ImmutableArray<ImmutableArray<byte>> Hashes { get; init; } = [];

    /// <summary>Gets the DNSCrypt 32-byte public key, or empty if not applicable.</summary>
    public ImmutableArray<byte> PublicKey { get; init; } = [];

    /// <summary>Gets the DNSCrypt provider name.</summary>
    public string ProviderName { get; init; } = string.Empty;

    /// <summary>Gets the TLS/HTTP host name (with optional port).</summary>
    public string HostName { get; init; } = string.Empty;

    /// <summary>Gets the HTTP URI path (for DoH / Oblivious DoH).</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Gets the optional bootstrap IP addresses.</summary>
    public ImmutableArray<string> BootstrapIps { get; init; } = [];

    /// <inheritdoc />
    public bool Equals(DnsStamp? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return Protocol == other.Protocol
            && Properties == other.Properties
            && EffectiveRawProperties() == other.EffectiveRawProperties()
            && string.Equals(ServerAddress, other.ServerAddress, StringComparison.Ordinal)
            && string.Equals(ProviderName, other.ProviderName, StringComparison.Ordinal)
            && string.Equals(HostName, other.HostName, StringComparison.Ordinal)
            && string.Equals(Path, other.Path, StringComparison.Ordinal)
            && BytesEqual(PublicKey, other.PublicKey)
            && HashesEqual(Hashes, other.Hashes)
            && StringsEqual(BootstrapIps, other.BootstrapIps);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Protocol);
        hash.Add(Properties);
        hash.Add(EffectiveRawProperties());
        hash.Add(ServerAddress, StringComparer.Ordinal);
        hash.Add(ProviderName, StringComparer.Ordinal);
        hash.Add(HostName, StringComparer.Ordinal);
        hash.Add(Path, StringComparer.Ordinal);

        if (!PublicKey.IsDefaultOrEmpty)
        {
            foreach (byte b in PublicKey)
            {
                hash.Add(b);
            }
        }

        if (!Hashes.IsDefaultOrEmpty)
        {
            foreach (ImmutableArray<byte> item in Hashes)
            {
                if (!item.IsDefaultOrEmpty)
                {
                    foreach (byte b in item)
                    {
                        hash.Add(b);
                    }
                }
            }
        }

        if (!BootstrapIps.IsDefaultOrEmpty)
        {
            foreach (string ip in BootstrapIps)
            {
                hash.Add(ip, StringComparer.Ordinal);
            }
        }

        return hash.ToHashCode();
    }

    internal ulong EffectiveRawProperties()
    {
        return RawProperties != 0
            ? (RawProperties & ~0x7UL) | (ulong)(uint)Properties
            : (ulong)(uint)Properties;
    }

    private static bool BytesEqual(ImmutableArray<byte> left, ImmutableArray<byte> right)
    {
        ReadOnlySpan<byte> leftSpan = left.IsDefault ? ReadOnlySpan<byte>.Empty : left.AsSpan();
        ReadOnlySpan<byte> rightSpan = right.IsDefault ? ReadOnlySpan<byte>.Empty : right.AsSpan();
        return leftSpan.SequenceEqual(rightSpan);
    }

    private static bool HashesEqual(
        ImmutableArray<ImmutableArray<byte>> left,
        ImmutableArray<ImmutableArray<byte>> right)
    {
        int leftCount = left.IsDefault ? 0 : left.Length;
        int rightCount = right.IsDefault ? 0 : right.Length;
        if (leftCount != rightCount)
        {
            return false;
        }

        for (int i = 0; i < leftCount; i++)
        {
            if (!BytesEqual(left[i], right[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool StringsEqual(ImmutableArray<string> left, ImmutableArray<string> right)
    {
        int leftCount = left.IsDefault ? 0 : left.Length;
        int rightCount = right.IsDefault ? 0 : right.Length;
        if (leftCount != rightCount)
        {
            return false;
        }

        for (int i = 0; i < leftCount; i++)
        {
            if (!string.Equals(left[i], right[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }
}
