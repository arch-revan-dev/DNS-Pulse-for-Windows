using System.Collections.Immutable;

namespace DnsPulse.Core.Cryptography;

/// <summary>
/// Represents a single entry in a <c>SHA256SUMS.txt</c> checksum manifest.
/// </summary>
public sealed record ManifestEntry(string FileName, ImmutableArray<byte> Sha256Hash)
{
    /// <inheritdoc />
    public bool Equals(ManifestEntry? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        ReadOnlySpan<byte> left = Sha256Hash.IsDefault ? ReadOnlySpan<byte>.Empty : Sha256Hash.AsSpan();
        ReadOnlySpan<byte> right = other.Sha256Hash.IsDefault ? ReadOnlySpan<byte>.Empty : other.Sha256Hash.AsSpan();

        return string.Equals(FileName, other.FileName, StringComparison.Ordinal)
            && left.SequenceEqual(right);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(FileName, StringComparer.Ordinal);

        if (!Sha256Hash.IsDefaultOrEmpty)
        {
            foreach (byte b in Sha256Hash)
            {
                hash.Add(b);
            }
        }

        return hash.ToHashCode();
    }
}
