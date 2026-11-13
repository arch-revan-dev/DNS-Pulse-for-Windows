using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;

namespace DnsPulse.Core.Cryptography;

/// <summary>
/// Parses <c>SHA256SUMS.txt</c> manifests, computes streaming SHA-256 digests, and verifies detached Ed25519 signatures.
/// </summary>
public static class SignedManifestVerifier
{
    private const int Sha256SizeBytes = 32;
    private const int Sha256HexLength = 64;

    /// <summary>
    /// Parses a GNU <c>SHA256SUMS.txt</c> manifest string into validated entries.
    /// </summary>
    /// <param name="manifestContent">The manifest text content.</param>
    /// <returns>The parsed manifest entries.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="manifestContent"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">Thrown when any line is malformed or a duplicate filename appears.</exception>
    public static ImmutableArray<ManifestEntry> ParseSha256Sums(string manifestContent)
    {
        ArgumentNullException.ThrowIfNull(manifestContent);

        if (!TryParseSha256Sums(manifestContent, out ImmutableArray<ManifestEntry> entries, out string? error))
        {
            throw new FormatException(error);
        }

        return entries;
    }

    private static bool TryParseSha256Sums(
        string manifestContent,
        out ImmutableArray<ManifestEntry> entries,
        out string? error)
    {
        ImmutableArray<ManifestEntry>.Builder builder = ImmutableArray.CreateBuilder<ManifestEntry>();
        HashSet<string> seenFiles = new(StringComparer.Ordinal);

        int lineNumber = 0;
        using StringReader reader = new(manifestContent);
        string? line;

        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (line.Length < Sha256HexLength + 2)
            {
                entries = [];
                error = string.Create(CultureInfo.InvariantCulture, $"Malformed SHA256SUMS entry at line {lineNumber}.");
                return false;
            }

            ReadOnlySpan<char> hexSpan = line.AsSpan(0, Sha256HexLength);
            if (!IsHexString(hexSpan))
            {
                entries = [];
                error = string.Create(CultureInfo.InvariantCulture, $"Invalid SHA-256 hex digest at line {lineNumber}.");
                return false;
            }

            char separator = line[Sha256HexLength];
            if (separator is not (' ' or '\t'))
            {
                entries = [];
                error = string.Create(CultureInfo.InvariantCulture, $"Missing whitespace separator at line {lineNumber}.");
                return false;
            }

            ReadOnlySpan<char> rest = line.AsSpan(Sha256HexLength + 1);
            int fileNameStart = 0;
            while (fileNameStart < rest.Length && rest[fileNameStart] is ' ' or '\t')
            {
                fileNameStart++;
            }

            if (fileNameStart < rest.Length && rest[fileNameStart] == '*')
            {
                fileNameStart++;
            }

            string fileName = rest[fileNameStart..].TrimEnd().ToString();
            if (fileName.Length == 0)
            {
                entries = [];
                error = string.Create(CultureInfo.InvariantCulture, $"Missing filename at line {lineNumber}.");
                return false;
            }

            if (!seenFiles.Add(fileName))
            {
                entries = [];
                error = string.Create(CultureInfo.InvariantCulture, $"Duplicate filename '{fileName}' at line {lineNumber}.");
                return false;
            }

            byte[] hashBytes = Convert.FromHexString(hexSpan);
            builder.Add(new ManifestEntry(fileName, ImmutableArray.Create(hashBytes)));
        }

        entries = builder.ToImmutable();
        error = null;
        return true;
    }

    /// <summary>
    /// Computes the streaming SHA-256 digest of a stream.
    /// </summary>
    /// <param name="content">The input stream.</param>
    /// <returns>The 32-byte SHA-256 hash.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="content"/> is <see langword="null"/>.</exception>
    public static ImmutableArray<byte> ComputeSha256(Stream content)
    {
        ArgumentNullException.ThrowIfNull(content);

        byte[] hash = SHA256.HashData(content);
        return ImmutableArray.Create(hash);
    }

    /// <summary>
    /// Asynchronously computes the streaming SHA-256 digest of a stream.
    /// </summary>
    /// <param name="content">The input stream.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte SHA-256 hash.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="content"/> is <see langword="null"/>.</exception>
    public static async Task<ImmutableArray<byte>> ComputeSha256Async(
        Stream content,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);

        byte[] hash = await SHA256.HashDataAsync(content, cancellationToken).ConfigureAwait(false);
        return ImmutableArray.Create(hash);
    }

    /// <summary>
    /// Computes the streaming SHA-256 digest of <paramref name="content"/> and compares it in constant time.
    /// </summary>
    /// <param name="content">The input stream.</param>
    /// <param name="expectedSha256">The expected 32-byte SHA-256 digest.</param>
    /// <returns><see langword="true"/> if the digest matches; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="content"/> is <see langword="null"/>.</exception>
    public static bool VerifySha256(Stream content, ReadOnlySpan<byte> expectedSha256)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (expectedSha256.Length != Sha256SizeBytes)
        {
            return false;
        }

        Span<byte> actual = stackalloc byte[Sha256SizeBytes];
        SHA256.HashData(content, actual);
        return CryptographicOperations.FixedTimeEquals(actual, expectedSha256);
    }

    /// <summary>
    /// Asynchronously computes the streaming SHA-256 digest of <paramref name="content"/> and compares it in constant time.
    /// </summary>
    /// <param name="content">The input stream.</param>
    /// <param name="expectedSha256">The expected 32-byte SHA-256 digest.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> if the digest matches; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="content"/> is <see langword="null"/>.</exception>
    public static async Task<bool> VerifySha256Async(
        Stream content,
        ReadOnlyMemory<byte> expectedSha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (expectedSha256.Length != Sha256SizeBytes)
        {
            return false;
        }

        byte[] actual = await SHA256.HashDataAsync(content, cancellationToken).ConfigureAwait(false);
        return CryptographicOperations.FixedTimeEquals(actual, expectedSha256.Span);
    }

    /// <summary>
    /// Verifies a <see cref="ManifestEntry"/> checksum against a stream in constant time.
    /// </summary>
    /// <param name="content">The file content stream.</param>
    /// <param name="entry">The manifest entry containing the expected SHA-256 hash.</param>
    /// <returns><see langword="true"/> if the digest matches; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="content"/> or <paramref name="entry"/> is <see langword="null"/>.</exception>
    public static bool VerifyManifestEntry(Stream content, ManifestEntry entry)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(entry);

        ReadOnlySpan<byte> expected = entry.Sha256Hash.IsDefault
            ? ReadOnlySpan<byte>.Empty
            : entry.Sha256Hash.AsSpan();
        return VerifySha256(content, expected);
    }

    /// <summary>
    /// Asynchronously verifies a <see cref="ManifestEntry"/> checksum against a stream in constant time.
    /// </summary>
    /// <param name="content">The file content stream.</param>
    /// <param name="entry">The manifest entry containing the expected SHA-256 hash.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> if the digest matches; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="content"/> or <paramref name="entry"/> is <see langword="null"/>.</exception>
    public static Task<bool> VerifyManifestEntryAsync(
        Stream content,
        ManifestEntry entry,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(entry);

        ReadOnlyMemory<byte> expected = entry.Sha256Hash.IsDefault
            ? ReadOnlyMemory<byte>.Empty
            : entry.Sha256Hash.AsMemory();
        return VerifySha256Async(content, expected, cancellationToken);
    }

    /// <summary>
    /// Verifies a detached Ed25519 signature over raw payload bytes.
    /// </summary>
    /// <param name="payload">The signed payload bytes.</param>
    /// <param name="signature">The 64-byte detached Ed25519 signature.</param>
    /// <param name="publicKey">The 32-byte Ed25519 public key.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise, <see langword="false"/>.</returns>
    public static bool VerifyDetachedSignature(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey)
    {
        return Ed25519Verifier.Verify(publicKey, payload, signature);
    }

    /// <summary>
    /// Verifies a detached Ed25519 signature over a <c>SHA256SUMS.txt</c> manifest and parses its entries.
    /// </summary>
    /// <param name="manifestBytes">The UTF-8 manifest bytes.</param>
    /// <param name="signature">The 64-byte detached Ed25519 signature over <paramref name="manifestBytes"/>.</param>
    /// <param name="publicKey">The 32-byte Ed25519 public key.</param>
    /// <param name="entries">When this method returns <see langword="true"/>, contains the parsed manifest entries.</param>
    /// <returns><see langword="true"/> if both the signature and manifest format are valid; otherwise, <see langword="false"/>.</returns>
    public static bool VerifySignedManifest(
        ReadOnlySpan<byte> manifestBytes,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey,
        out ImmutableArray<ManifestEntry> entries)
    {
        if (!Ed25519Verifier.Verify(publicKey, manifestBytes, signature))
        {
            entries = [];
            return false;
        }

        if (!Utf8.IsValid(manifestBytes))
        {
            entries = [];
            return false;
        }

        string text = Encoding.UTF8.GetString(manifestBytes);
        return TryParseSha256Sums(text, out entries, out _);
    }

    /// <summary>
    /// Verifies both the constant-time SHA-256 digest and the detached Ed25519 signature of an in-memory payload.
    /// </summary>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signature">The 64-byte detached Ed25519 signature.</param>
    /// <param name="publicKey">The 32-byte Ed25519 public key.</param>
    /// <param name="expectedSha256">The expected 32-byte SHA-256 digest.</param>
    /// <returns><see langword="true"/> if both the SHA-256 digest and Ed25519 signature are valid; otherwise, <see langword="false"/>.</returns>
    public static bool VerifySignedPayload(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> expectedSha256)
    {
        if (expectedSha256.Length != Sha256SizeBytes)
        {
            return false;
        }

        Span<byte> actual = stackalloc byte[Sha256SizeBytes];
        SHA256.HashData(payload, actual);

        if (!CryptographicOperations.FixedTimeEquals(actual, expectedSha256))
        {
            return false;
        }

        return Ed25519Verifier.Verify(publicKey, payload, signature);
    }

    private static bool IsHexString(ReadOnlySpan<char> span)
    {
        for (int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F')))
            {
                return false;
            }
        }

        return true;
    }
}
