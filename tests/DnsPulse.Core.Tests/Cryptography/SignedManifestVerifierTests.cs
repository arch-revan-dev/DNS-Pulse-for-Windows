using System.Collections.Immutable;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using DnsPulse.Core.Cryptography;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Cryptography;

public sealed class SignedManifestVerifierTests
{
    // RFC 8032 Section 7.1 Test Vector 1 keypair
    private const string Vector1SecretKeyHex =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    private const string Vector1PublicKeyHex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    [Fact]
    public void ParseSha256Sums_ValidManifestWithStandardAndBinaryEntries_ParsesAllEntries()
    {
        byte[] payloadA = "DnsPulse.exe payload"u8.ToArray();
        byte[] payloadB = "dns_catalog_1000.tsv payload"u8.ToArray();
        string hexA = Convert.ToHexStringLower(SHA256.HashData(payloadA));
        string hexB = Convert.ToHexString(SHA256.HashData(payloadB));

        string manifest = $"""
            {hexA}  DnsPulse.exe

            {hexB} *assets/dns_catalog_1000.tsv
            """;

        ImmutableArray<ManifestEntry> entries = SignedManifestVerifier.ParseSha256Sums(manifest);

        entries.Should().HaveCount(2);
        entries[0].FileName.Should().Be("DnsPulse.exe");
        entries[0].Sha256Hash.AsSpan().SequenceEqual(SHA256.HashData(payloadA)).Should().BeTrue();
        entries[1].FileName.Should().Be("assets/dns_catalog_1000.tsv");
        entries[1].Sha256Hash.AsSpan().SequenceEqual(SHA256.HashData(payloadB)).Should().BeTrue();
    }

    [Theory]
    [InlineData("not-a-hex-digest  file.bin")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855x file.bin")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  dup.bin\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  dup.bin")]
    public void ParseSha256Sums_MalformedOrDuplicateManifest_ThrowsFormatException(string manifest)
    {
        Action act = () => SignedManifestVerifier.ParseSha256Sums(manifest);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void VerifySha256_LargeStreamSync_MatchesExpectedDigestAndRejectsMismatch()
    {
        byte[] largePayload = new byte[128 * 1024 + 17];
        for (int i = 0; i < largePayload.Length; i++)
        {
            largePayload[i] = (byte)(i * 31 + 7);
        }

        byte[] expectedHash = SHA256.HashData(largePayload);

        using (MemoryStream stream1 = new(largePayload, writable: false))
        {
            SignedManifestVerifier.ComputeSha256(stream1).AsSpan().SequenceEqual(expectedHash).Should().BeTrue();
        }

        using (MemoryStream stream2 = new(largePayload, writable: false))
        {
            SignedManifestVerifier.VerifySha256(stream2, expectedHash).Should().BeTrue();
        }

        byte[] wrongHash = expectedHash.ToArray();
        wrongHash[0] ^= 0x80;

        using (MemoryStream stream4 = new(largePayload, writable: false))
        {
            SignedManifestVerifier.VerifySha256(stream4, wrongHash).Should().BeFalse();
        }
    }

    [Fact]
    public async Task VerifySha256Async_LargeStream_MatchesExpectedDigestAndRejectsMismatch()
    {
        byte[] largePayload = new byte[128 * 1024 + 17];
        for (int i = 0; i < largePayload.Length; i++)
        {
            largePayload[i] = (byte)(i * 31 + 7);
        }

        byte[] expectedHash = SHA256.HashData(largePayload);

        await using (MemoryStream stream1 = new(largePayload, writable: false))
        {
            ImmutableArray<byte> computed = await SignedManifestVerifier.ComputeSha256Async(stream1);
            computed.AsSpan().SequenceEqual(expectedHash).Should().BeTrue();
        }

        await using (MemoryStream stream2 = new(largePayload, writable: false))
        {
            bool asyncOk = await SignedManifestVerifier.VerifySha256Async(stream2, expectedHash);
            asyncOk.Should().BeTrue();
        }

        byte[] wrongHash = expectedHash.ToArray();
        wrongHash[0] ^= 0x80;

        await using (MemoryStream stream3 = new(largePayload, writable: false))
        {
            bool mismatchOk = await SignedManifestVerifier.VerifySha256Async(stream3, wrongHash);
            mismatchOk.Should().BeFalse();
        }
    }

    [Fact]
    public void VerifySignedManifest_AndManifestEntry_SucceedsForValidAndRejectsTampered()
    {
        byte[] catalogPayload = "id\tname\tprovider\n1\tCloudflare\tCloudflare\n"u8.ToArray();
        byte[] catalogHash = SHA256.HashData(catalogPayload);
        string manifestText = string.Create(
            CultureInfo.InvariantCulture,
            $"{Convert.ToHexStringLower(catalogHash)}  dns_catalog_1000.tsv\n");

        byte[] manifestBytes = Encoding.UTF8.GetBytes(manifestText);
        byte[] secretKey = Convert.FromHexString(Vector1SecretKeyHex);
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);

        byte[] manifestSignature = TestEd25519Sign(secretKey, publicKey, manifestBytes);
        byte[] payloadSignature = TestEd25519Sign(secretKey, publicKey, catalogPayload);

        // Sanity check that our test signer produces RFC 8032 Test Vector 1 identically
        byte[] vector1Sig = TestEd25519Sign(secretKey, publicKey, []);
        Convert.ToHexStringLower(vector1Sig).Should().Be(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        bool manifestOk = SignedManifestVerifier.VerifySignedManifest(
            manifestBytes,
            manifestSignature,
            publicKey,
            out ImmutableArray<ManifestEntry> entries);

        manifestOk.Should().BeTrue();
        entries.Should().HaveCount(1);
        entries[0].FileName.Should().Be("dns_catalog_1000.tsv");

        using (MemoryStream payloadStream = new(catalogPayload, writable: false))
        {
            SignedManifestVerifier.VerifyManifestEntry(payloadStream, entries[0]).Should().BeTrue();
        }

        SignedManifestVerifier.VerifySignedPayload(
            catalogPayload,
            payloadSignature,
            publicKey,
            catalogHash).Should().BeTrue();

        // Tamper manifest bytes -> signature fails
        byte[] tamperedManifest = manifestBytes.ToArray();
        tamperedManifest[^2] ^= 0x01;
        SignedManifestVerifier.VerifySignedManifest(
            tamperedManifest,
            manifestSignature,
            publicKey,
            out ImmutableArray<ManifestEntry> rejectedEntries).Should().BeFalse();
        rejectedEntries.Should().BeEmpty();

        // Tamper payload -> VerifySignedPayload fails
        byte[] tamperedPayload = catalogPayload.ToArray();
        tamperedPayload[0] ^= 0x01;
        SignedManifestVerifier.VerifySignedPayload(
            tamperedPayload,
            payloadSignature,
            publicKey,
            catalogHash).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyManifestEntryAsync_ValidStream_ReturnsTrue()
    {
        byte[] catalogPayload = "id\tname\tprovider\n1\tCloudflare\tCloudflare\n"u8.ToArray();
        ManifestEntry entry = new("dns_catalog_1000.tsv", ImmutableArray.Create(SHA256.HashData(catalogPayload)));

        await using MemoryStream asyncStream = new(catalogPayload, writable: false);
        bool entryOk = await SignedManifestVerifier.VerifyManifestEntryAsync(asyncStream, entry);
        entryOk.Should().BeTrue();
    }

    private static byte[] TestEd25519Sign(
        ReadOnlySpan<byte> secretKey,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message)
    {
        BigInteger p = (BigInteger.One << 255) - 19;
        BigInteger l = (BigInteger.One << 252)
            + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
        BigInteger d = Mod(-121665 * BigInteger.ModPow(121666, p - 2, p), p);
        BigInteger sqrtM1 = BigInteger.ModPow(2, (p - 1) / 4, p);

        BigInteger by = Mod(4 * BigInteger.ModPow(5, p - 2, p), p);
        BigInteger bx = RecoverX(by, p, d, sqrtM1);

        byte[] h = SHA512.HashData(secretKey);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;

        BigInteger a = new(h.AsSpan(0, 32), isUnsigned: true, isBigEndian: false);

        byte[] rDigest = new byte[64];
        using (IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
        {
            sha.AppendData(h.AsSpan(32, 32));
            sha.AppendData(message);
            sha.GetHashAndReset(rDigest);
        }

        BigInteger r = new BigInteger(rDigest, isUnsigned: true, isBigEndian: false) % l;
        (BigInteger rx, BigInteger ry) = ScalarMul(r, bx, by, p, d);
        byte[] rEncoded = EncodePoint(rx, ry);

        byte[] kDigest = new byte[64];
        using (IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
        {
            sha.AppendData(rEncoded);
            sha.AppendData(publicKey);
            sha.AppendData(message);
            sha.GetHashAndReset(kDigest);
        }

        BigInteger k = new BigInteger(kDigest, isUnsigned: true, isBigEndian: false) % l;
        BigInteger s = (r + k * a) % l;

        byte[] signature = new byte[64];
        rEncoded.CopyTo(signature, 0);
        s.TryWriteBytes(signature.AsSpan(32, 32), out _, isUnsigned: true, isBigEndian: false);
        return signature;
    }

    private static byte[] EncodePoint(BigInteger x, BigInteger y)
    {
        byte[] encoded = new byte[32];
        y.TryWriteBytes(encoded, out _, isUnsigned: true, isBigEndian: false);
        if ((x & BigInteger.One) == BigInteger.One)
        {
            encoded[31] |= 0x80;
        }

        return encoded;
    }

    private static (BigInteger X, BigInteger Y) ScalarMul(
        BigInteger scalar,
        BigInteger bx,
        BigInteger by,
        BigInteger p,
        BigInteger d)
    {
        BigInteger x = BigInteger.Zero;
        BigInteger y = BigInteger.One;
        BigInteger curX = bx;
        BigInteger curY = by;

        while (!scalar.IsZero)
        {
            if ((scalar & BigInteger.One) == BigInteger.One)
            {
                (x, y) = EdwardsAdd(x, y, curX, curY, p, d);
            }

            (curX, curY) = EdwardsAdd(curX, curY, curX, curY, p, d);
            scalar >>= 1;
        }

        return (x, y);
    }

    private static (BigInteger X, BigInteger Y) EdwardsAdd(
        BigInteger x1,
        BigInteger y1,
        BigInteger x2,
        BigInteger y2,
        BigInteger p,
        BigInteger d)
    {
        BigInteger x1x2 = Mod(x1 * x2, p);
        BigInteger y1y2 = Mod(y1 * y2, p);
        BigInteger dxxyy = Mod(d * Mod(x1x2 * y1y2, p), p);
        BigInteger x3 = Mod(Mod(x1 * y2 + x2 * y1, p) * BigInteger.ModPow(Mod(BigInteger.One + dxxyy, p), p - 2, p), p);
        BigInteger y3 = Mod(Mod(y1y2 + x1x2, p) * BigInteger.ModPow(Mod(BigInteger.One - dxxyy, p), p - 2, p), p);
        return (x3, y3);
    }

    private static BigInteger RecoverX(BigInteger y, BigInteger p, BigInteger d, BigInteger sqrtM1)
    {
        BigInteger y2 = Mod(y * y, p);
        BigInteger u = Mod(y2 - 1, p);
        BigInteger v = Mod(d * y2 + 1, p);
        BigInteger x = Mod(u * BigInteger.ModPow(v, 3, p) * BigInteger.ModPow(Mod(u * BigInteger.ModPow(v, 7, p), p), (p - 5) / 8, p), p);
        if (Mod(v * x * x, p) != u)
        {
            x = Mod(x * sqrtM1, p);
        }

        if ((x & BigInteger.One) == BigInteger.One)
        {
            x = p - x;
        }

        return x;
    }

    private static BigInteger Mod(BigInteger v, BigInteger p)
    {
        BigInteger r = v % p;
        return r.Sign < 0 ? r + p : r;
    }
}
