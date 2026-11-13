using System.Globalization;
using System.Numerics;
using DnsPulse.Core.Cryptography;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Cryptography;

public sealed class Ed25519VerifierTests
{
    // RFC 8032 Section 7.1 Test Vector 1 (empty message)
    private const string Vector1PublicKeyHex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    private const string Vector1SignatureHex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    // RFC 8032 Section 7.1 Test Vector 2 (1-byte message 0x72)
    private const string Vector2PublicKeyHex =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    private const string Vector2MessageHex = "72";

    private const string Vector2SignatureHex =
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    // RFC 8032 Section 7.1 Test Vector 3 (2-byte message 0xaf82)
    private const string Vector3PublicKeyHex =
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

    private const string Vector3MessageHex = "af82";

    private const string Vector3SignatureHex =
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    [Theory]
    [InlineData(Vector1PublicKeyHex, "", Vector1SignatureHex)]
    [InlineData(Vector2PublicKeyHex, Vector2MessageHex, Vector2SignatureHex)]
    [InlineData(Vector3PublicKeyHex, Vector3MessageHex, Vector3SignatureHex)]
    public void Verify_Rfc8032Section71Vectors1To3_ReturnsTrue(
        string publicKeyHex,
        string messageHex,
        string signatureHex)
    {
        byte[] publicKey = Convert.FromHexString(publicKeyHex);
        byte[] message = Convert.FromHexString(messageHex);
        byte[] signature = Convert.FromHexString(signatureHex);

        bool verified = Ed25519Verifier.Verify(publicKey, message, signature);

        verified.Should().BeTrue();
    }

    [Fact]
    public void Verify_TamperedMessage_ReturnsFalse()
    {
        byte[] publicKey = Convert.FromHexString(Vector3PublicKeyHex);
        byte[] message = Convert.FromHexString(Vector3MessageHex);
        byte[] signature = Convert.FromHexString(Vector3SignatureHex);

        message[0] ^= 0x01;

        Ed25519Verifier.Verify(publicKey, message, signature).Should().BeFalse();
    }

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        byte[] wrongPublicKey = Convert.FromHexString(Vector2PublicKeyHex);
        byte[] message = [];
        byte[] signature = Convert.FromHexString(Vector1SignatureHex);

        Ed25519Verifier.Verify(wrongPublicKey, message, signature).Should().BeFalse();
    }

    [Fact]
    public void Verify_TamperedSignatureR_ReturnsFalse()
    {
        byte[] publicKey = Convert.FromHexString(Vector2PublicKeyHex);
        byte[] message = Convert.FromHexString(Vector2MessageHex);
        byte[] signature = Convert.FromHexString(Vector2SignatureHex);

        signature[0] ^= 0x01;

        Ed25519Verifier.Verify(publicKey, message, signature).Should().BeFalse();
    }

    [Fact]
    public void Verify_NonCanonicalScalarSGreaterOrEqualL_ReturnsFalse()
    {
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);
        byte[] signature = Convert.FromHexString(Vector1SignatureHex);

        BigInteger groupOrder =
            (BigInteger.One << 252)
            + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);

        BigInteger originalS = new(signature.AsSpan(32, 32), isUnsigned: true, isBigEndian: false);
        BigInteger malleableS = originalS + groupOrder;

        byte[] malleableSig = signature.ToArray();
        Span<byte> sSpan = malleableSig.AsSpan(32, 32);
        sSpan.Clear();
        malleableS.TryWriteBytes(sSpan, out _, isUnsigned: true, isBigEndian: false).Should().BeTrue();

        Ed25519Verifier.Verify(publicKey, ReadOnlySpan<byte>.Empty, malleableSig).Should().BeFalse();
    }

    [Fact]
    public void Verify_NonCanonicalRWithYGreaterOrEqualP_ReturnsFalse()
    {
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);
        byte[] signature = Convert.FromHexString(Vector1SignatureHex);

        // Set R to 2^255 - 19 (p, which is >= p and therefore non-canonical)
        byte[] badSig = signature.ToArray();
        Array.Fill(badSig, (byte)0xFF, 0, 32);
        badSig[0] = 0xED;
        badSig[31] = 0x7F;

        Ed25519Verifier.Verify(publicKey, ReadOnlySpan<byte>.Empty, badSig).Should().BeFalse();
    }

    [Fact]
    public void Verify_NonCanonicalPublicKeyWithYGreaterOrEqualP_ReturnsFalse()
    {
        byte[] badPublicKey = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        badPublicKey[0] = 0xED;
        badPublicKey[31] = 0x7F;
        byte[] signature = Convert.FromHexString(Vector1SignatureHex);

        Ed25519Verifier.Verify(badPublicKey, ReadOnlySpan<byte>.Empty, signature).Should().BeFalse();
    }

    [Fact]
    public void Verify_IdentitySmallOrderPublicKey_ReturnsFalse()
    {
        // Identity point (0, 1) encoded in little-endian
        byte[] identityKey = new byte[32];
        identityKey[0] = 0x01;

        byte[] forgedSig = new byte[64];
        forgedSig[0] = 0x01; // R = (0, 1), S = 0

        Ed25519Verifier.Verify(identityKey, "test"u8, forgedSig).Should().BeFalse();
    }

    [Fact]
    public void Verify_InvalidKeyOrSignatureLengths_ReturnsFalse()
    {
        byte[] publicKey = Convert.FromHexString(Vector1PublicKeyHex);
        byte[] signature = Convert.FromHexString(Vector1SignatureHex);

        Ed25519Verifier.Verify(publicKey.AsSpan(0, 31), ReadOnlySpan<byte>.Empty, signature).Should().BeFalse();
        Ed25519Verifier.Verify([.. publicKey, 0x00], ReadOnlySpan<byte>.Empty, signature).Should().BeFalse();
        Ed25519Verifier.Verify(publicKey, ReadOnlySpan<byte>.Empty, signature.AsSpan(0, 63)).Should().BeFalse();
        Ed25519Verifier.Verify(publicKey, ReadOnlySpan<byte>.Empty, [.. signature, 0x00]).Should().BeFalse();
    }
}
