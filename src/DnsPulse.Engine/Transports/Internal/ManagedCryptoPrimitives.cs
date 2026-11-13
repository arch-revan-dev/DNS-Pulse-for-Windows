using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// Pure-managed cryptographic primitives for DNSCrypt v2 (X25519, XSalsa20-Poly1305, XChaCha20-Poly1305)
/// and RFC 9230 Oblivious DoH (HPKE Base DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-GCM).
/// </summary>
internal static class ManagedCryptoPrimitives
{
    public const int KeySize = 32;
    public const int Nonce24Size = 24;
    public const int TagSize = 16;

    // -------------------------------------------------------------------------
    // X25519 (RFC 7748) using TweetNaCl 16-bit limb GF(2^255 - 19) arithmetic
    // -------------------------------------------------------------------------

    private static readonly long[] A24 = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    public static void GenerateX25519KeyPair(out byte[] secretKey, out byte[] publicKey)
    {
        secretKey = RandomNumberGenerator.GetBytes(KeySize);
        secretKey[0] &= 248;
        secretKey[31] &= 127;
        secretKey[31] |= 64;
        publicKey = X25519ScalarMultBase(secretKey);
    }

    public static byte[] X25519ScalarMultBase(ReadOnlySpan<byte> scalar)
    {
        Span<byte> baseU = stackalloc byte[KeySize];
        baseU[0] = 9;
        return X25519ScalarMult(scalar, baseU);
    }

    public static byte[] X25519ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        if (scalar.Length != KeySize)
        {
            throw new ArgumentException("X25519 scalar must be 32 bytes.", nameof(scalar));
        }

        if (uCoordinate.Length != KeySize)
        {
            throw new ArgumentException("X25519 u-coordinate must be 32 bytes.", nameof(uCoordinate));
        }

        Span<byte> z = stackalloc byte[KeySize];
        scalar.CopyTo(z);
        z[0] &= 248;
        z[31] &= 127;
        z[31] |= 64;

        long[] x = new long[16];
        Unpack25519(x, uCoordinate);

        long[] a = new long[16];
        long[] b = new long[16];
        long[] c = new long[16];
        long[] d = new long[16];
        long[] e = new long[16];
        long[] f = new long[16];

        Array.Copy(x, b, 16);
        a[0] = 1;
        c[0] = 0;
        d[0] = 1;

        for (int i = 254; i >= 0; i--)
        {
            int r = (z[i >> 3] >> (i & 7)) & 1;
            Swap25519(a, b, r);
            Swap25519(c, d, r);
            Add25519(e, a, c);
            Sub25519(a, a, c);
            Add25519(c, b, d);
            Sub25519(b, b, d);
            Mul25519(d, e, e);
            Mul25519(f, a, a);
            Mul25519(a, c, a);
            Mul25519(c, b, e);
            Add25519(e, a, c);
            Sub25519(a, a, c);
            Mul25519(b, a, a);
            Sub25519(c, d, f);
            Mul25519(a, c, A24);
            Add25519(a, a, d);
            Mul25519(c, c, a);
            Mul25519(a, d, f);
            Mul25519(d, b, x);
            Mul25519(b, e, e);
            Swap25519(a, b, r);
            Swap25519(c, d, r);
        }

        Inv25519(c, c);
        Mul25519(a, a, c);
        byte[] output = new byte[KeySize];
        Pack25519(output, a);
        return output;
    }

    public static bool IsAllZero(ReadOnlySpan<byte> bytes)
    {
        byte acc = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            acc |= bytes[i];
        }

        return acc == 0;
    }

    private static void Unpack25519(long[] output, ReadOnlySpan<byte> bytes)
    {
        for (int i = 0; i < 16; i++)
        {
            output[i] = bytes[2 * i] + ((long)bytes[(2 * i) + 1] << 8);
        }

        output[15] &= 0x7FFF;
    }

    private static void Pack25519(Span<byte> output, long[] input)
    {
        long[] m = new long[16];
        long[] t = new long[16];
        Array.Copy(input, t, 16);
        Carry25519(t);
        Carry25519(t);
        Carry25519(t);

        for (int j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xFFED;
            for (int i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xFFFF;
            }

            m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
            long b = (m[15] >> 16) & 1;
            m[14] &= 0xFFFF;
            Swap25519(t, m, 1 - (int)b);
        }

        for (int i = 0; i < 16; i++)
        {
            output[2 * i] = (byte)(t[i] & 0xFF);
            output[(2 * i) + 1] = (byte)(t[i] >> 8);
        }
    }

    private static void Carry25519(long[] o)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += (c - 1) + (37 * (c - 1) * (i == 15 ? 1 : 0));
            o[i] -= c << 16;
        }
    }

    private static void Swap25519(long[] p, long[] q, int bit)
    {
        long mask = ~(bit - 1);
        for (int i = 0; i < 16; i++)
        {
            long t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Add25519(long[] o, long[] a, long[] b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] + b[i];
        }
    }

    private static void Sub25519(long[] o, long[] a, long[] b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] - b[i];
        }
    }

    private static void Mul25519(long[] o, long[] a, long[] b)
    {
        long[] t = new long[31];
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 16; j++)
            {
                t[i + j] += a[i] * b[j];
            }
        }

        for (int i = 0; i < 15; i++)
        {
            t[i] += 38 * t[i + 16];
        }

        Array.Copy(t, o, 16);
        Carry25519(o);
        Carry25519(o);
    }

    private static void Inv25519(long[] o, long[] i)
    {
        long[] c = new long[16];
        Array.Copy(i, c, 16);
        for (int a = 253; a >= 0; a--)
        {
            Mul25519(c, c, c);
            if (a != 2 && a != 4)
            {
                Mul25519(c, c, i);
            }
        }

        Array.Copy(c, o, 16);
    }

    // -------------------------------------------------------------------------
    // Salsa20 / HSalsa20 / XSalsa20-Poly1305 (NaCl crypto_box)
    // -------------------------------------------------------------------------

    private static readonly uint[] SigmaConstants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];

    public static byte[] ComputeXSalsa20SharedKey(ReadOnlySpan<byte> clientSecretKey, ReadOnlySpan<byte> serverPublicKey)
    {
        byte[] shared = X25519ScalarMult(clientSecretKey, serverPublicKey);
        if (IsAllZero(shared))
        {
            throw new CryptographicException("X25519 produced an all-zero shared secret.");
        }

        Span<byte> zeros = stackalloc byte[16];
        zeros.Clear();
        return HSalsa20(shared, zeros);
    }

    public static byte[] SealXSalsa20Poly1305(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> plaintext)
    {
        byte[] subkey = HSalsa20(key32, nonce24[..16]);
        Span<byte> salsaNonce = stackalloc byte[16];
        nonce24[16..24].CopyTo(salsaNonce);
        salsaNonce[8..16].Clear();

        Span<byte> firstBlock = stackalloc byte[64];
        Salsa20Core(firstBlock, salsaNonce, subkey);

        ReadOnlySpan<byte> polyKey = firstBlock[..32];
        byte[] result = new byte[TagSize + plaintext.Length];
        Span<byte> ciphertext = result.AsSpan(TagSize);

        int firstPlain = Math.Min(32, plaintext.Length);
        for (int i = 0; i < firstPlain; i++)
        {
            ciphertext[i] = (byte)(plaintext[i] ^ firstBlock[32 + i]);
        }

        if (plaintext.Length > 32)
        {
            Span<byte> block = stackalloc byte[64];
            ulong counter = 1;
            int offset = 32;
            while (offset < plaintext.Length)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(salsaNonce[8..16], counter++);
                Salsa20Core(block, salsaNonce, subkey);
                int count = Math.Min(64, plaintext.Length - offset);
                for (int i = 0; i < count; i++)
                {
                    ciphertext[offset + i] = (byte)(plaintext[offset + i] ^ block[i]);
                }

                offset += count;
            }
        }

        ComputePoly1305Tag(polyKey, ciphertext, result.AsSpan(0, TagSize));
        return result;
    }

    public static byte[] OpenXSalsa20Poly1305(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> macAndCiphertext)
    {
        if (macAndCiphertext.Length < TagSize)
        {
            throw new CryptographicException("XSalsa20-Poly1305 box is shorter than 16-byte MAC.");
        }

        byte[] subkey = HSalsa20(key32, nonce24[..16]);
        Span<byte> salsaNonce = stackalloc byte[16];
        nonce24[16..24].CopyTo(salsaNonce);
        salsaNonce[8..16].Clear();

        Span<byte> firstBlock = stackalloc byte[64];
        Salsa20Core(firstBlock, salsaNonce, subkey);

        ReadOnlySpan<byte> polyKey = firstBlock[..32];
        ReadOnlySpan<byte> expectedTag = macAndCiphertext[..TagSize];
        ReadOnlySpan<byte> ciphertext = macAndCiphertext[TagSize..];

        Span<byte> actualTag = stackalloc byte[TagSize];
        ComputePoly1305Tag(polyKey, ciphertext, actualTag);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, actualTag))
        {
            throw new CryptographicException("DNSCrypt XSalsa20-Poly1305 MAC verification failed.");
        }

        byte[] plaintext = new byte[ciphertext.Length];
        int firstPlain = Math.Min(32, ciphertext.Length);
        for (int i = 0; i < firstPlain; i++)
        {
            plaintext[i] = (byte)(ciphertext[i] ^ firstBlock[32 + i]);
        }

        if (ciphertext.Length > 32)
        {
            Span<byte> block = stackalloc byte[64];
            ulong counter = 1;
            int offset = 32;
            while (offset < ciphertext.Length)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(salsaNonce[8..16], counter++);
                Salsa20Core(block, salsaNonce, subkey);
                int count = Math.Min(64, ciphertext.Length - offset);
                for (int i = 0; i < count; i++)
                {
                    plaintext[offset + i] = (byte)(ciphertext[offset + i] ^ block[i]);
                }

                offset += count;
            }
        }

        return plaintext;
    }

    private static byte[] HSalsa20(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> input16)
    {
        Span<uint> x = stackalloc uint[16];
        x[0] = SigmaConstants[0];
        x[1] = BinaryPrimitives.ReadUInt32LittleEndian(key32[0..4]);
        x[2] = BinaryPrimitives.ReadUInt32LittleEndian(key32[4..8]);
        x[3] = BinaryPrimitives.ReadUInt32LittleEndian(key32[8..12]);
        x[4] = BinaryPrimitives.ReadUInt32LittleEndian(key32[12..16]);
        x[5] = SigmaConstants[1];
        x[6] = BinaryPrimitives.ReadUInt32LittleEndian(input16[0..4]);
        x[7] = BinaryPrimitives.ReadUInt32LittleEndian(input16[4..8]);
        x[8] = BinaryPrimitives.ReadUInt32LittleEndian(input16[8..12]);
        x[9] = BinaryPrimitives.ReadUInt32LittleEndian(input16[12..16]);
        x[10] = SigmaConstants[2];
        x[11] = BinaryPrimitives.ReadUInt32LittleEndian(key32[16..20]);
        x[12] = BinaryPrimitives.ReadUInt32LittleEndian(key32[20..24]);
        x[13] = BinaryPrimitives.ReadUInt32LittleEndian(key32[24..28]);
        x[14] = BinaryPrimitives.ReadUInt32LittleEndian(key32[28..32]);
        x[15] = SigmaConstants[3];

        for (int i = 0; i < 10; i++)
        {
            SalsaQuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
            SalsaQuarterRound(ref x[5], ref x[9], ref x[13], ref x[1]);
            SalsaQuarterRound(ref x[10], ref x[14], ref x[2], ref x[6]);
            SalsaQuarterRound(ref x[15], ref x[3], ref x[7], ref x[11]);

            SalsaQuarterRound(ref x[0], ref x[1], ref x[2], ref x[3]);
            SalsaQuarterRound(ref x[5], ref x[6], ref x[7], ref x[4]);
            SalsaQuarterRound(ref x[10], ref x[11], ref x[8], ref x[9]);
            SalsaQuarterRound(ref x[15], ref x[12], ref x[13], ref x[14]);
        }

        byte[] output = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(0, 4), x[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4, 4), x[5]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(8, 4), x[10]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(12, 4), x[15]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(16, 4), x[6]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(20, 4), x[7]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(24, 4), x[8]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(28, 4), x[9]);
        return output;
    }

    private static void Salsa20Core(Span<byte> output64, ReadOnlySpan<byte> input16, ReadOnlySpan<byte> key32)
    {
        Span<uint> x = stackalloc uint[16];
        Span<uint> initial = stackalloc uint[16];

        initial[0] = SigmaConstants[0];
        initial[1] = BinaryPrimitives.ReadUInt32LittleEndian(key32[0..4]);
        initial[2] = BinaryPrimitives.ReadUInt32LittleEndian(key32[4..8]);
        initial[3] = BinaryPrimitives.ReadUInt32LittleEndian(key32[8..12]);
        initial[4] = BinaryPrimitives.ReadUInt32LittleEndian(key32[12..16]);
        initial[5] = SigmaConstants[1];
        initial[6] = BinaryPrimitives.ReadUInt32LittleEndian(input16[0..4]);
        initial[7] = BinaryPrimitives.ReadUInt32LittleEndian(input16[4..8]);
        initial[8] = BinaryPrimitives.ReadUInt32LittleEndian(input16[8..12]);
        initial[9] = BinaryPrimitives.ReadUInt32LittleEndian(input16[12..16]);
        initial[10] = SigmaConstants[2];
        initial[11] = BinaryPrimitives.ReadUInt32LittleEndian(key32[16..20]);
        initial[12] = BinaryPrimitives.ReadUInt32LittleEndian(key32[20..24]);
        initial[13] = BinaryPrimitives.ReadUInt32LittleEndian(key32[24..28]);
        initial[14] = BinaryPrimitives.ReadUInt32LittleEndian(key32[28..32]);
        initial[15] = SigmaConstants[3];

        initial.CopyTo(x);
        for (int i = 0; i < 10; i++)
        {
            SalsaQuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
            SalsaQuarterRound(ref x[5], ref x[9], ref x[13], ref x[1]);
            SalsaQuarterRound(ref x[10], ref x[14], ref x[2], ref x[6]);
            SalsaQuarterRound(ref x[15], ref x[3], ref x[7], ref x[11]);

            SalsaQuarterRound(ref x[0], ref x[1], ref x[2], ref x[3]);
            SalsaQuarterRound(ref x[5], ref x[6], ref x[7], ref x[4]);
            SalsaQuarterRound(ref x[10], ref x[11], ref x[8], ref x[9]);
            SalsaQuarterRound(ref x[15], ref x[12], ref x[13], ref x[14]);
        }

        for (int i = 0; i < 16; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output64.Slice(i * 4, 4), x[i] + initial[i]);
        }
    }

    private static void SalsaQuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        b ^= RotateLeft(a + d, 7);
        c ^= RotateLeft(b + a, 9);
        d ^= RotateLeft(c + b, 13);
        a ^= RotateLeft(d + c, 18);
    }

    // -------------------------------------------------------------------------
    // HChaCha20 / XChaCha20-Poly1305 (DNSCrypt v2 0x0002: tag prepended)
    // -------------------------------------------------------------------------

    public static byte[] ComputeXChaCha20SharedKey(ReadOnlySpan<byte> clientSecretKey, ReadOnlySpan<byte> serverPublicKey)
    {
        byte[] shared = X25519ScalarMult(clientSecretKey, serverPublicKey);
        if (IsAllZero(shared))
        {
            throw new CryptographicException("X25519 produced an all-zero shared secret.");
        }

        Span<byte> zeros = stackalloc byte[16];
        zeros.Clear();
        return HChaCha20(shared, zeros);
    }

    public static byte[] SealXChaCha20Poly1305(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> plaintext)
    {
        byte[] subkey = HChaCha20(key32, nonce24[..16]);
        Span<byte> nonce12 = stackalloc byte[12];
        nonce12[..4].Clear();
        nonce24[16..24].CopyTo(nonce12[4..12]);

        byte[] result = new byte[TagSize + plaintext.Length];
        Span<byte> tag = result.AsSpan(0, TagSize);
        Span<byte> ciphertext = result.AsSpan(TagSize);

        if (ChaCha20Poly1305.IsSupported)
        {
            using ChaCha20Poly1305 aead = new(subkey);
            aead.Encrypt(nonce12, plaintext, ciphertext, tag);
            return result;
        }

        EncryptChaCha20Poly1305Managed(subkey, nonce12, plaintext, ciphertext, tag);
        return result;
    }

    public static byte[] OpenXChaCha20Poly1305(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> macAndCiphertext)
    {
        if (macAndCiphertext.Length < TagSize)
        {
            throw new CryptographicException("XChaCha20-Poly1305 box is shorter than 16-byte MAC.");
        }

        byte[] subkey = HChaCha20(key32, nonce24[..16]);
        Span<byte> nonce12 = stackalloc byte[12];
        nonce12[..4].Clear();
        nonce24[16..24].CopyTo(nonce12[4..12]);

        ReadOnlySpan<byte> tag = macAndCiphertext[..TagSize];
        ReadOnlySpan<byte> ciphertext = macAndCiphertext[TagSize..];
        byte[] plaintext = new byte[ciphertext.Length];

        if (ChaCha20Poly1305.IsSupported)
        {
            using ChaCha20Poly1305 aead = new(subkey);
            aead.Decrypt(nonce12, ciphertext, tag, plaintext);
            return plaintext;
        }

        DecryptChaCha20Poly1305Managed(subkey, nonce12, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static byte[] HChaCha20(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> nonce16)
    {
        Span<uint> s = stackalloc uint[16];
        s[0] = SigmaConstants[0];
        s[1] = SigmaConstants[1];
        s[2] = SigmaConstants[2];
        s[3] = SigmaConstants[3];
        s[4] = BinaryPrimitives.ReadUInt32LittleEndian(key32[0..4]);
        s[5] = BinaryPrimitives.ReadUInt32LittleEndian(key32[4..8]);
        s[6] = BinaryPrimitives.ReadUInt32LittleEndian(key32[8..12]);
        s[7] = BinaryPrimitives.ReadUInt32LittleEndian(key32[12..16]);
        s[8] = BinaryPrimitives.ReadUInt32LittleEndian(key32[16..20]);
        s[9] = BinaryPrimitives.ReadUInt32LittleEndian(key32[20..24]);
        s[10] = BinaryPrimitives.ReadUInt32LittleEndian(key32[24..28]);
        s[11] = BinaryPrimitives.ReadUInt32LittleEndian(key32[28..32]);
        s[12] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[0..4]);
        s[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[4..8]);
        s[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[8..12]);
        s[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[12..16]);

        for (int i = 0; i < 10; i++)
        {
            ChaChaQuarterRound(ref s[0], ref s[4], ref s[8], ref s[12]);
            ChaChaQuarterRound(ref s[1], ref s[5], ref s[9], ref s[13]);
            ChaChaQuarterRound(ref s[2], ref s[6], ref s[10], ref s[14]);
            ChaChaQuarterRound(ref s[3], ref s[7], ref s[11], ref s[15]);
            ChaChaQuarterRound(ref s[0], ref s[5], ref s[10], ref s[15]);
            ChaChaQuarterRound(ref s[1], ref s[6], ref s[11], ref s[12]);
            ChaChaQuarterRound(ref s[2], ref s[7], ref s[8], ref s[13]);
            ChaChaQuarterRound(ref s[3], ref s[4], ref s[9], ref s[14]);
        }

        byte[] output = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(0, 4), s[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4, 4), s[1]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(8, 4), s[2]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(12, 4), s[3]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(16, 4), s[12]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(20, 4), s[13]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(24, 4), s[14]);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(28, 4), s[15]);
        return output;
    }

    private static void EncryptChaCha20Poly1305Managed(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce12,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        Span<byte> polyKeyBlock = stackalloc byte[64];
        ChaCha20Block(polyKeyBlock, key32, 0, nonce12);

        ChaCha20Xor(key32, 1, nonce12, plaintext, ciphertext);

        Span<byte> macData = BuildIetfAeadMacData(ReadOnlySpan<byte>.Empty, ciphertext);
        ComputePoly1305Tag(polyKeyBlock[..32], macData, tag);
    }

    private static void DecryptChaCha20Poly1305Managed(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce12,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        Span<byte> polyKeyBlock = stackalloc byte[64];
        ChaCha20Block(polyKeyBlock, key32, 0, nonce12);

        Span<byte> macData = BuildIetfAeadMacData(ReadOnlySpan<byte>.Empty, ciphertext);
        Span<byte> expectedTag = stackalloc byte[TagSize];
        ComputePoly1305Tag(polyKeyBlock[..32], macData, expectedTag);
        if (!CryptographicOperations.FixedTimeEquals(tag, expectedTag))
        {
            throw new CryptographicException("DNSCrypt XChaCha20-Poly1305 MAC verification failed.");
        }

        ChaCha20Xor(key32, 1, nonce12, ciphertext, plaintext);
    }

    private static byte[] BuildIetfAeadMacData(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext)
    {
        int aadPad = (16 - (aad.Length % 16)) % 16;
        int ctPad = (16 - (ciphertext.Length % 16)) % 16;
        byte[] buffer = new byte[aad.Length + aadPad + ciphertext.Length + ctPad + 16];
        aad.CopyTo(buffer);
        ciphertext.CopyTo(buffer.AsSpan(aad.Length + aadPad));
        int lenOffset = aad.Length + aadPad + ciphertext.Length + ctPad;
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(lenOffset, 8), (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(lenOffset + 8, 8), (ulong)ciphertext.Length);
        return buffer;
    }

    private static void ChaCha20Xor(
        ReadOnlySpan<byte> key32,
        uint counter,
        ReadOnlySpan<byte> nonce12,
        ReadOnlySpan<byte> input,
        Span<byte> output)
    {
        Span<byte> block = stackalloc byte[64];
        int offset = 0;
        while (offset < input.Length)
        {
            ChaCha20Block(block, key32, counter++, nonce12);
            int count = Math.Min(64, input.Length - offset);
            for (int i = 0; i < count; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ block[i]);
            }

            offset += count;
        }
    }

    private static void ChaCha20Block(Span<byte> output64, ReadOnlySpan<byte> key32, uint counter, ReadOnlySpan<byte> nonce12)
    {
        Span<uint> initial = stackalloc uint[16];
        Span<uint> s = stackalloc uint[16];

        initial[0] = SigmaConstants[0];
        initial[1] = SigmaConstants[1];
        initial[2] = SigmaConstants[2];
        initial[3] = SigmaConstants[3];
        initial[4] = BinaryPrimitives.ReadUInt32LittleEndian(key32[0..4]);
        initial[5] = BinaryPrimitives.ReadUInt32LittleEndian(key32[4..8]);
        initial[6] = BinaryPrimitives.ReadUInt32LittleEndian(key32[8..12]);
        initial[7] = BinaryPrimitives.ReadUInt32LittleEndian(key32[12..16]);
        initial[8] = BinaryPrimitives.ReadUInt32LittleEndian(key32[16..20]);
        initial[9] = BinaryPrimitives.ReadUInt32LittleEndian(key32[20..24]);
        initial[10] = BinaryPrimitives.ReadUInt32LittleEndian(key32[24..28]);
        initial[11] = BinaryPrimitives.ReadUInt32LittleEndian(key32[28..32]);
        initial[12] = counter;
        initial[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12[0..4]);
        initial[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12[4..8]);
        initial[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12[8..12]);

        initial.CopyTo(s);
        for (int i = 0; i < 10; i++)
        {
            ChaChaQuarterRound(ref s[0], ref s[4], ref s[8], ref s[12]);
            ChaChaQuarterRound(ref s[1], ref s[5], ref s[9], ref s[13]);
            ChaChaQuarterRound(ref s[2], ref s[6], ref s[10], ref s[14]);
            ChaChaQuarterRound(ref s[3], ref s[7], ref s[11], ref s[15]);
            ChaChaQuarterRound(ref s[0], ref s[5], ref s[10], ref s[15]);
            ChaChaQuarterRound(ref s[1], ref s[6], ref s[11], ref s[12]);
            ChaChaQuarterRound(ref s[2], ref s[7], ref s[8], ref s[13]);
            ChaChaQuarterRound(ref s[3], ref s[4], ref s[9], ref s[14]);
        }

        for (int i = 0; i < 16; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output64.Slice(i * 4, 4), s[i] + initial[i]);
        }
    }

    private static void ChaChaQuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d = RotateLeft(d ^ a, 16);
        c += d;
        b = RotateLeft(b ^ c, 12);
        a += b;
        d = RotateLeft(d ^ a, 8);
        c += d;
        b = RotateLeft(b ^ c, 7);
    }

    // -------------------------------------------------------------------------
    // Poly1305 (RFC 8439) using 5x26-bit limbs
    // -------------------------------------------------------------------------

    public static void ComputePoly1305Tag(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> message, Span<byte> tag16)
    {
        uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(key32[0..4]) & 0x03FFFFFF;
        uint r1 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[3..7]) >> 2) & 0x03FFFF03;
        uint r2 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[6..10]) >> 4) & 0x03FFC0FF;
        uint r3 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[9..13]) >> 6) & 0x03F03FFF;
        uint r4 = (BinaryPrimitives.ReadUInt32LittleEndian(key32[12..16]) >> 8) & 0x000FFFFF;

        uint s1 = r1 * 5;
        uint s2 = r2 * 5;
        uint s3 = r3 * 5;
        uint s4 = r4 * 5;

        uint h0 = 0;
        uint h1 = 0;
        uint h2 = 0;
        uint h3 = 0;
        uint h4 = 0;

        Span<byte> block = stackalloc byte[17];
        int offset = 0;
        while (offset < message.Length)
        {
            int take = Math.Min(16, message.Length - offset);
            block.Clear();
            message.Slice(offset, take).CopyTo(block);
            block[take] = 1;
            offset += take;

            uint t0 = BinaryPrimitives.ReadUInt32LittleEndian(block[0..4]);
            uint t1 = BinaryPrimitives.ReadUInt32LittleEndian(block[4..8]);
            uint t2 = BinaryPrimitives.ReadUInt32LittleEndian(block[8..12]);
            uint t3 = BinaryPrimitives.ReadUInt32LittleEndian(block[12..16]);
            uint hibit = (uint)block[16] << 24;

            h0 += t0 & 0x03FFFFFF;
            h1 += ((t0 >> 26) | (t1 << 6)) & 0x03FFFFFF;
            h2 += ((t1 >> 20) | (t2 << 12)) & 0x03FFFFFF;
            h3 += ((t2 >> 14) | (t3 << 18)) & 0x03FFFFFF;
            h4 += (t3 >> 8) | hibit;

            ulong d0 = ((ulong)h0 * r0) + ((ulong)h1 * s4) + ((ulong)h2 * s3) + ((ulong)h3 * s2) + ((ulong)h4 * s1);
            ulong d1 = ((ulong)h0 * r1) + ((ulong)h1 * r0) + ((ulong)h2 * s4) + ((ulong)h3 * s3) + ((ulong)h4 * s2);
            ulong d2 = ((ulong)h0 * r2) + ((ulong)h1 * r1) + ((ulong)h2 * r0) + ((ulong)h3 * s4) + ((ulong)h4 * s3);
            ulong d3 = ((ulong)h0 * r3) + ((ulong)h1 * r2) + ((ulong)h2 * r1) + ((ulong)h3 * r0) + ((ulong)h4 * s4);
            ulong d4 = ((ulong)h0 * r4) + ((ulong)h1 * r3) + ((ulong)h2 * r2) + ((ulong)h3 * r1) + ((ulong)h4 * r0);

            ulong c = d0 >> 26;
            h0 = (uint)d0 & 0x03FFFFFF;
            d1 += c;
            c = d1 >> 26;
            h1 = (uint)d1 & 0x03FFFFFF;
            d2 += c;
            c = d2 >> 26;
            h2 = (uint)d2 & 0x03FFFFFF;
            d3 += c;
            c = d3 >> 26;
            h3 = (uint)d3 & 0x03FFFFFF;
            d4 += c;
            c = d4 >> 26;
            h4 = (uint)d4 & 0x03FFFFFF;
            h0 += (uint)c * 5;
            c = h0 >> 26;
            h0 &= 0x03FFFFFF;
            h1 += (uint)c;
        }

        uint carry = h1 >> 26;
        h1 &= 0x03FFFFFF;
        h2 += carry;
        carry = h2 >> 26;
        h2 &= 0x03FFFFFF;
        h3 += carry;
        carry = h3 >> 26;
        h3 &= 0x03FFFFFF;
        h4 += carry;
        carry = h4 >> 26;
        h4 &= 0x03FFFFFF;
        h0 += carry * 5;
        carry = h0 >> 26;
        h0 &= 0x03FFFFFF;
        h1 += carry;

        uint g0 = h0 + 5;
        carry = g0 >> 26;
        g0 &= 0x03FFFFFF;
        uint g1 = h1 + carry;
        carry = g1 >> 26;
        g1 &= 0x03FFFFFF;
        uint g2 = h2 + carry;
        carry = g2 >> 26;
        g2 &= 0x03FFFFFF;
        uint g3 = h3 + carry;
        carry = g3 >> 26;
        g3 &= 0x03FFFFFF;
        uint g4 = h4 + carry - (1U << 26);

        uint mask = (g4 >> 31) - 1;
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        uint notMask = ~mask;
        h0 = (h0 & notMask) | g0;
        h1 = (h1 & notMask) | g1;
        h2 = (h2 & notMask) | g2;
        h3 = (h3 & notMask) | g3;
        h4 = (h4 & notMask) | g4;

        uint f0 = h0 | (h1 << 26);
        uint f1 = (h1 >> 6) | (h2 << 20);
        uint f2 = (h2 >> 12) | (h3 << 14);
        uint f3 = (h3 >> 18) | (h4 << 8);

        ulong acc = (ulong)f0 + BinaryPrimitives.ReadUInt32LittleEndian(key32[16..20]);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[0..4], (uint)acc);
        acc = (acc >> 32) + f1 + BinaryPrimitives.ReadUInt32LittleEndian(key32[20..24]);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[4..8], (uint)acc);
        acc = (acc >> 32) + f2 + BinaryPrimitives.ReadUInt32LittleEndian(key32[24..28]);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[8..12], (uint)acc);
        acc = (acc >> 32) + f3 + BinaryPrimitives.ReadUInt32LittleEndian(key32[28..32]);
        BinaryPrimitives.WriteUInt32LittleEndian(tag16[12..16], (uint)acc);
    }

    // -------------------------------------------------------------------------
    // ISO/IEC 7816-4 padding (DNSCrypt v2)
    // -------------------------------------------------------------------------

    public static byte[] PadIso7816(ReadOnlySpan<byte> data, int minLength, int blockMultiple)
    {
        int rawNeeded = data.Length + 1;
        int targetLength = Math.Max(minLength, ((rawNeeded + blockMultiple - 1) / blockMultiple) * blockMultiple);
        byte[] padded = new byte[targetLength];
        data.CopyTo(padded);
        padded[data.Length] = 0x80;
        return padded;
    }

    public static ReadOnlySpan<byte> UnpadIso7816(ReadOnlySpan<byte> padded)
    {
        int i = padded.Length - 1;
        while (i >= 0 && padded[i] == 0x00)
        {
            i--;
        }

        if (i < 0 || padded[i] != 0x80)
        {
            throw new CryptographicException("Invalid ISO/IEC 7816-4 padding in DNSCrypt packet.");
        }

        return padded[..i];
    }

    // -------------------------------------------------------------------------
    // HPKE RFC 9180 Base Mode: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-GCM
    // -------------------------------------------------------------------------

    public const ushort HpkeKemX25519Sha256 = 0x0020;
    public const ushort HpkeKdfHkdfSha256 = 0x0001;
    public const ushort HpkeAeadAes128Gcm = 0x0001;
    public const ushort HpkeAeadAes256Gcm = 0x0002;

    private static readonly byte[] HpkeVersionPrefix = Encoding.ASCII.GetBytes("HPKE-v1");
    private static readonly byte[] KemSuiteId = BuildKemSuiteId(HpkeKemX25519Sha256);

    public sealed class HpkeBaseContext
    {
        private readonly byte[] _key;
        private readonly byte[] _baseNonce;
        private readonly byte[] _exporterSecret;
        private ulong _sequence;

        internal HpkeBaseContext(byte[] key, byte[] baseNonce, byte[] exporterSecret, ushort aeadId)
        {
            _key = key;
            _baseNonce = baseNonce;
            _exporterSecret = exporterSecret;
            AeadId = aeadId;
        }

        public ushort AeadId { get; }

        public int KeyLength => _key.Length;

        public int NonceLength => _baseNonce.Length;

        public byte[] Seal(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
        {
            Span<byte> nonce = stackalloc byte[12];
            ComputeNonce(nonce);

            byte[] output = new byte[plaintext.Length + TagSize];
            using AesGcm aes = new(_key, TagSize);
            aes.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length, TagSize), aad);
            _sequence++;
            return output;
        }

        public byte[] Open(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextWithTag)
        {
            if (ciphertextWithTag.Length < TagSize)
            {
                throw new CryptographicException("HPKE ciphertext shorter than 16-byte AEAD tag.");
            }

            Span<byte> nonce = stackalloc byte[12];
            ComputeNonce(nonce);

            int ptLen = ciphertextWithTag.Length - TagSize;
            byte[] plaintext = new byte[ptLen];
            using AesGcm aes = new(_key, TagSize);
            aes.Decrypt(nonce, ciphertextWithTag[..ptLen], ciphertextWithTag[ptLen..], plaintext, aad);
            _sequence++;
            return plaintext;
        }

        public byte[] Export(ReadOnlySpan<byte> exporterContext, int length)
        {
            byte[] suiteId = BuildHpkeSuiteId(HpkeKemX25519Sha256, HpkeKdfHkdfSha256, AeadId);
            return LabeledExpand(_exporterSecret, suiteId, "sec", exporterContext, length);
        }

        private void ComputeNonce(Span<byte> destination)
        {
            _baseNonce.CopyTo(destination);
            Span<byte> seqBytes = stackalloc byte[12];
            seqBytes.Clear();
            BinaryPrimitives.WriteUInt64BigEndian(seqBytes[4..12], _sequence);
            for (int i = 0; i < 12; i++)
            {
                destination[i] ^= seqBytes[i];
            }
        }
    }

    public static (byte[] EncapsulatedKey, HpkeBaseContext Context) SetupHpkeBaseSender(
        ReadOnlySpan<byte> recipientPublicKey,
        ushort aeadId,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> ephemeralSecretKeyOverride = default)
    {
        byte[] skE;
        byte[] enc;
        if (!ephemeralSecretKeyOverride.IsEmpty)
        {
            skE = ephemeralSecretKeyOverride.ToArray();
            enc = X25519ScalarMultBase(skE);
        }
        else
        {
            GenerateX25519KeyPair(out skE, out enc);
        }

        byte[] dh = X25519ScalarMult(skE, recipientPublicKey);
        if (IsAllZero(dh))
        {
            throw new CryptographicException("HPKE DHKEM produced an all-zero DH shared secret.");
        }

        byte[] kemContext = new byte[KeySize * 2];
        enc.CopyTo(kemContext.AsSpan(0, KeySize));
        recipientPublicKey.CopyTo(kemContext.AsSpan(KeySize, KeySize));

        byte[] sharedSecret = ExtractAndExpandKem(dh, kemContext);
        HpkeBaseContext ctx = KeyScheduleBase(sharedSecret, aeadId, info);
        return (enc, ctx);
    }

    public static HpkeBaseContext SetupHpkeBaseReceiver(
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> recipientSecretKey,
        ushort aeadId,
        ReadOnlySpan<byte> info)
    {
        byte[] pkR = X25519ScalarMultBase(recipientSecretKey);
        byte[] dh = X25519ScalarMult(recipientSecretKey, encapsulatedKey);
        if (IsAllZero(dh))
        {
            throw new CryptographicException("HPKE DHKEM produced an all-zero DH shared secret.");
        }

        byte[] kemContext = new byte[KeySize * 2];
        encapsulatedKey.CopyTo(kemContext.AsSpan(0, KeySize));
        pkR.CopyTo(kemContext.AsSpan(KeySize, KeySize));

        byte[] sharedSecret = ExtractAndExpandKem(dh, kemContext);
        return KeyScheduleBase(sharedSecret, aeadId, info);
    }

    private static byte[] ExtractAndExpandKem(ReadOnlySpan<byte> dh, ReadOnlySpan<byte> kemContext)
    {
        byte[] eaePrk = LabeledExtract(ReadOnlySpan<byte>.Empty, KemSuiteId, "eae_prk", dh);
        return LabeledExpand(eaePrk, KemSuiteId, "shared_secret", kemContext, 32);
    }

    private static HpkeBaseContext KeyScheduleBase(ReadOnlySpan<byte> sharedSecret, ushort aeadId, ReadOnlySpan<byte> info)
    {
        int keyLength = aeadId switch
        {
            HpkeAeadAes128Gcm => 16,
            HpkeAeadAes256Gcm => 32,
            _ => throw new NotSupportedException($"Unsupported HPKE AEAD ID: 0x{aeadId:X4}.")
        };

        byte[] suiteId = BuildHpkeSuiteId(HpkeKemX25519Sha256, HpkeKdfHkdfSha256, aeadId);
        byte[] pskIdHash = LabeledExtract(ReadOnlySpan<byte>.Empty, suiteId, "psk_id_hash", ReadOnlySpan<byte>.Empty);
        byte[] infoHash = LabeledExtract(ReadOnlySpan<byte>.Empty, suiteId, "info_hash", info);

        byte[] ksContext = new byte[1 + 32 + 32];
        ksContext[0] = 0x00; // Base mode
        pskIdHash.CopyTo(ksContext.AsSpan(1, 32));
        infoHash.CopyTo(ksContext.AsSpan(33, 32));

        byte[] secret = LabeledExtract(ReadOnlySpan<byte>.Empty, suiteId, "secret", sharedSecret);
        byte[] key = LabeledExpand(secret, suiteId, "key", ksContext, keyLength);
        byte[] baseNonce = LabeledExpand(secret, suiteId, "base_nonce", ksContext, 12);
        byte[] exporterSecret = LabeledExpand(secret, suiteId, "exp", ksContext, 32);

        return new HpkeBaseContext(key, baseNonce, exporterSecret, aeadId);
    }

    private static byte[] LabeledExtract(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> suiteId,
        string label,
        ReadOnlySpan<byte> ikm)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] labeledIkm = new byte[HpkeVersionPrefix.Length + suiteId.Length + labelBytes.Length + ikm.Length];
        int offset = 0;
        HpkeVersionPrefix.CopyTo(labeledIkm.AsSpan(offset));
        offset += HpkeVersionPrefix.Length;
        suiteId.CopyTo(labeledIkm.AsSpan(offset));
        offset += suiteId.Length;
        labelBytes.CopyTo(labeledIkm.AsSpan(offset));
        offset += labelBytes.Length;
        ikm.CopyTo(labeledIkm.AsSpan(offset));

        byte[] prk = new byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, labeledIkm, salt, prk);
        return prk;
    }

    private static byte[] LabeledExpand(
        ReadOnlySpan<byte> prk,
        ReadOnlySpan<byte> suiteId,
        string label,
        ReadOnlySpan<byte> info,
        int length)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] labeledInfo = new byte[2 + HpkeVersionPrefix.Length + suiteId.Length + labelBytes.Length + info.Length];
        BinaryPrimitives.WriteUInt16BigEndian(labeledInfo.AsSpan(0, 2), (ushort)length);
        int offset = 2;
        HpkeVersionPrefix.CopyTo(labeledInfo.AsSpan(offset));
        offset += HpkeVersionPrefix.Length;
        suiteId.CopyTo(labeledInfo.AsSpan(offset));
        offset += suiteId.Length;
        labelBytes.CopyTo(labeledInfo.AsSpan(offset));
        offset += labelBytes.Length;
        info.CopyTo(labeledInfo.AsSpan(offset));

        byte[] output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, output, labeledInfo);
        return output;
    }

    private static byte[] BuildKemSuiteId(ushort kemId)
    {
        byte[] suite = new byte[5];
        Encoding.ASCII.GetBytes("KEM").CopyTo(suite.AsSpan(0, 3));
        BinaryPrimitives.WriteUInt16BigEndian(suite.AsSpan(3, 2), kemId);
        return suite;
    }

    private static byte[] BuildHpkeSuiteId(ushort kemId, ushort kdfId, ushort aeadId)
    {
        byte[] suite = new byte[10];
        Encoding.ASCII.GetBytes("HPKE").CopyTo(suite.AsSpan(0, 4));
        BinaryPrimitives.WriteUInt16BigEndian(suite.AsSpan(4, 2), kemId);
        BinaryPrimitives.WriteUInt16BigEndian(suite.AsSpan(6, 2), kdfId);
        BinaryPrimitives.WriteUInt16BigEndian(suite.AsSpan(8, 2), aeadId);
        return suite;
    }

    private static uint RotateLeft(uint value, int shift)
    {
        return (value << shift) | (value >> (32 - shift));
    }
}
