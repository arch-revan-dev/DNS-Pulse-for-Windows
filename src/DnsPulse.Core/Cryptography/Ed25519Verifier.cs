using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace DnsPulse.Core.Cryptography;

/// <summary>
/// Self-contained managed RFC 8032 Ed25519 signature verifier.
/// </summary>
public static class Ed25519Verifier
{
    /// <summary>The required length of an Ed25519 public key in bytes.</summary>
    public const int PublicKeySizeBytes = 32;

    /// <summary>The required length of an Ed25519 signature in bytes.</summary>
    public const int SignatureSizeBytes = 64;

    private static readonly BigInteger FieldPrime = (BigInteger.One << 255) - 19;

    private static readonly BigInteger GroupOrder =
        (BigInteger.One << 252)
        + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);

    private static readonly BigInteger CurveD =
        Mod(-121665 * BigInteger.ModPow(121666, FieldPrime - 2, FieldPrime));

    private static readonly BigInteger CurveD2 = Mod(2 * CurveD);

    private static readonly BigInteger SqrtMinusOne =
        BigInteger.ModPow(2, (FieldPrime - 1) / 4, FieldPrime);

    private static readonly ExtendedPoint BasePoint = CreateBasePoint();

    /// <summary>
    /// Verifies an Ed25519 signature according to RFC 8032 with strict canonical encoding and curve checks.
    /// </summary>
    /// <param name="publicKey">The 32-byte Ed25519 public key.</param>
    /// <param name="message">The signed message bytes.</param>
    /// <param name="signature">The 64-byte Ed25519 signature (<c>R || S</c>).</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise, <see langword="false"/>.</returns>
    public static bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySizeBytes || signature.Length != SignatureSizeBytes)
        {
            return false;
        }

        if (!TryDecodePoint(publicKey, out ExtendedPoint publicKeyPoint))
        {
            return false;
        }

        if (IsSmallOrder(publicKeyPoint))
        {
            return false;
        }

        ReadOnlySpan<byte> rBytes = signature[..32];
        if (!TryDecodePoint(rBytes, out ExtendedPoint rPoint))
        {
            return false;
        }

        BigInteger s = new(signature[32..], isUnsigned: true, isBigEndian: false);
        if (s >= GroupOrder)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[64];
        using (IncrementalHash sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
        {
            sha512.AppendData(rBytes);
            sha512.AppendData(publicKey);
            sha512.AppendData(message);
            sha512.GetHashAndReset(digest);
        }

        BigInteger k = new BigInteger(digest, isUnsigned: true, isBigEndian: false) % GroupOrder;

        ExtendedPoint negA = Negate(publicKeyPoint);
        ExtendedPoint computedR = DoubleScalarMultiply(s, BasePoint, k, negA);

        return PointsEqual(computedR, rPoint);
    }

    private static ExtendedPoint CreateBasePoint()
    {
        BigInteger by = Mod(4 * BigInteger.ModPow(5, FieldPrime - 2, FieldPrime));
        if (!TryRecoverX(by, 0, out BigInteger bx))
        {
            throw new InvalidOperationException("Failed to initialize Ed25519 base point.");
        }

        return new ExtendedPoint(bx, by, BigInteger.One, Mod(bx * by));
    }

    private static bool TryDecodePoint(ReadOnlySpan<byte> encoded, out ExtendedPoint point)
    {
        if (encoded.Length != PublicKeySizeBytes)
        {
            point = default;
            return false;
        }

        Span<byte> yBytes = stackalloc byte[PublicKeySizeBytes];
        encoded.CopyTo(yBytes);
        int signBit = (yBytes[31] >> 7) & 1;
        yBytes[31] &= 0x7F;

        BigInteger y = new(yBytes, isUnsigned: true, isBigEndian: false);
        if (y >= FieldPrime)
        {
            point = default;
            return false;
        }

        if (!TryRecoverX(y, signBit, out BigInteger x))
        {
            point = default;
            return false;
        }

        BigInteger x2 = Mod(x * x);
        BigInteger y2 = Mod(y * y);
        BigInteger lhs = Mod(y2 - x2);
        BigInteger rhs = Mod(BigInteger.One + Mod(CurveD * Mod(x2 * y2)));
        if (lhs != rhs)
        {
            point = default;
            return false;
        }

        point = new ExtendedPoint(x, y, BigInteger.One, Mod(x * y));
        return true;
    }

    private static bool TryRecoverX(BigInteger y, int signBit, out BigInteger x)
    {
        BigInteger y2 = Mod(y * y);
        BigInteger u = Mod(y2 - BigInteger.One);
        BigInteger v = Mod(CurveD * y2 + BigInteger.One);
        BigInteger v2 = Mod(v * v);
        BigInteger v3 = Mod(v2 * v);
        BigInteger v7 = Mod(Mod(v3 * v3) * v);
        BigInteger uv7 = Mod(u * v7);

        x = Mod(Mod(u * v3) * BigInteger.ModPow(uv7, (FieldPrime - 5) / 8, FieldPrime));
        BigInteger vx2 = Mod(v * Mod(x * x));

        if (vx2 != u)
        {
            if (vx2 == Mod(FieldPrime - u))
            {
                x = Mod(x * SqrtMinusOne);
            }
            else
            {
                x = BigInteger.Zero;
                return false;
            }
        }

        if (x.IsZero && signBit == 1)
        {
            x = BigInteger.Zero;
            return false;
        }

        if (((int)(x & BigInteger.One)) != signBit)
        {
            x = FieldPrime - x;
        }

        return true;
    }

    private static bool IsSmallOrder(ExtendedPoint point)
    {
        ExtendedPoint cleared = Double(Double(Double(point)));
        return cleared.X.IsZero && Mod(cleared.Y - cleared.Z).IsZero;
    }

    private static ExtendedPoint DoubleScalarMultiply(
        BigInteger scalar1,
        ExtendedPoint point1,
        BigInteger scalar2,
        ExtendedPoint point2)
    {
        Span<byte> bytes1 = stackalloc byte[32];
        Span<byte> bytes2 = stackalloc byte[32];
        scalar1.TryWriteBytes(bytes1, out _, isUnsigned: true, isBigEndian: false);
        scalar2.TryWriteBytes(bytes2, out _, isUnsigned: true, isBigEndian: false);

        ExtendedPoint combined = Add(point1, point2);
        ExtendedPoint accumulator = ExtendedPoint.Identity;

        for (int bit = 255; bit >= 0; bit--)
        {
            accumulator = Double(accumulator);
            bool bit1 = ((bytes1[bit >> 3] >> (bit & 7)) & 1) != 0;
            bool bit2 = ((bytes2[bit >> 3] >> (bit & 7)) & 1) != 0;

            if (bit1 && bit2)
            {
                accumulator = Add(accumulator, combined);
            }
            else if (bit1)
            {
                accumulator = Add(accumulator, point1);
            }
            else if (bit2)
            {
                accumulator = Add(accumulator, point2);
            }
        }

        return accumulator;
    }

    private static ExtendedPoint Negate(ExtendedPoint point)
    {
        return new ExtendedPoint(Mod(-point.X), point.Y, point.Z, Mod(-point.T));
    }

    private static ExtendedPoint Add(ExtendedPoint p1, ExtendedPoint p2)
    {
        BigInteger a = Mod((p1.Y - p1.X) * (p2.Y - p2.X));
        BigInteger b = Mod((p1.Y + p1.X) * (p2.Y + p2.X));
        BigInteger c = Mod(Mod(p1.T * CurveD2) * p2.T);
        BigInteger d = Mod(Mod(p1.Z * 2) * p2.Z);
        BigInteger e = Mod(b - a);
        BigInteger f = Mod(d - c);
        BigInteger g = Mod(d + c);
        BigInteger h = Mod(b + a);

        return new ExtendedPoint(
            Mod(e * f),
            Mod(g * h),
            Mod(f * g),
            Mod(e * h));
    }

    private static ExtendedPoint Double(ExtendedPoint p)
    {
        BigInteger a = Mod(p.X * p.X);
        BigInteger b = Mod(p.Y * p.Y);
        BigInteger c = Mod(2 * Mod(p.Z * p.Z));
        BigInteger d = Mod(-a);
        BigInteger xySum = Mod(p.X + p.Y);
        BigInteger e = Mod(Mod(xySum * xySum) - a - b);
        BigInteger g = Mod(d + b);
        BigInteger f = Mod(g - c);
        BigInteger h = Mod(d - b);

        return new ExtendedPoint(
            Mod(e * f),
            Mod(g * h),
            Mod(f * g),
            Mod(e * h));
    }

    private static bool PointsEqual(ExtendedPoint p1, ExtendedPoint p2)
    {
        BigInteger xDiff = Mod((p1.X * p2.Z) - (p2.X * p1.Z));
        BigInteger yDiff = Mod((p1.Y * p2.Z) - (p2.Y * p1.Z));
        return xDiff.IsZero && yDiff.IsZero;
    }

    private static BigInteger Mod(BigInteger value)
    {
        BigInteger remainder = value % FieldPrime;
        return remainder.Sign < 0 ? remainder + FieldPrime : remainder;
    }

    private readonly record struct ExtendedPoint(
        BigInteger X,
        BigInteger Y,
        BigInteger Z,
        BigInteger T)
    {
        public static readonly ExtendedPoint Identity = new(
            BigInteger.Zero,
            BigInteger.One,
            BigInteger.One,
            BigInteger.Zero);
    }
}
