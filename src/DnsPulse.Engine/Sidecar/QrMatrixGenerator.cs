using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace DnsPulse.Engine.Sidecar;

/// <summary>
/// Error correction level supported by <see cref="QrMatrixGenerator"/>.
/// </summary>
public enum QrEccLevel
{
    /// <summary>Low error correction (~7% codeword recovery).</summary>
    Low = 0,

    /// <summary>Medium error correction (~15% codeword recovery).</summary>
    Medium = 1
}

/// <summary>
/// Self-contained, zero-dependency ISO/IEC 18004 Byte-mode QR Code matrix encoder
/// supporting Versions 1–6 (<c>21×21</c> through <c>41×41</c>) at ECC Level L and M.
/// </summary>
[SuppressMessage("Performance", "CA1814:Prefer jagged arrays over multidimensional", Justification = "Square QR matrix API returns bool[,] per sidecar contract.")]
public static class QrMatrixGenerator
{
    private const int MinVersion = 1;
    private const int MaxVersion = 6;
    private const int FormatInfoGeneratorPoly = 0x537;
    private const int FormatInfoMask = 0x5412;

    private static readonly byte[] GfExp = BuildGfExpTable();
    private static readonly byte[] GfLog = BuildGfLogTable(GfExp);

    private static readonly EccSpec[] SpecsLow =
    [
        new(Version: 1, TotalDataCodewords: 19, BlockCount: 1, DataPerBlock: 19, EccPerBlock: 7),
        new(Version: 2, TotalDataCodewords: 34, BlockCount: 1, DataPerBlock: 34, EccPerBlock: 10),
        new(Version: 3, TotalDataCodewords: 55, BlockCount: 1, DataPerBlock: 55, EccPerBlock: 15),
        new(Version: 4, TotalDataCodewords: 80, BlockCount: 1, DataPerBlock: 80, EccPerBlock: 20),
        new(Version: 5, TotalDataCodewords: 108, BlockCount: 1, DataPerBlock: 108, EccPerBlock: 26),
        new(Version: 6, TotalDataCodewords: 136, BlockCount: 2, DataPerBlock: 68, EccPerBlock: 18)
    ];

    private static readonly EccSpec[] SpecsMedium =
    [
        new(Version: 1, TotalDataCodewords: 16, BlockCount: 1, DataPerBlock: 16, EccPerBlock: 10),
        new(Version: 2, TotalDataCodewords: 28, BlockCount: 1, DataPerBlock: 28, EccPerBlock: 16),
        new(Version: 3, TotalDataCodewords: 44, BlockCount: 1, DataPerBlock: 44, EccPerBlock: 26),
        new(Version: 4, TotalDataCodewords: 64, BlockCount: 2, DataPerBlock: 32, EccPerBlock: 18),
        new(Version: 5, TotalDataCodewords: 86, BlockCount: 2, DataPerBlock: 43, EccPerBlock: 24),
        new(Version: 6, TotalDataCodewords: 108, BlockCount: 4, DataPerBlock: 27, EccPerBlock: 16)
    ];

    /// <summary>
    /// Encodes <paramref name="payload"/> in QR Byte mode (UTF-8) into a square <see cref="bool"/> matrix
    /// (<c>true</c> = dark module, <c>false</c> = light module), selecting the smallest Version 1–6 that fits.
    /// </summary>
    public static bool[,] Generate(string payload, QrEccLevel eccLevel = QrEccLevel.Medium, int? minimumVersion = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
        return Generate(payloadBytes, eccLevel, minimumVersion);
    }

    /// <summary>
    /// Encodes raw <paramref name="payloadBytes"/> in QR Byte mode into a square <see cref="bool"/> matrix
    /// (<c>true</c> = dark module, <c>false</c> = light module), selecting the smallest Version 1–6 that fits.
    /// </summary>
    public static bool[,] Generate(ReadOnlySpan<byte> payloadBytes, QrEccLevel eccLevel = QrEccLevel.Medium, int? minimumVersion = null)
    {
        if (minimumVersion is < MinVersion or > MaxVersion)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumVersion), minimumVersion, "QR version must be between 1 and 6.");
        }

        EccSpec spec = SelectSpec(payloadBytes.Length, eccLevel, minimumVersion ?? MinVersion);
        byte[] dataCodewords = EncodeByteModeData(payloadBytes, spec.TotalDataCodewords);
        byte[] interleavedCodewords = BuildErrorCorrectionAndInterleave(dataCodewords, spec);

        int size = GetDimension(spec.Version);
        bool[,] baseMatrix = new bool[size, size];
        bool[,] isFunction = new bool[size, size];

        DrawFunctionPatterns(baseMatrix, isFunction, spec.Version, size);
        DrawCodewords(baseMatrix, isFunction, interleavedCodewords, size);

        int eccFormatBits = eccLevel == QrEccLevel.Low ? 0b01 : 0b00;
        int lowestPenalty = int.MaxValue;
        bool[,]? bestMatrix = null;

        for (int mask = 0; mask < 8; mask++)
        {
            bool[,] candidate = (bool[,])baseMatrix.Clone();
            ApplyMask(candidate, isFunction, mask, size);
            DrawFormatBits(candidate, eccFormatBits, mask, size);

            int penalty = ComputePenaltyScore(candidate, size);
            if (penalty < lowestPenalty)
            {
                lowestPenalty = penalty;
                bestMatrix = candidate;
            }
        }

        return bestMatrix!;
    }

    /// <summary>
    /// Returns the square matrix width/height (<c>21 + 4 * (version - 1)</c>) for QR Version 1–6.
    /// </summary>
    public static int GetDimension(int version)
    {
        if (version is < MinVersion or > MaxVersion)
        {
            throw new ArgumentOutOfRangeException(nameof(version), version, "QR version must be between 1 and 6.");
        }

        return 21 + (4 * (version - 1));
    }

    /// <summary>
    /// Computes the 15-bit masked BCH(15,5) format information word for the given ECC level and mask pattern (0–7).
    /// </summary>
    public static int ComputeFormatBits(QrEccLevel eccLevel, int maskPattern)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maskPattern);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maskPattern, 7);

        int eccBits = eccLevel == QrEccLevel.Low ? 0b01 : 0b00;
        int data = (eccBits << 3) | maskPattern;
        int remainder = data << 10;

        while (GetBitLength(remainder) >= 11)
        {
            remainder ^= FormatInfoGeneratorPoly << (GetBitLength(remainder) - 11);
        }

        return ((data << 10) | remainder) ^ FormatInfoMask;
    }

    private static EccSpec SelectSpec(int payloadLength, QrEccLevel eccLevel, int minVersion)
    {
        EccSpec[] table = eccLevel switch
        {
            QrEccLevel.Low => SpecsLow,
            QrEccLevel.Medium => SpecsMedium,
            _ => throw new ArgumentOutOfRangeException(nameof(eccLevel), eccLevel, "Supported ECC levels are Low and Medium.")
        };

        // Byte mode header for V1..V6 is 4 mode bits + 8 character count bits = 12 bits.
        int requiredBits = 12 + (payloadLength * 8);
        for (int i = minVersion - 1; i < table.Length; i++)
        {
            if (requiredBits <= table[i].TotalDataCodewords * 8)
            {
                return table[i];
            }
        }

        throw new ArgumentException(
            $"Payload of {payloadLength} bytes exceeds QR Version {MaxVersion} ({eccLevel}) capacity.",
            nameof(payloadLength));
    }

    private static byte[] EncodeByteModeData(ReadOnlySpan<byte> payloadBytes, int totalDataCodewords)
    {
        int totalBits = totalDataCodewords * 8;
        bool[] bits = new bool[totalBits];
        int bitPos = 0;

        // Mode indicator: Byte mode = 0100
        AppendBits(bits, ref bitPos, 0b0100, 4);
        // Character count indicator (8 bits for V1..V9)
        AppendBits(bits, ref bitPos, payloadBytes.Length, 8);

        for (int i = 0; i < payloadBytes.Length; i++)
        {
            AppendBits(bits, ref bitPos, payloadBytes[i], 8);
        }

        // Terminator (up to 4 zero bits)
        int terminatorBits = Math.Min(4, totalBits - bitPos);
        bitPos += terminatorBits;

        // Pad to byte boundary
        int remainderInByte = bitPos & 7;
        if (remainderInByte != 0)
        {
            bitPos += 8 - remainderInByte;
        }

        byte[] codewords = new byte[totalDataCodewords];
        int populatedBytes = bitPos / 8;
        for (int b = 0; b < populatedBytes; b++)
        {
            int val = 0;
            for (int bit = 0; bit < 8; bit++)
            {
                if (bits[(b * 8) + bit])
                {
                    val |= 1 << (7 - bit);
                }
            }

            codewords[b] = (byte)val;
        }

        // Pad remaining data codewords alternating 0xEC and 0x11
        for (int b = populatedBytes; b < totalDataCodewords; b++)
        {
            codewords[b] = ((b - populatedBytes) & 1) == 0 ? (byte)0xEC : (byte)0x11;
        }

        return codewords;
    }

    private static void AppendBits(bool[] buffer, ref int bitPos, int value, int bitCount)
    {
        for (int i = bitCount - 1; i >= 0; i--)
        {
            buffer[bitPos++] = ((value >> i) & 1) != 0;
        }
    }

    private static byte[] BuildErrorCorrectionAndInterleave(byte[] dataCodewords, EccSpec spec)
    {
        byte[] generator = BuildReedSolomonGenerator(spec.EccPerBlock);
        byte[][] dataBlocks = new byte[spec.BlockCount][];
        byte[][] eccBlocks = new byte[spec.BlockCount][];

        int offset = 0;
        for (int b = 0; b < spec.BlockCount; b++)
        {
            byte[] blockData = new byte[spec.DataPerBlock];
            Array.Copy(dataCodewords, offset, blockData, 0, spec.DataPerBlock);
            offset += spec.DataPerBlock;

            dataBlocks[b] = blockData;
            eccBlocks[b] = ComputeReedSolomonRemainder(blockData, generator, spec.EccPerBlock);
        }

        byte[] result = new byte[(spec.BlockCount * spec.DataPerBlock) + (spec.BlockCount * spec.EccPerBlock)];
        int outPos = 0;

        for (int i = 0; i < spec.DataPerBlock; i++)
        {
            for (int b = 0; b < spec.BlockCount; b++)
            {
                result[outPos++] = dataBlocks[b][i];
            }
        }

        for (int i = 0; i < spec.EccPerBlock; i++)
        {
            for (int b = 0; b < spec.BlockCount; b++)
            {
                result[outPos++] = eccBlocks[b][i];
            }
        }

        return result;
    }

    private static byte[] BuildReedSolomonGenerator(int degree)
    {
        byte[] poly = [1];
        for (int i = 0; i < degree; i++)
        {
            byte[] next = new byte[poly.Length + 1];
            byte root = GfExp[i];
            for (int j = 0; j < poly.Length; j++)
            {
                next[j] ^= poly[j];
                next[j + 1] ^= GfMultiply(poly[j], root);
            }

            poly = next;
        }

        return poly;
    }

    private static byte[] ComputeReedSolomonRemainder(byte[] data, byte[] generator, int eccCount)
    {
        byte[] work = new byte[data.Length + eccCount];
        Array.Copy(data, 0, work, 0, data.Length);

        for (int i = 0; i < data.Length; i++)
        {
            byte factor = work[i];
            if (factor == 0)
            {
                continue;
            }

            for (int j = 0; j < generator.Length; j++)
            {
                work[i + j] ^= GfMultiply(generator[j], factor);
            }
        }

        byte[] ecc = new byte[eccCount];
        Array.Copy(work, data.Length, ecc, 0, eccCount);
        return ecc;
    }

    private static byte GfMultiply(byte a, byte b)
    {
        if (a == 0 || b == 0)
        {
            return 0;
        }

        return GfExp[GfLog[a] + GfLog[b]];
    }

    private static byte[] BuildGfExpTable()
    {
        byte[] exp = new byte[512];
        int value = 1;
        for (int i = 0; i < 255; i++)
        {
            exp[i] = (byte)value;
            exp[i + 255] = (byte)value;
            value <<= 1;
            if ((value & 0x100) != 0)
            {
                value ^= 0x11D;
            }
        }

        exp[510] = exp[0];
        exp[511] = exp[1];
        return exp;
    }

    private static byte[] BuildGfLogTable(byte[] exp)
    {
        byte[] log = new byte[256];
        for (int i = 0; i < 255; i++)
        {
            log[exp[i]] = (byte)i;
        }

        return log;
    }

    private static void DrawFunctionPatterns(bool[,] matrix, bool[,] isFunction, int version, int size)
    {
        // Finder patterns + 1-module separators
        DrawFinderPattern(matrix, isFunction, 0, 0, size);
        DrawFinderPattern(matrix, isFunction, 0, size - 7, size);
        DrawFinderPattern(matrix, isFunction, size - 7, 0, size);

        // Alignment pattern (Versions 2..6 have one alignment pattern at (size - 7, size - 7))
        if (version >= 2)
        {
            DrawAlignmentPattern(matrix, isFunction, size - 7, size - 7);
        }

        // Timing patterns along row 6 and col 6
        for (int i = 8; i < size - 8; i++)
        {
            bool dark = (i & 1) == 0;
            SetFunctionModule(matrix, isFunction, 6, i, dark);
            SetFunctionModule(matrix, isFunction, i, 6, dark);
        }

        // Fixed dark module at (4*version + 9, 8) = (size - 8, 8)
        SetFunctionModule(matrix, isFunction, size - 8, 8, dark: true);

        // Reserve format information areas (values written after masking)
        for (int i = 0; i < 9; i++)
        {
            if (i != 6)
            {
                isFunction[8, i] = true;
                isFunction[i, 8] = true;
            }
        }

        for (int i = size - 8; i < size; i++)
        {
            isFunction[8, i] = true;
        }

        for (int i = size - 7; i < size; i++)
        {
            isFunction[i, 8] = true;
        }
    }

    private static void DrawFinderPattern(bool[,] matrix, bool[,] isFunction, int topRow, int leftCol, int size)
    {
        for (int dr = -1; dr <= 7; dr++)
        {
            int r = topRow + dr;
            if (r < 0 || r >= size)
            {
                continue;
            }

            for (int dc = -1; dc <= 7; dc++)
            {
                int c = leftCol + dc;
                if (c < 0 || c >= size)
                {
                    continue;
                }

                bool insideFinder = dr is >= 0 and <= 6 && dc is >= 0 and <= 6;
                bool dark = insideFinder &&
                    (dr is 0 or 6 || dc is 0 or 6 || (dr is >= 2 and <= 4 && dc is >= 2 and <= 4));
                SetFunctionModule(matrix, isFunction, r, c, dark);
            }
        }
    }

    private static void DrawAlignmentPattern(bool[,] matrix, bool[,] isFunction, int centerRow, int centerCol)
    {
        for (int dr = -2; dr <= 2; dr++)
        {
            for (int dc = -2; dc <= 2; dc++)
            {
                int dist = Math.Max(Math.Abs(dr), Math.Abs(dc));
                bool dark = dist != 1;
                SetFunctionModule(matrix, isFunction, centerRow + dr, centerCol + dc, dark);
            }
        }
    }

    private static void SetFunctionModule(bool[,] matrix, bool[,] isFunction, int row, int col, bool dark)
    {
        matrix[row, col] = dark;
        isFunction[row, col] = true;
    }

    private static void DrawCodewords(bool[,] matrix, bool[,] isFunction, byte[] codewords, int size)
    {
        int totalBits = codewords.Length * 8;
        int bitIndex = 0;
        bool goingUp = true;

        for (int right = size - 1; right >= 1; right -= 2)
        {
            if (right == 6)
            {
                right--;
            }

            for (int step = 0; step < size; step++)
            {
                int row = goingUp ? size - 1 - step : step;
                for (int dx = 0; dx < 2; dx++)
                {
                    int col = right - dx;
                    if (isFunction[row, col])
                    {
                        continue;
                    }

                    bool bit = false;
                    if (bitIndex < totalBits)
                    {
                        bit = ((codewords[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1) != 0;
                        bitIndex++;
                    }

                    matrix[row, col] = bit;
                }
            }

            goingUp = !goingUp;
        }
    }

    private static void ApplyMask(bool[,] matrix, bool[,] isFunction, int maskPattern, int size)
    {
        for (int r = 0; r < size; r++)
        {
            for (int c = 0; c < size; c++)
            {
                if (isFunction[r, c])
                {
                    continue;
                }

                bool invert = maskPattern switch
                {
                    0 => ((r + c) & 1) == 0,
                    1 => (r & 1) == 0,
                    2 => c % 3 == 0,
                    3 => (r + c) % 3 == 0,
                    4 => (((r / 2) + (c / 3)) & 1) == 0,
                    5 => ((r * c) % 2) + ((r * c) % 3) == 0,
                    6 => ((((r * c) % 2) + ((r * c) % 3)) & 1) == 0,
                    7 => ((((r + c) % 2) + ((r * c) % 3)) & 1) == 0,
                    _ => false
                };

                if (invert)
                {
                    matrix[r, c] = !matrix[r, c];
                }
            }
        }
    }

    private static void DrawFormatBits(bool[,] matrix, int eccFormatBits, int maskPattern, int size)
    {
        QrEccLevel level = eccFormatBits == 0b01 ? QrEccLevel.Low : QrEccLevel.Medium;
        int bits = ComputeFormatBits(level, maskPattern);

        // Copy 1: around top-left finder
        for (int k = 14; k >= 9; k--)
        {
            matrix[8, 14 - k] = ((bits >> k) & 1) != 0;
        }

        matrix[8, 7] = ((bits >> 8) & 1) != 0;
        matrix[8, 8] = ((bits >> 7) & 1) != 0;
        matrix[7, 8] = ((bits >> 6) & 1) != 0;

        for (int k = 5; k >= 0; k--)
        {
            matrix[k, 8] = ((bits >> k) & 1) != 0;
        }

        // Copy 2: bottom-left col 8 & top-right row 8
        for (int k = 14; k >= 8; k--)
        {
            matrix[size - 1 - (14 - k), 8] = ((bits >> k) & 1) != 0;
        }

        for (int k = 7; k >= 0; k--)
        {
            matrix[8, size - 8 + (7 - k)] = ((bits >> k) & 1) != 0;
        }
    }

    private static int ComputePenaltyScore(bool[,] matrix, int size)
    {
        int penalty = 0;

        // N1: 5+ consecutive modules of same color in rows and columns
        for (int r = 0; r < size; r++)
        {
            int runLen = 1;
            for (int c = 1; c < size; c++)
            {
                if (matrix[r, c] == matrix[r, c - 1])
                {
                    runLen++;
                }
                else
                {
                    if (runLen >= 5)
                    {
                        penalty += 3 + (runLen - 5);
                    }

                    runLen = 1;
                }
            }

            if (runLen >= 5)
            {
                penalty += 3 + (runLen - 5);
            }
        }

        for (int c = 0; c < size; c++)
        {
            int runLen = 1;
            for (int r = 1; r < size; r++)
            {
                if (matrix[r, c] == matrix[r - 1, c])
                {
                    runLen++;
                }
                else
                {
                    if (runLen >= 5)
                    {
                        penalty += 3 + (runLen - 5);
                    }

                    runLen = 1;
                }
            }

            if (runLen >= 5)
            {
                penalty += 3 + (runLen - 5);
            }
        }

        // N2: 2x2 blocks of same color
        for (int r = 0; r < size - 1; r++)
        {
            for (int c = 0; c < size - 1; c++)
            {
                bool color = matrix[r, c];
                if (matrix[r, c + 1] == color && matrix[r + 1, c] == color && matrix[r + 1, c + 1] == color)
                {
                    penalty += 3;
                }
            }
        }

        // N3: 1:1:3:1:1 finder-like patterns with 4 light modules on either side
        for (int r = 0; r < size; r++)
        {
            for (int c = 0; c <= size - 11; c++)
            {
                if (MatchesFinderLikeHorizontal(matrix, r, c))
                {
                    penalty += 40;
                }
            }
        }

        for (int c = 0; c < size; c++)
        {
            for (int r = 0; r <= size - 11; r++)
            {
                if (MatchesFinderLikeVertical(matrix, r, c))
                {
                    penalty += 40;
                }
            }
        }

        // N4: dark module ratio deviation from 50%
        int darkCount = 0;
        for (int r = 0; r < size; r++)
        {
            for (int c = 0; c < size; c++)
            {
                if (matrix[r, c])
                {
                    darkCount++;
                }
            }
        }

        int totalModules = size * size;
        int k = Math.Abs((darkCount * 20) - (totalModules * 10)) / totalModules;
        penalty += k * 10;

        return penalty;
    }

    private static bool MatchesFinderLikeHorizontal(bool[,] matrix, int r, int c)
    {
        bool patternA =
            matrix[r, c] && !matrix[r, c + 1] && matrix[r, c + 2] && matrix[r, c + 3] && matrix[r, c + 4] && !matrix[r, c + 5] && matrix[r, c + 6] &&
            !matrix[r, c + 7] && !matrix[r, c + 8] && !matrix[r, c + 9] && !matrix[r, c + 10];
        bool patternB =
            !matrix[r, c] && !matrix[r, c + 1] && !matrix[r, c + 2] && !matrix[r, c + 3] &&
            matrix[r, c + 4] && !matrix[r, c + 5] && matrix[r, c + 6] && matrix[r, c + 7] && matrix[r, c + 8] && !matrix[r, c + 9] && matrix[r, c + 10];
        return patternA || patternB;
    }

    private static bool MatchesFinderLikeVertical(bool[,] matrix, int r, int c)
    {
        bool patternA =
            matrix[r, c] && !matrix[r + 1, c] && matrix[r + 2, c] && matrix[r + 3, c] && matrix[r + 4, c] && !matrix[r + 5, c] && matrix[r + 6, c] &&
            !matrix[r + 7, c] && !matrix[r + 8, c] && !matrix[r + 9, c] && !matrix[r + 10, c];
        bool patternB =
            !matrix[r, c] && !matrix[r + 1, c] && !matrix[r + 2, c] && !matrix[r + 3, c] &&
            matrix[r + 4, c] && !matrix[r + 5, c] && matrix[r + 6, c] && matrix[r + 7, c] && matrix[r + 8, c] && !matrix[r + 9, c] && matrix[r + 10, c];
        return patternA || patternB;
    }

    private static int GetBitLength(int value)
    {
        int len = 0;
        while (value > 0)
        {
            len++;
            value >>= 1;
        }

        return len;
    }

    private readonly record struct EccSpec(
        int Version,
        int TotalDataCodewords,
        int BlockCount,
        int DataPerBlock,
        int EccPerBlock);
}
