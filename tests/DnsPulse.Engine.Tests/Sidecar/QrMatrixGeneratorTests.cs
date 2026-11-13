using System.Diagnostics.CodeAnalysis;
using System.Net;
using DnsPulse.Engine.Sidecar;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Sidecar;

[SuppressMessage("Performance", "CA1814:Prefer jagged arrays over multidimensional", Justification = "Tests verify bool[,] matrix API directly.")]
public sealed class QrMatrixGeneratorTests
{
    [Theory]
    [InlineData(1, 21)]
    [InlineData(2, 25)]
    [InlineData(3, 29)]
    [InlineData(4, 33)]
    [InlineData(5, 37)]
    [InlineData(6, 41)]
    public void Generate_Versions1Through6_ProduceExpectedSquareDimensionsAndStructuralPatterns(int version, int expectedSize)
    {
        // 10-byte payload fits Version 1 ECC-M (14B max) so minimumVersion controls the exact version tested.
        bool[,] matrix = QrMatrixGenerator.Generate("http://1.1", QrEccLevel.Medium, minimumVersion: version);

        matrix.GetLength(0).Should().Be(expectedSize);
        matrix.GetLength(1).Should().Be(expectedSize);

        // Verify all 3 7x7 finder patterns
        AssertFinderPattern(matrix, 0, 0);
        AssertFinderPattern(matrix, 0, expectedSize - 7);
        AssertFinderPattern(matrix, expectedSize - 7, 0);

        // Verify white separators around top-left finder
        for (int i = 0; i < 8; i++)
        {
            matrix[7, i].Should().BeFalse();
            matrix[i, 7].Should().BeFalse();
        }

        // Verify timing patterns along row 6 and col 6
        for (int i = 8; i < expectedSize - 8; i++)
        {
            bool expectedDark = (i & 1) == 0;
            matrix[6, i].Should().Be(expectedDark);
            matrix[i, 6].Should().Be(expectedDark);
        }

        // Verify fixed dark module at (size - 8, 8)
        matrix[expectedSize - 8, 8].Should().BeTrue();

        // Verify alignment pattern at (size - 7, size - 7) for Versions 2..6
        if (version >= 2)
        {
            int center = expectedSize - 7;
            for (int dr = -2; dr <= 2; dr++)
            {
                for (int dc = -2; dc <= 2; dc++)
                {
                    bool expectedDark = Math.Max(Math.Abs(dr), Math.Abs(dc)) != 1;
                    matrix[center + dr, center + dc].Should().Be(expectedDark);
                }
            }
        }
    }

    [Theory]
    [InlineData(QrEccLevel.Low)]
    [InlineData(QrEccLevel.Medium)]
    public void Generate_FormatInformationBits_MatchBchAndAreIdenticalInBothCopies(QrEccLevel eccLevel)
    {
        bool[,] matrix = QrMatrixGenerator.Generate("http://192.168.1.50:8080/proxy.pac", eccLevel);
        int size = matrix.GetLength(0);

        int copy1 = ExtractFormatCopy1(matrix);
        int copy2 = ExtractFormatCopy2(matrix, size);

        copy1.Should().Be(copy2);

        List<int> validFormatWords = [];
        for (int mask = 0; mask < 8; mask++)
        {
            validFormatWords.Add(QrMatrixGenerator.ComputeFormatBits(eccLevel, mask));
        }

        validFormatWords.Should().Contain(copy1);
    }

    [Fact]
    public void ComputeFormatBits_KnownIsoTestVector_MatchesSpec()
    {
        // ISO/IEC 18004 Table C.1: ECC=L (01), Mask=0 (000) -> 0x77C4 (111011111000100)
        QrMatrixGenerator.ComputeFormatBits(QrEccLevel.Low, 0).Should().Be(0x77C4);
        // ECC=M (00), Mask=0 (000) -> 0x5412 (101010000010010)
        QrMatrixGenerator.ComputeFormatBits(QrEccLevel.Medium, 0).Should().Be(0x5412);
    }

    [Fact]
    public void LanGatewayDescriptor_Create_FormatsEndpointsAndEncodesPacQr()
    {
        LanGatewayDescriptor descriptor = LanGatewayDescriptor.Create(
            IPAddress.Parse("192.168.50.2"),
            dnsPort: 53,
            pacPort: 8080,
            proxyPort: 10808);

        descriptor.DnsEndpoint.Should().Be("192.168.50.2:53");
        descriptor.PacUrl.Should().Be("http://192.168.50.2:8080/proxy.pac");
        descriptor.ProxyEndpoint.Should().Be("192.168.50.2:10808");
        descriptor.PacQrMatrix.GetLength(0).Should().Be(descriptor.PacQrMatrix.GetLength(1));
        descriptor.PacQrMatrix.GetLength(0).Should().BeGreaterThanOrEqualTo(21);
    }

    private static void AssertFinderPattern(bool[,] matrix, int topRow, int leftCol)
    {
        for (int dr = 0; dr < 7; dr++)
        {
            for (int dc = 0; dc < 7; dc++)
            {
                bool expectedDark = dr is 0 or 6 || dc is 0 or 6 || (dr is >= 2 and <= 4 && dc is >= 2 and <= 4);
                matrix[topRow + dr, leftCol + dc].Should().Be(expectedDark);
            }
        }
    }

    private static int ExtractFormatCopy1(bool[,] matrix)
    {
        int value = 0;
        for (int k = 14; k >= 9; k--)
        {
            value = (value << 1) | (matrix[8, 14 - k] ? 1 : 0);
        }

        value = (value << 1) | (matrix[8, 7] ? 1 : 0);
        value = (value << 1) | (matrix[8, 8] ? 1 : 0);
        value = (value << 1) | (matrix[7, 8] ? 1 : 0);

        for (int k = 5; k >= 0; k--)
        {
            value = (value << 1) | (matrix[k, 8] ? 1 : 0);
        }

        return value;
    }

    private static int ExtractFormatCopy2(bool[,] matrix, int size)
    {
        int value = 0;
        for (int k = 14; k >= 8; k--)
        {
            value = (value << 1) | (matrix[size - 1 - (14 - k), 8] ? 1 : 0);
        }

        for (int k = 7; k >= 0; k--)
        {
            value = (value << 1) | (matrix[8, size - 8 + (7 - k)] ? 1 : 0);
        }

        return value;
    }
}
