using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace DnsPulse.App.Converters;

/// <summary>
/// Converts a <c>bool[,]</c> QR module matrix into a crisp nearest-neighbor <see cref="WriteableBitmap"/>
/// with standard 4-module quiet zone.
/// </summary>
[SuppressMessage("Performance", "CA1814:Prefer jagged arrays over multidimensional", Justification = "Matches QrMatrixGenerator and LanGatewayDescriptor bool[,] API.")]
public sealed class QrMatrixToImageSourceConverter : IValueConverter
{
    public int PixelsPerModule { get; set; } = 8;

    public int QuietZoneModules { get; set; } = 4;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not bool[,] matrix)
        {
            return null;
        }

        int scale = PixelsPerModule;
        if (parameter is string s && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) && parsed > 0)
        {
            scale = parsed;
        }

        return RenderQrBitmap(matrix, scale, QuietZoneModules);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }

    /// <summary>
    /// Renders a square <c>bool[,]</c> QR matrix into a frozen, crisp <see cref="WriteableBitmap"/>.
    /// </summary>
    public static WriteableBitmap? RenderQrBitmap(bool[,]? matrix, int pixelsPerModule = 8, int quietZoneModules = 4)
    {
        if (matrix is null)
        {
            return null;
        }

        int rows = matrix.GetLength(0);
        int cols = matrix.GetLength(1);
        if (rows <= 0 || cols <= 0)
        {
            return null;
        }

        int safeScale = Math.Clamp(pixelsPerModule, 1, 32);
        int safeQuiet = Math.Clamp(quietZoneModules, 0, 16);

        int totalModulesWidth = cols + (2 * safeQuiet);
        int totalModulesHeight = rows + (2 * safeQuiet);
        int pixelWidth = totalModulesWidth * safeScale;
        int pixelHeight = totalModulesHeight * safeScale;
        int stride = pixelWidth * 4;

        byte[] buffer = new byte[stride * pixelHeight];
        // Initialize entire buffer to opaque white (#FFFFFFFF).
        Array.Fill(buffer, (byte)0xFF);

        for (int r = 0; r < rows; r++)
        {
            for (int c = 0; c < cols; c++)
            {
                if (!matrix[r, c])
                {
                    continue;
                }

                int startY = (r + safeQuiet) * safeScale;
                int startX = (c + safeQuiet) * safeScale;

                for (int dy = 0; dy < safeScale; dy++)
                {
                    int rowOffset = (startY + dy) * stride;
                    for (int dx = 0; dx < safeScale; dx++)
                    {
                        int idx = rowOffset + ((startX + dx) * 4);
                        buffer[idx] = 0x00;     // B
                        buffer[idx + 1] = 0x00; // G
                        buffer[idx + 2] = 0x00; // R
                        buffer[idx + 3] = 0xFF; // A
                    }
                }
            }
        }

        WriteableBitmap bitmap = new(pixelWidth, pixelHeight, 96, 96, PixelFormats.Bgra32, palette: null);
        bitmap.WritePixels(new Int32Rect(0, 0, pixelWidth, pixelHeight), buffer, stride, 0);
        bitmap.Freeze();
        return bitmap;
    }
}
