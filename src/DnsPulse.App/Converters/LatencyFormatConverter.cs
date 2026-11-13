using System.Globalization;
using System.Windows.Data;

namespace DnsPulse.App.Converters;

/// <summary>
/// Formats nullable latency values (<see cref="double"/> or <see cref="TimeSpan"/>) as crisp millisecond strings.
/// </summary>
public sealed class LatencyFormatConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            double ms when !double.IsNaN(ms) && !double.IsInfinity(ms) =>
                string.Create(CultureInfo.InvariantCulture, $"{ms:F1} ms"),
            TimeSpan ts =>
                string.Create(CultureInfo.InvariantCulture, $"{ts.TotalMilliseconds:F0} ms"),
            int percent when parameter is string p && string.Equals(p, "Percent", StringComparison.OrdinalIgnoreCase) =>
                string.Create(CultureInfo.InvariantCulture, $"{percent}%"),
            _ => "—"
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }
}
