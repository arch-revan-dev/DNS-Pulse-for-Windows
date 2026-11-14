using System.Globalization;
using System.Windows.Data;

namespace DnsPulse.App.Converters;

/// <summary>
/// Formats nullable latency values (<see cref="double"/> or <see cref="TimeSpan"/>) as crisp millisecond strings,
/// rendering <see langword="null"/>, <see cref="double.NaN"/>, non-finite, or non-positive values as <c>—</c>.
/// </summary>
public sealed class LatencyFormatConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            double ms when !double.IsNaN(ms) && !double.IsInfinity(ms) && ms > 0.0 =>
                string.Create(CultureInfo.InvariantCulture, $"{ms:F1} ms"),
            float ms when !float.IsNaN(ms) && !float.IsInfinity(ms) && ms > 0f =>
                string.Create(CultureInfo.InvariantCulture, $"{ms:F1} ms"),
            TimeSpan ts when ts > TimeSpan.Zero =>
                ts.TotalMilliseconds < 1.0
                    ? "<1 ms"
                    : string.Create(CultureInfo.InvariantCulture, $"{ts.TotalMilliseconds:F0} ms"),
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
