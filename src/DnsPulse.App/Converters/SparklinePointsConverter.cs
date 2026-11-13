using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace DnsPulse.App.Converters;

/// <summary>
/// Converts a latency series (<see cref="IReadOnlyList{T}"/> or <see cref="IEnumerable{T}"/> of <see cref="double"/>)
/// into a bounded WPF <see cref="PointCollection"/> for <see cref="System.Windows.Shapes.Polyline"/> sparklines.
/// Implements both <see cref="IValueConverter"/> and <see cref="IMultiValueConverter"/> so live <c>Count</c> updates re-render.
/// </summary>
public sealed class SparklinePointsConverter : IValueConverter, IMultiValueConverter
{
    public double Width { get; set; } = 220;

    public double Height { get; set; } = 44;

    public double Padding { get; set; } = 3;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        (double width, double height) = ResolveBounds(parameter);
        return BuildPoints(value as IEnumerable<double>, width, height, Padding);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }

    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(values);

        IEnumerable<double>? series = values.OfType<IEnumerable<double>>().FirstOrDefault();
        (double width, double height) = ResolveBounds(parameter);
        return BuildPoints(series, width, height, Padding);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
    {
        return [];
    }

    /// <summary>
    /// Computes bounded sparkline points within <c>[padding, width - padding]</c> × <c>[padding, height - padding]</c>.
    /// </summary>
    public static PointCollection BuildPoints(
        IEnumerable<double>? samples,
        double width = 220,
        double height = 44,
        double padding = 3)
    {
        PointCollection points = [];
        if (samples is null || width <= 0 || height <= 0)
        {
            return points;
        }

        double safePadding = Math.Clamp(padding, 0, Math.Min(width, height) / 2.5);
        double plotWidth = Math.Max(1, width - (2 * safePadding));
        double plotHeight = Math.Max(1, height - (2 * safePadding));

        List<double> valid = [];
        foreach (double sample in samples)
        {
            if (!double.IsNaN(sample) && !double.IsInfinity(sample))
            {
                valid.Add(sample);
            }
        }

        if (valid.Count == 0)
        {
            return points;
        }

        if (valid.Count == 1)
        {
            double midY = safePadding + (plotHeight / 2.0);
            points.Add(new System.Windows.Point(safePadding, midY));
            points.Add(new System.Windows.Point(safePadding + plotWidth, midY));
            return points;
        }

        double min = valid.Min();
        double max = valid.Max();
        double range = max - min;

        for (int i = 0; i < valid.Count; i++)
        {
            double x = safePadding + ((double)i / (valid.Count - 1) * plotWidth);
            double y = range < 1e-6
                ? safePadding + (plotHeight / 2.0)
                : safePadding + plotHeight - ((valid[i] - min) / range * plotHeight);

            points.Add(new System.Windows.Point(Math.Round(x, 2), Math.Round(y, 2)));
        }

        return points;
    }

    private (double Width, double Height) ResolveBounds(object? parameter)
    {
        if (parameter is string spec && !string.IsNullOrWhiteSpace(spec))
        {
            string[] parts = spec.Split([',', 'x', 'X'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 2 &&
                double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out double parsedW) &&
                double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out double parsedH) &&
                parsedW > 0 &&
                parsedH > 0)
            {
                return (parsedW, parsedH);
            }
        }

        return (Width, Height);
    }
}
