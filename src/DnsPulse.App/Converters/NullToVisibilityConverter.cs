using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DnsPulse.App.Converters;

/// <summary>
/// Converts null, whitespace strings, or empty collections to <see cref="Visibility.Collapsed"/> (or inverted).
/// </summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool hasValue = value switch
        {
            null => false,
            string text => !string.IsNullOrWhiteSpace(text),
            int count => count > 0,
            ICollection collection => collection.Count > 0,
            _ => true
        };

        bool invertFromParam = parameter is string s && string.Equals(s, "Invert", StringComparison.OrdinalIgnoreCase);
        if (Invert ^ invertFromParam)
        {
            hasValue = !hasValue;
        }

        return hasValue ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }
}
