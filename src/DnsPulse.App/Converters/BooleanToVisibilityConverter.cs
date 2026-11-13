using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DnsPulse.App.Converters;

/// <summary>
/// Converts a <see cref="bool"/> to <see cref="Visibility"/> with optional inversion.
/// </summary>
public sealed class BooleanToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public bool CollapseWhenFalse { get; set; } = true;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool flag = value is bool b && b;
        bool invertFromParam = parameter is string s && string.Equals(s, "Invert", StringComparison.OrdinalIgnoreCase);
        if (Invert ^ invertFromParam)
        {
            flag = !flag;
        }

        if (flag)
        {
            return Visibility.Visible;
        }

        return CollapseWhenFalse ? Visibility.Collapsed : Visibility.Hidden;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not Visibility visibility)
        {
            return false;
        }

        bool result = visibility == Visibility.Visible;
        bool invertFromParam = parameter is string s && string.Equals(s, "Invert", StringComparison.OrdinalIgnoreCase);
        return (Invert ^ invertFromParam) ? !result : result;
    }
}
