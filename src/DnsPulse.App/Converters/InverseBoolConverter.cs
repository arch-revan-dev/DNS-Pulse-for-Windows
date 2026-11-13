using System.Globalization;
using System.Windows.Data;

namespace DnsPulse.App.Converters;

/// <summary>
/// Negates a boolean value for <c>IsEnabled</c> and toggle bindings.
/// </summary>
public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool flag ? !flag : true;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool flag ? !flag : false;
    }
}
