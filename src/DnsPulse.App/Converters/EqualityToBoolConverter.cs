using System.Globalization;
using System.Windows.Data;

namespace DnsPulse.App.Converters;

/// <summary>
/// Compares two values (or a bound value against <c>ConverterParameter</c>) for radio/chip active-state bindings.
/// </summary>
public sealed class EqualityToBoolConverter : IValueConverter, IMultiValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return Equals(value, parameter);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true && parameter is not null ? parameter : System.Windows.Data.Binding.DoNothing;
    }

    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Length < 2)
        {
            return false;
        }

        return Equals(values[0], values[1]);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
    {
        return [];
    }
}
