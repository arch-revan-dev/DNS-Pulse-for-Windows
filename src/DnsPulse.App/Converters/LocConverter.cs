using System.Globalization;
using System.Windows;
using System.Windows.Data;
using DnsPulse.App.Localization;

namespace DnsPulse.App.Converters;

/// <summary>
/// Resolves localized strings from <see cref="LocalizationService"/> or <see cref="LocalizationSource"/>
/// in single-value or multi-value bindings.
/// </summary>
public sealed class LocConverter : IValueConverter, IMultiValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is LocalizationService service && parameter is string paramKey)
        {
            return service[paramKey];
        }

        if (value is string key)
        {
            return parameter is LocalizationService explicitService
                ? explicitService[key]
                : LocalizationSource.Instance[key];
        }

        if (parameter is string fallbackKey)
        {
            return LocalizationSource.Instance[fallbackKey];
        }

        return string.Empty;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }

    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(values);

        LocalizationService? service = values.OfType<LocalizationService>().FirstOrDefault();
        string? key = parameter as string ?? values.OfType<string>().FirstOrDefault(static s => !string.IsNullOrWhiteSpace(s));

        if (string.IsNullOrWhiteSpace(key))
        {
            return DependencyProperty.UnsetValue;
        }

        return service is not null ? service[key] : LocalizationSource.Instance[key];
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
    {
        return [];
    }
}
