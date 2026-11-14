using System.Globalization;
using System.Windows.Data;
using DnsPulse.Core.Models;

namespace DnsPulse.App.Converters;

/// <summary>
/// Maps <see cref="ServerDisplayCategory"/>, <see cref="DnsServerEntry"/>, or <see cref="TrustTier"/>
/// to a localized plain-language category name. Pass <c>ConverterParameter="Short"</c> for compact pill badges.
/// </summary>
public sealed class CategoryToLabelConverter : IValueConverter, IMultiValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool shortLabel = parameter is string mode && string.Equals(mode, "Short", StringComparison.OrdinalIgnoreCase);

        if (value is null)
        {
            return LocalizationSource.Instance["Servers_Category_All"];
        }

        ServerDisplayCategory category = value switch
        {
            ServerDisplayCategory displayCategory => displayCategory,
            DnsServerEntry server => ServerCategoryClassifier.Classify(server),
            TrustTier.Tier1EncryptedTrusted => ServerDisplayCategory.FastEncrypted,
            TrustTier.Tier2VerifiedGeoUnlock => ServerDisplayCategory.AiAndGeoUnlock,
            _ => ServerDisplayCategory.CustomAndDiscovered
        };

        return TrustTierToBadgeBrushConverter.GetCategoryLabel(category, shortLabel);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }

    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(values);
        object? primary = values.Length > 0 ? values[0] : null;
        return Convert(primary, targetType, parameter, culture);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
    {
        return [];
    }
}
