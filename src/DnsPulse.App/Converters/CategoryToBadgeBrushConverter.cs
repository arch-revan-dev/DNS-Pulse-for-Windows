using System.Globalization;
using System.Windows.Data;
using DnsPulse.Core.Models;

namespace DnsPulse.App.Converters;

/// <summary>
/// Maps <see cref="ServerDisplayCategory"/>, <see cref="DnsServerEntry"/>, or <see cref="TrustTier"/>
/// to a high-contrast dark-compatible badge background brush suitable for white text.
/// </summary>
public sealed class CategoryToBadgeBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        ServerDisplayCategory category = value switch
        {
            ServerDisplayCategory displayCategory => displayCategory,
            DnsServerEntry server => ServerCategoryClassifier.Classify(server),
            TrustTier.Tier1EncryptedTrusted => ServerDisplayCategory.FastEncrypted,
            TrustTier.Tier2VerifiedGeoUnlock => ServerDisplayCategory.AiAndGeoUnlock,
            _ => ServerDisplayCategory.CustomAndDiscovered
        };

        return TrustTierToBadgeBrushConverter.GetCategoryBrush(category);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }
}
