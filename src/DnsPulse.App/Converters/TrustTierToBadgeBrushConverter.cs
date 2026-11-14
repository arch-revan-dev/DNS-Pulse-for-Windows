using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DnsPulse.Core.Models;

namespace DnsPulse.App.Converters;

/// <summary>
/// Maps <see cref="TrustTier"/>, <see cref="ServerDisplayCategory"/>, or <see cref="DnsServerEntry"/>
/// to a high-contrast dark-compatible badge brush (or localized badge label when <c>ConverterParameter="Label"</c>).
/// </summary>
public sealed class TrustTierToBadgeBrushConverter : IValueConverter, IMultiValueConverter
{
    private static readonly SolidColorBrush AiGeoBrush = CreateFrozenBrush(0x1D, 0x4E, 0xD8);
    private static readonly SolidColorBrush FastEncryptedBrush = CreateFrozenBrush(0x15, 0x80, 0x3D);
    private static readonly SolidColorBrush StreamingGamingBrush = CreateFrozenBrush(0x0F, 0x76, 0x6E);
    private static readonly SolidColorBrush CustomBrush = CreateFrozenBrush(0x6D, 0x28, 0xD9);
    private static readonly SolidColorBrush LabBrush = CreateFrozenBrush(0xB4, 0x53, 0x09);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool returnLabel = parameter is string mode && string.Equals(mode, "Label", StringComparison.OrdinalIgnoreCase);

        if (value is DnsServerEntry server)
        {
            ServerDisplayCategory classified = ServerCategoryClassifier.Classify(server);
            return returnLabel ? GetCategoryLabel(classified) : GetCategoryBrush(classified);
        }

        if (value is ServerDisplayCategory category)
        {
            return returnLabel ? GetCategoryLabel(category) : GetCategoryBrush(category);
        }

        TrustTier tier = value is TrustTier t ? t : TrustTier.Tier3CustomOrSelfHosted;
        if (returnLabel)
        {
            string key = tier switch
            {
                TrustTier.Tier1EncryptedTrusted => "Servers_Badge_Trust_Fast",
                TrustTier.Tier2VerifiedGeoUnlock => "Servers_Badge_Trust_Geo",
                TrustTier.Tier3CustomOrSelfHosted => "Servers_Badge_Trust_Custom",
                TrustTier.Tier4ExperimentalLab => "Servers_Badge_Trust_Lab",
                _ => "Servers_Badge_Trust_Custom"
            };
            return LocalizationSource.Instance[key];
        }

        return tier switch
        {
            TrustTier.Tier1EncryptedTrusted => FastEncryptedBrush,
            TrustTier.Tier2VerifiedGeoUnlock => AiGeoBrush,
            TrustTier.Tier3CustomOrSelfHosted => CustomBrush,
            TrustTier.Tier4ExperimentalLab => LabBrush,
            _ => CustomBrush
        };
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

    internal static SolidColorBrush GetCategoryBrush(ServerDisplayCategory category)
    {
        return category switch
        {
            ServerDisplayCategory.AiAndGeoUnlock => AiGeoBrush,
            ServerDisplayCategory.FastEncrypted => FastEncryptedBrush,
            ServerDisplayCategory.StreamingAndGaming => StreamingGamingBrush,
            ServerDisplayCategory.CustomAndDiscovered => CustomBrush,
            _ => CustomBrush
        };
    }

    internal static string GetCategoryLabel(ServerDisplayCategory category, bool shortLabel = true)
    {
        string key = (category, shortLabel) switch
        {
            (ServerDisplayCategory.AiAndGeoUnlock, true) => "Servers_Category_AiGeo_Short",
            (ServerDisplayCategory.AiAndGeoUnlock, false) => "Servers_Category_AiGeo",
            (ServerDisplayCategory.FastEncrypted, true) => "Servers_Category_FastEncrypted_Short",
            (ServerDisplayCategory.FastEncrypted, false) => "Servers_Category_FastEncrypted",
            (ServerDisplayCategory.StreamingAndGaming, true) => "Servers_Category_StreamingGaming_Short",
            (ServerDisplayCategory.StreamingAndGaming, false) => "Servers_Category_StreamingGaming",
            (ServerDisplayCategory.CustomAndDiscovered, true) => "Servers_Category_Custom_Short",
            (ServerDisplayCategory.CustomAndDiscovered, false) => "Servers_Category_Custom",
            _ => "Servers_Category_Custom_Short"
        };

        return LocalizationSource.Instance[key];
    }

    private static SolidColorBrush CreateFrozenBrush(byte r, byte g, byte b)
    {
        SolidColorBrush brush = new(System.Windows.Media.Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}
