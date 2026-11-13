using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DnsPulse.Core.Models;

namespace DnsPulse.App.Converters;

/// <summary>
/// Maps <see cref="TrustTier"/> to a semantic badge brush (or short tier badge label when <c>ConverterParameter="Label"</c>).
/// </summary>
public sealed class TrustTierToBadgeBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Tier1Brush = CreateFrozenBrush(0x10, 0xB9, 0x81);
    private static readonly SolidColorBrush Tier2Brush = CreateFrozenBrush(0x3B, 0x82, 0xF6);
    private static readonly SolidColorBrush Tier3Brush = CreateFrozenBrush(0x8B, 0x5C, 0xF6);
    private static readonly SolidColorBrush Tier4Brush = CreateFrozenBrush(0xF5, 0x9E, 0x0B);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        TrustTier tier = value is TrustTier t ? t : TrustTier.Tier3CustomOrSelfHosted;

        if (parameter is string mode && string.Equals(mode, "Label", StringComparison.OrdinalIgnoreCase))
        {
            return tier switch
            {
                TrustTier.Tier1EncryptedTrusted => "Tier 1",
                TrustTier.Tier2VerifiedGeoUnlock => "Tier 2",
                TrustTier.Tier3CustomOrSelfHosted => "Tier 3",
                TrustTier.Tier4ExperimentalLab => "Tier 4",
                _ => "Tier 3"
            };
        }

        return tier switch
        {
            TrustTier.Tier1EncryptedTrusted => Tier1Brush,
            TrustTier.Tier2VerifiedGeoUnlock => Tier2Brush,
            TrustTier.Tier3CustomOrSelfHosted => Tier3Brush,
            TrustTier.Tier4ExperimentalLab => Tier4Brush,
            _ => Tier3Brush
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }

    private static SolidColorBrush CreateFrozenBrush(byte r, byte g, byte b)
    {
        SolidColorBrush brush = new(System.Windows.Media.Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}
