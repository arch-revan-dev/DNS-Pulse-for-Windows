using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DnsPulse.App.ViewModels;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Diagnostics;

namespace DnsPulse.App.Converters;

/// <summary>
/// Maps <see cref="DiagnosticVerdict"/>, <see cref="DiagnosticLayerStatus"/>, and <see cref="HeroConnectionState"/>
/// to WCAG-AA accessible semantic status brushes suitable for pairing with white foreground icons/text.
/// </summary>
public sealed class VerdictToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush SuccessBrush = CreateFrozenBrush(0x15, 0x80, 0x3D);
    private static readonly SolidColorBrush InfoBrush = CreateFrozenBrush(0x1D, 0x4E, 0xD8);
    private static readonly SolidColorBrush WarningBrush = CreateFrozenBrush(0xB4, 0x53, 0x09);
    private static readonly SolidColorBrush ErrorBrush = CreateFrozenBrush(0xB9, 0x1C, 0x1C);
    private static readonly SolidColorBrush NeutralBrush = CreateFrozenBrush(0x47, 0x55, 0x69);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            DiagnosticVerdict verdict => verdict switch
            {
                DiagnosticVerdict.Healthy => SuccessBrush,
                DiagnosticVerdict.Unknown => NeutralBrush,
                DiagnosticVerdict.BrowserDohBypass or DiagnosticVerdict.LocalPort53Conflict => WarningBrush,
                _ => ErrorBrush
            },
            DiagnosticLayerStatus status => status switch
            {
                DiagnosticLayerStatus.Passed => SuccessBrush,
                DiagnosticLayerStatus.Warning => WarningBrush,
                DiagnosticLayerStatus.Failed => ErrorBrush,
                _ => NeutralBrush
            },
            HeroConnectionState heroState => heroState switch
            {
                HeroConnectionState.Protected => SuccessBrush,
                HeroConnectionState.SmartBypassActive => InfoBrush,
                HeroConnectionState.Degraded => WarningBrush,
                _ => NeutralBrush
            },
            _ => NeutralBrush
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
