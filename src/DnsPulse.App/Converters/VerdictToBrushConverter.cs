using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DnsPulse.App.ViewModels;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Diagnostics;

namespace DnsPulse.App.Converters;

/// <summary>
/// Maps <see cref="DiagnosticVerdict"/>, <see cref="DiagnosticLayerStatus"/>, and <see cref="HeroConnectionState"/>
/// to semantic high-contrast status brushes.
/// </summary>
public sealed class VerdictToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush SuccessBrush = CreateFrozenBrush(0x10, 0xB9, 0x81);
    private static readonly SolidColorBrush InfoBrush = CreateFrozenBrush(0x3B, 0x82, 0xF6);
    private static readonly SolidColorBrush WarningBrush = CreateFrozenBrush(0xF5, 0x9E, 0x0B);
    private static readonly SolidColorBrush ErrorBrush = CreateFrozenBrush(0xEF, 0x44, 0x44);
    private static readonly SolidColorBrush NeutralBrush = CreateFrozenBrush(0x64, 0x74, 0x8B);

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
