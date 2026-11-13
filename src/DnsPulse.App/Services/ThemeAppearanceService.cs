using System.Diagnostics.CodeAnalysis;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using MediaColor = System.Windows.Media.Color;

namespace DnsPulse.App.Services;

/// <summary>
/// Supported application accent color presets.
/// </summary>
public enum ThemeAccentPreset
{
    Emerald = 0,
    Azure = 1,
    Violet = 2,
    Amber = 3,
    Rose = 4
}

/// <summary>
/// Manages WPF-UI theme (<see cref="ApplicationTheme"/>), accent presets, Windows 11 Mica vs. Windows 10 solid
/// backdrop selection, and <see cref="SystemParameters.HighContrast"/> compliance.
/// </summary>
public sealed class ThemeAppearanceService : ObservableObject
{
    private readonly Func<bool> _highContrastProvider;
    private readonly Func<int> _windowsBuildProvider;

    private ApplicationTheme _currentTheme = ApplicationTheme.Dark;
    private ThemeAccentPreset _currentAccentPreset = ThemeAccentPreset.Emerald;
    private WindowBackdropType _currentBackdrop = WindowBackdropType.Mica;
    private bool _isHighContrastActive;

    public ThemeAppearanceService()
        : this(
            static () => SystemParameters.HighContrast || ApplicationThemeManager.IsHighContrast(),
            static () => Environment.OSVersion.Version.Build)
    {
    }

    public ThemeAppearanceService(
        Func<bool> highContrastProvider,
        Func<int> windowsBuildProvider)
    {
        ArgumentNullException.ThrowIfNull(highContrastProvider);
        ArgumentNullException.ThrowIfNull(windowsBuildProvider);

        _highContrastProvider = highContrastProvider;
        _windowsBuildProvider = windowsBuildProvider;
        _isHighContrastActive = SafeEvaluateHighContrast();
        _currentBackdrop = ResolveBackdrop(_isHighContrastActive, _windowsBuildProvider());
    }

    /// <summary>
    /// Gets the canonical list of accent preset names compatible with v1.5.3 <c>settings.json</c>.
    /// </summary>
    public static IReadOnlyList<string> AvailableAccentPresets { get; } =
    [
        "Emerald",
        "Azure",
        "Violet",
        "Amber",
        "Rose"
    ];

    public ApplicationTheme CurrentTheme => _currentTheme;

    public ThemeAccentPreset CurrentAccentPreset => _currentAccentPreset;

    public string CurrentAccentPresetName => _currentAccentPreset.ToString();

    public WindowBackdropType CurrentBackdrop => _currentBackdrop;

    public bool IsHighContrastActive => _isHighContrastActive;

    public bool IsMicaSupported => !_isHighContrastActive && _windowsBuildProvider() >= 22000;

    /// <summary>
    /// Applies theme, accent preset, backdrop (Win11 Mica / Win10 solid fallback), and high-contrast compliance.
    /// Safe to invoke when <see cref="Application.Current"/> is null (e.g., headless unit tests).
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Headless/non-STA test hosts without WPF dispatcher resources should still update observable theme state cleanly.")]
    public void ApplyTheme(bool isDarkTheme, string? accentPresetName)
    {
        bool highContrast = SafeEvaluateHighContrast();
        ThemeAccentPreset preset = ParseAccentPreset(accentPresetName);
        ApplicationTheme targetTheme = highContrast
            ? ApplicationTheme.HighContrast
            : (isDarkTheme ? ApplicationTheme.Dark : ApplicationTheme.Light);
        WindowBackdropType backdrop = ResolveBackdrop(highContrast, _windowsBuildProvider());

        _isHighContrastActive = highContrast;
        _currentAccentPreset = preset;
        _currentTheme = targetTheme;
        _currentBackdrop = backdrop;

        if (System.Windows.Application.Current is not null)
        {
            try
            {
                ApplicationThemeManager.Apply(targetTheme, backdrop, updateAccent: !highContrast);
                if (!highContrast)
                {
                    ApplicationAccentColorManager.Apply(GetAccentColor(preset), targetTheme, false, false);
                }
            }
            catch (Exception)
            {
                // Ignore WPF resource dictionary errors if invoked prior to Application resource initialization.
            }
        }

        OnPropertyChanged(nameof(CurrentTheme));
        OnPropertyChanged(nameof(CurrentAccentPreset));
        OnPropertyChanged(nameof(CurrentAccentPresetName));
        OnPropertyChanged(nameof(CurrentBackdrop));
        OnPropertyChanged(nameof(IsHighContrastActive));
        OnPropertyChanged(nameof(IsMicaSupported));
    }

    /// <summary>
    /// Resolves the appropriate <see cref="WindowBackdropType"/> for the OS build and high-contrast posture.
    /// </summary>
    public static WindowBackdropType ResolveBackdrop(bool isHighContrast, int osBuildNumber)
    {
        if (isHighContrast || osBuildNumber < 22000)
        {
            return WindowBackdropType.None;
        }

        return WindowBackdropType.Mica;
    }

    /// <summary>
    /// Parses a persisted accent preset name with <see cref="ThemeAccentPreset.Emerald"/> fallback.
    /// </summary>
    public static ThemeAccentPreset ParseAccentPreset(string? presetName)
    {
        if (string.IsNullOrWhiteSpace(presetName))
        {
            return ThemeAccentPreset.Emerald;
        }

        return Enum.TryParse<ThemeAccentPreset>(presetName.Trim(), ignoreCase: true, out ThemeAccentPreset parsed)
            ? parsed
            : ThemeAccentPreset.Emerald;
    }

    /// <summary>
    /// Maps a <see cref="ThemeAccentPreset"/> to its primary UI accent color.
    /// </summary>
    public static MediaColor GetAccentColor(ThemeAccentPreset preset)
    {
        return preset switch
        {
            ThemeAccentPreset.Azure => MediaColor.FromRgb(0x3B, 0x82, 0xF6),
            ThemeAccentPreset.Violet => MediaColor.FromRgb(0x8B, 0x5C, 0xF6),
            ThemeAccentPreset.Amber => MediaColor.FromRgb(0xF5, 0x9E, 0x0B),
            ThemeAccentPreset.Rose => MediaColor.FromRgb(0xF4, 0x3F, 0x5E),
            _ => MediaColor.FromRgb(0x10, 0xB9, 0x81)
        };
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "High-contrast probe may fail on headless test runners.")]
    private bool SafeEvaluateHighContrast()
    {
        try
        {
            return _highContrastProvider();
        }
        catch (Exception)
        {
            return false;
        }
    }
}
