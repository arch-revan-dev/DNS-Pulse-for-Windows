using System.Diagnostics.CodeAnalysis;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
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
    private readonly record struct AccentPalette(
        MediaColor Primary,
        MediaColor Hover,
        MediaColor Pressed,
        MediaColor DarkTextAccent);

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
    /// Dispatches synchronously onto the WPF UI thread when invoked from a background thread.
    /// </summary>
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

        if (System.Windows.Application.Current is { } app)
        {
            Dispatcher? dispatcher = app.Dispatcher;
            if (dispatcher is not null && !dispatcher.HasShutdownStarted && !dispatcher.HasShutdownFinished)
            {
                if (dispatcher.CheckAccess())
                {
                    ApplyWpfResources(app, targetTheme, backdrop, preset, highContrast);
                }
                else
                {
                    dispatcher.Invoke(() => ApplyWpfResources(app, targetTheme, backdrop, preset, highContrast));
                }
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
    /// Maps a <see cref="ThemeAccentPreset"/> to its primary WCAG-AA accessible UI accent color.
    /// </summary>
    public static MediaColor GetAccentColor(ThemeAccentPreset preset)
    {
        return GetAccentPalette(preset).Primary;
    }

    private static void ApplyWpfResources(
        System.Windows.Application app,
        ApplicationTheme targetTheme,
        WindowBackdropType backdrop,
        ThemeAccentPreset preset,
        bool highContrast)
    {
        // Never pass updateAccent: true — Wpf.Ui would pull the Windows OS accent color (often washed-out purple/pink).
        ApplicationThemeManager.Apply(targetTheme, backdrop, updateAccent: false);
        if (highContrast)
        {
            return;
        }

        AccentPalette palette = GetAccentPalette(preset);
        ApplicationAccentColorManager.Apply(palette.Primary, targetTheme, false, false);
        ApplyAccessibleAccentOverrides(app.Resources, palette, targetTheme);
    }

    private static void ApplyAccessibleAccentOverrides(
        ResourceDictionary resources,
        AccentPalette palette,
        ApplicationTheme targetTheme)
    {
        bool isDark = targetTheme == ApplicationTheme.Dark;
        MediaColor textAccentColor = isDark ? palette.DarkTextAccent : palette.Primary;
        MediaColor textAccentSecondaryColor = isDark ? palette.DarkTextAccent : palette.Hover;
        MediaColor textAccentTertiaryColor = isDark ? palette.DarkTextAccent : palette.Pressed;
        MediaColor white = MediaColor.FromRgb(0xFF, 0xFF, 0xFF);
        MediaColor whiteSecondary = MediaColor.FromArgb(0xE6, 0xFF, 0xFF, 0xFF);

        // Override Wpf.Ui 4.3.0 pastel dark-mode accent computation so primary buttons and checked chips
        // always render crisp saturated fills paired with high-contrast #FFFFFFFF white text.
        SetColorAndBrush(resources, "AccentFillColorDefault", "AccentFillColorDefaultBrush", palette.Primary);
        SetColorAndBrush(resources, "AccentFillColorSecondary", "AccentFillColorSecondaryBrush", palette.Hover);
        SetColorAndBrush(resources, "AccentFillColorTertiary", "AccentFillColorTertiaryBrush", palette.Pressed);
        SetBrush(resources, "AccentFillColorSelectedTextBackgroundBrush", palette.Primary);

        SetBrush(resources, "AccentButtonBackground", palette.Primary);
        SetBrush(resources, "AccentButtonBackgroundPointerOver", palette.Hover);
        SetBrush(resources, "AccentButtonBackgroundPressed", palette.Pressed);
        SetBrush(resources, "AccentButtonForeground", white);
        SetBrush(resources, "AccentButtonForegroundPointerOver", white);
        SetBrush(resources, "AccentButtonForegroundPressed", whiteSecondary);

        SetColorAndBrush(resources, "TextOnAccentFillColorPrimary", "TextOnAccentFillColorPrimaryBrush", white);
        SetColorAndBrush(resources, "TextOnAccentFillColorSecondary", "TextOnAccentFillColorSecondaryBrush", whiteSecondary);
        SetColorAndBrush(resources, "TextOnAccentFillColorSelectedText", "TextOnAccentFillColorSelectedTextBrush", white);

        SetColorAndBrush(resources, "SystemAccentColor", "SystemAccentBrush", palette.Primary);
        SetColorAndBrush(resources, "SystemAccentColorPrimary", "SystemAccentColorPrimaryBrush", textAccentColor);
        SetColorAndBrush(resources, "SystemAccentColorSecondary", "SystemAccentColorSecondaryBrush", palette.Hover);
        SetColorAndBrush(resources, "SystemAccentColorTertiary", "SystemAccentColorTertiaryBrush", palette.Pressed);

        SetBrush(resources, "AccentTextFillColorPrimaryBrush", textAccentColor);
        SetBrush(resources, "AccentTextFillColorSecondaryBrush", textAccentSecondaryColor);
        SetBrush(resources, "AccentTextFillColorTertiaryBrush", textAccentTertiaryColor);
        SetBrush(resources, "SystemFillColorAttentionBrush", textAccentColor);

        SetBrush(resources, "ToggleButtonBackgroundChecked", palette.Primary);
        SetBrush(resources, "ToggleButtonBackgroundCheckedPointerOver", palette.Hover);
        SetBrush(resources, "ToggleButtonBackgroundCheckedPressed", palette.Pressed);
        SetBrush(resources, "ToggleButtonForegroundChecked", white);
        SetBrush(resources, "ToggleButtonForegroundCheckedPointerOver", white);
        SetBrush(resources, "ToggleButtonForegroundCheckedPressed", whiteSecondary);
        SetBrush(resources, "ListViewItemPillFillBrush", textAccentColor);
    }

    private static void SetColorAndBrush(
        ResourceDictionary resources,
        string colorKey,
        string brushKey,
        MediaColor color)
    {
        resources[colorKey] = color;
        SetBrush(resources, brushKey, color);
    }

    private static void SetBrush(
        ResourceDictionary resources,
        string brushKey,
        MediaColor color)
    {
        SolidColorBrush brush = new(color);
        brush.Freeze();
        resources[brushKey] = brush;
    }

    private static AccentPalette GetAccentPalette(ThemeAccentPreset preset)
    {
        return preset switch
        {
            ThemeAccentPreset.Azure => new AccentPalette(
                Primary: MediaColor.FromRgb(0x25, 0x63, 0xEB),
                Hover: MediaColor.FromRgb(0x1D, 0x4E, 0xD8),
                Pressed: MediaColor.FromRgb(0x1E, 0x40, 0xAF),
                DarkTextAccent: MediaColor.FromRgb(0x60, 0xA5, 0xFA)),
            ThemeAccentPreset.Violet => new AccentPalette(
                Primary: MediaColor.FromRgb(0x7C, 0x3A, 0xED),
                Hover: MediaColor.FromRgb(0x6D, 0x28, 0xD9),
                Pressed: MediaColor.FromRgb(0x5B, 0x21, 0xB6),
                DarkTextAccent: MediaColor.FromRgb(0xA7, 0x8B, 0xFA)),
            ThemeAccentPreset.Amber => new AccentPalette(
                Primary: MediaColor.FromRgb(0xB4, 0x53, 0x09),
                Hover: MediaColor.FromRgb(0x92, 0x40, 0x0E),
                Pressed: MediaColor.FromRgb(0x78, 0x35, 0x0F),
                DarkTextAccent: MediaColor.FromRgb(0xFB, 0xBF, 0x24)),
            ThemeAccentPreset.Rose => new AccentPalette(
                Primary: MediaColor.FromRgb(0xE1, 0x1D, 0x48),
                Hover: MediaColor.FromRgb(0xBE, 0x12, 0x3C),
                Pressed: MediaColor.FromRgb(0x9F, 0x12, 0x39),
                DarkTextAccent: MediaColor.FromRgb(0xFB, 0x71, 0x85)),
            _ => new AccentPalette(
                Primary: MediaColor.FromRgb(0x04, 0x78, 0x57),
                Hover: MediaColor.FromRgb(0x05, 0x96, 0x69),
                Pressed: MediaColor.FromRgb(0x06, 0x5F, 0x46),
                DarkTextAccent: MediaColor.FromRgb(0x34, 0xD3, 0x99))
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
