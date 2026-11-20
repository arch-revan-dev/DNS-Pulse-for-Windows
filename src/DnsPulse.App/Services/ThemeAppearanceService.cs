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
            if (dispatcher is not null &&
                !dispatcher.HasShutdownStarted &&
                !dispatcher.HasShutdownFinished &&
                dispatcher.Thread.IsAlive)
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
    /// Updates shared layout density tokens (<c>PulsePagePadding</c>, <c>PulseHeroPadding</c>, <c>PulseSectionMargin</c>)
    /// so enabling Compact Layout Mode immediately tightens page spacing across the shell.
    /// </summary>
    public void ApplyCompactMode(bool isCompact)
    {
        if (System.Windows.Application.Current is not { } app)
        {
            return;
        }

        void UpdateSpacing() => ApplyCompactTokens(app.Resources, isCompact);

        Dispatcher? dispatcher = app.Dispatcher;
        if (dispatcher is not null &&
            !dispatcher.HasShutdownStarted &&
            !dispatcher.HasShutdownFinished &&
            dispatcher.Thread.IsAlive)
        {
            if (dispatcher.CheckAccess())
            {
                UpdateSpacing();
            }
            else
            {
                dispatcher.Invoke(UpdateSpacing);
            }
        }
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
        if (!highContrast)
        {
            AccentPalette palette = GetAccentPalette(preset);
            ApplicationAccentColorManager.Apply(palette.Primary, targetTheme, false, false);
        }

        ApplyResourceTokenOverrides(app.Resources, targetTheme, preset, highContrast);
    }

    /// <summary>
    /// Updates shared layout density tokens inside <paramref name="resources"/> for Compact vs Normal mode.
    /// </summary>
    public static void ApplyCompactTokens(ResourceDictionary resources, bool isCompact)
    {
        ArgumentNullException.ThrowIfNull(resources);
        resources["PulsePagePadding"] = isCompact ? new Thickness(16, 10, 16, 16) : new Thickness(24, 16, 24, 24);
        resources["PulseHeroPadding"] = isCompact ? new Thickness(16) : new Thickness(22);
        resources["PulseSectionMargin"] = isCompact ? new Thickness(0, 0, 0, 10) : new Thickness(0, 0, 0, 16);
    }

    /// <summary>
    /// Applies accessible accent and adaptive Light/Dark/High-Contrast surface tokens into <paramref name="resources"/>.
    /// </summary>
    public static void ApplyResourceTokenOverrides(
        ResourceDictionary resources,
        ApplicationTheme targetTheme,
        ThemeAccentPreset preset,
        bool highContrast)
    {
        ArgumentNullException.ThrowIfNull(resources);
        if (highContrast)
        {
            ApplyHighContrastSemanticOverrides(resources);
            return;
        }

        AccentPalette palette = GetAccentPalette(preset);
        ApplyAccessibleAccentOverrides(resources, palette, targetTheme);
        ApplyAdaptiveSemanticOverrides(resources, palette, targetTheme);
    }

    private static void ApplyAdaptiveSemanticOverrides(
        ResourceDictionary resources,
        AccentPalette palette,
        ApplicationTheme targetTheme)
    {
        bool isDark = targetTheme == ApplicationTheme.Dark;

        SetBrush(resources, "TextFillColorPrimaryBrush", isDark
            ? MediaColor.FromRgb(0xFF, 0xFF, 0xFF)
            : MediaColor.FromArgb(0xE4, 0x00, 0x00, 0x00));
        SetBrush(resources, "TextFillColorSecondaryBrush", isDark
            ? MediaColor.FromArgb(0xC8, 0xFF, 0xFF, 0xFF)
            : MediaColor.FromArgb(0x9E, 0x00, 0x00, 0x00));
        SetBrush(resources, "TextFillColorTertiaryBrush", isDark
            ? MediaColor.FromArgb(0x8C, 0xFF, 0xFF, 0xFF)
            : MediaColor.FromArgb(0x72, 0x00, 0x00, 0x00));

        SetBrush(resources, "PulseInnerPanelBrush", isDark
            ? MediaColor.FromRgb(0x1A, 0x20, 0x29)
            : MediaColor.FromRgb(0xF3, 0xF6, 0xFA));
        SetBrush(resources, "PulseInnerPanelBorderBrush", isDark
            ? MediaColor.FromRgb(0x2C, 0x35, 0x44)
            : MediaColor.FromRgb(0xDC, 0xE3, 0xEC));
        SetBrush(resources, "PulseHeaderSurfaceBrush", isDark
            ? MediaColor.FromRgb(0x15, 0x1A, 0x22)
            : MediaColor.FromRgb(0xE9, 0xEE, 0xF5));
        SetBrush(resources, "PulseChipSurfaceBrush", isDark
            ? MediaColor.FromRgb(0x26, 0x2E, 0x3D)
            : MediaColor.FromRgb(0xE5, 0xEB, 0xF3));
        SetBrush(resources, "PulseCountBadgeBgBrush", isDark
            ? MediaColor.FromArgb(0x33, 0x00, 0x00, 0x00)
            : MediaColor.FromArgb(0x18, 0x0F, 0x17, 0x2A));

        SetBrush(resources, "PulseProtocolBadgeBgBrush", isDark
            ? MediaColor.FromRgb(0x1E, 0x3A, 0x5F)
            : MediaColor.FromRgb(0xDB, 0xEA, 0xFE));
        SetBrush(resources, "PulseProtocolBadgeFgBrush", isDark
            ? MediaColor.FromRgb(0x93, 0xC5, 0xFD)
            : MediaColor.FromRgb(0x1D, 0x4E, 0xD8));

        SetBrush(resources, "PulseAccentSubtleBrush", MediaColor.FromArgb(
            (byte)(isDark ? 0x24 : 0x18),
            palette.Primary.R,
            palette.Primary.G,
            palette.Primary.B));

        SetBrush(resources, "PulseSuccessSubtleBrush", isDark
            ? MediaColor.FromRgb(0x12, 0x2A, 0x20)
            : MediaColor.FromRgb(0xEC, 0xFD, 0xF5));
        SetBrush(resources, "PulseSuccessBorderBrush", isDark
            ? MediaColor.FromRgb(0x16, 0xA3, 0x4A)
            : MediaColor.FromRgb(0x10, 0xB9, 0x81));
        SetBrush(resources, "PulseSuccessBadgeBgBrush", isDark
            ? MediaColor.FromRgb(0x15, 0x80, 0x3D)
            : MediaColor.FromRgb(0x04, 0x78, 0x57));

        SetBrush(resources, "PulseInfoSubtleBrush", isDark
            ? MediaColor.FromRgb(0x15, 0x23, 0x38)
            : MediaColor.FromRgb(0xEF, 0xF6, 0xFF));
        SetBrush(resources, "PulseInfoBorderBrush", isDark
            ? MediaColor.FromRgb(0x25, 0x63, 0xEB)
            : MediaColor.FromRgb(0x3B, 0x82, 0xF6));
        SetBrush(resources, "PulseInfoBadgeBgBrush", isDark
            ? MediaColor.FromRgb(0x1D, 0x4E, 0xD8)
            : MediaColor.FromRgb(0x25, 0x63, 0xEB));

        SetBrush(resources, "PulseWarningSubtleBrush", isDark
            ? MediaColor.FromRgb(0x2B, 0x20, 0x12)
            : MediaColor.FromRgb(0xFF, 0xFB, 0xEB));
        SetBrush(resources, "PulseWarningBorderBrush", isDark
            ? MediaColor.FromRgb(0xD9, 0x77, 0x06)
            : MediaColor.FromRgb(0xF5, 0x9E, 0x0B));
        SetBrush(resources, "PulseWarningBadgeBgBrush", isDark
            ? MediaColor.FromRgb(0xB4, 0x53, 0x09)
            : MediaColor.FromRgb(0xD9, 0x77, 0x06));

        SetBrush(resources, "PulseDangerSubtleBrush", isDark
            ? MediaColor.FromRgb(0x2C, 0x16, 0x1A)
            : MediaColor.FromRgb(0xFE, 0xF2, 0xF2));
        SetBrush(resources, "PulseDangerBorderBrush", isDark
            ? MediaColor.FromRgb(0xDC, 0x26, 0x26)
            : MediaColor.FromRgb(0xEF, 0x44, 0x44));
        SetBrush(resources, "PulseDangerBadgeBgBrush", isDark
            ? MediaColor.FromRgb(0xB9, 0x1C, 0x1C)
            : MediaColor.FromRgb(0xDC, 0x26, 0x26));

        // iOS x Windows 11 Frosted Glass & Grouped Inset Surface Tokens
        SetBrush(resources, "PulseGlassCardBrush", isDark
            ? MediaColor.FromArgb(0xD8, 0x1C, 0x1E, 0x24)
            : MediaColor.FromArgb(0xEC, 0xFF, 0xFF, 0xFF));
        SetBrush(resources, "PulseGlassCardBorderBrush", isDark
            ? MediaColor.FromArgb(0x22, 0xFF, 0xFF, 0xFF)
            : MediaColor.FromArgb(0x18, 0x0F, 0x17, 0x2A));
        SetBrush(resources, "PulseHairlineDividerBrush", isDark
            ? MediaColor.FromArgb(0x18, 0xFF, 0xFF, 0xFF)
            : MediaColor.FromArgb(0x14, 0x0F, 0x17, 0x2A));
        SetBrush(resources, "PulseSegmentTrackBrush", isDark
            ? MediaColor.FromArgb(0x24, 0xFF, 0xFF, 0xFF)
            : MediaColor.FromArgb(0x12, 0x0F, 0x17, 0x2A));
        SetBrush(resources, "PulseSegmentActiveBrush", isDark
            ? MediaColor.FromRgb(0x36, 0x3A, 0x45)
            : MediaColor.FromRgb(0xFF, 0xFF, 0xFF));
        SetBrush(resources, "PulseIosGreenBrush", isDark
            ? MediaColor.FromRgb(0x30, 0xD1, 0x58)
            : MediaColor.FromRgb(0x34, 0xC7, 0x59));
        SetBrush(resources, "PulseIosBlueBrush", isDark
            ? MediaColor.FromRgb(0x0A, 0x84, 0xFF)
            : MediaColor.FromRgb(0x00, 0x7A, 0xFF));
        SetBrush(resources, "PulseIosRedBrush", isDark
            ? MediaColor.FromRgb(0xFF, 0x45, 0x3A)
            : MediaColor.FromRgb(0xFF, 0x3B, 0x30));
        SetBrush(resources, "PulseOrbHaloBrush", MediaColor.FromArgb(
            (byte)(isDark ? 0x26 : 0x1E),
            palette.Primary.R,
            palette.Primary.G,
            palette.Primary.B));
    }

    private static void ApplyHighContrastSemanticOverrides(ResourceDictionary resources)
    {
        MediaColor window = System.Windows.SystemColors.WindowColor;
        MediaColor control = System.Windows.SystemColors.ControlColor;
        MediaColor windowText = System.Windows.SystemColors.WindowTextColor;
        MediaColor highlight = System.Windows.SystemColors.HighlightColor;

        SetBrush(resources, "TextFillColorPrimaryBrush", windowText);
        SetBrush(resources, "TextFillColorSecondaryBrush", windowText);
        SetBrush(resources, "TextFillColorTertiaryBrush", System.Windows.SystemColors.GrayTextColor);

        SetBrush(resources, "PulseInnerPanelBrush", window);
        SetBrush(resources, "PulseInnerPanelBorderBrush", windowText);
        SetBrush(resources, "PulseHeaderSurfaceBrush", control);
        SetBrush(resources, "PulseChipSurfaceBrush", control);
        SetBrush(resources, "PulseCountBadgeBgBrush", control);
        SetBrush(resources, "PulseProtocolBadgeBgBrush", highlight);
        SetBrush(resources, "PulseProtocolBadgeFgBrush", System.Windows.SystemColors.HighlightTextColor);
        SetBrush(resources, "PulseAccentSubtleBrush", control);
        SetBrush(resources, "PulseSuccessSubtleBrush", window);
        SetBrush(resources, "PulseSuccessBorderBrush", windowText);
        SetBrush(resources, "PulseSuccessBadgeBgBrush", highlight);
        SetBrush(resources, "PulseInfoSubtleBrush", window);
        SetBrush(resources, "PulseInfoBorderBrush", windowText);
        SetBrush(resources, "PulseInfoBadgeBgBrush", highlight);
        SetBrush(resources, "PulseWarningSubtleBrush", window);
        SetBrush(resources, "PulseWarningBorderBrush", windowText);
        SetBrush(resources, "PulseWarningBadgeBgBrush", highlight);
        SetBrush(resources, "PulseDangerSubtleBrush", window);
        SetBrush(resources, "PulseDangerBorderBrush", windowText);
        SetBrush(resources, "PulseDangerBadgeBgBrush", highlight);
        SetBrush(resources, "PulseGlassCardBrush", window);
        SetBrush(resources, "PulseGlassCardBorderBrush", windowText);
        SetBrush(resources, "PulseHairlineDividerBrush", windowText);
        SetBrush(resources, "PulseSegmentTrackBrush", control);
        SetBrush(resources, "PulseSegmentActiveBrush", highlight);
        SetBrush(resources, "PulseIosGreenBrush", highlight);
        SetBrush(resources, "PulseIosBlueBrush", highlight);
        SetBrush(resources, "PulseIosRedBrush", windowText);
        SetBrush(resources, "PulseOrbHaloBrush", control);
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
