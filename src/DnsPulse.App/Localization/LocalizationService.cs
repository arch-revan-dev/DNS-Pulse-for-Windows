using System.Globalization;
using System.Resources;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.ComponentModel;

namespace DnsPulse.App.Localization;

/// <summary>
/// Describes a selectable UI language option and its text flow direction.
/// </summary>
public sealed record LanguageOption(
    string CultureCode,
    string NativeName,
    bool IsRightToLeft);

/// <summary>
/// Event arguments carrying the newly activated UI <see cref="CultureInfo"/>.
/// </summary>
public sealed class CultureChangedEventArgs(CultureInfo culture) : EventArgs
{
    public CultureInfo Culture { get; } = culture ?? throw new ArgumentNullException(nameof(culture));
}

/// <summary>
/// Runtime localization service backed by <c>Strings.resx</c> and satellite assemblies,
/// supporting zero-restart language switching and RTL <see cref="System.Windows.FlowDirection"/> readiness.
/// </summary>
public sealed class LocalizationService : ObservableObject
{
    public const string DefaultLanguageCode = "en-US";
    public const string RussianLanguageCode = "ru-RU";

    private static readonly ResourceManager StringsResourceManager =
        new("DnsPulse.App.Localization.Strings", typeof(LocalizationService).Assembly);

    private CultureInfo _currentCulture = CultureInfo.GetCultureInfo(DefaultLanguageCode);

    /// <summary>
    /// Gets the languages with full built-in translations shipped in the application.
    /// </summary>
    public static IReadOnlyList<LanguageOption> AvailableLanguages { get; } =
    [
        new LanguageOption("en-US", "English (United States)", false),
        new LanguageOption("ru-RU", "Русский (Россия)", false)
    ];

    /// <summary>
    /// Gets the full list of BCP-47 cultures planned/ready in the extensible localization architecture
    /// (including RTL <c>fa-IR</c> readiness).
    /// </summary>
    public static IReadOnlyList<LanguageOption> ExtensibleLanguageCatalog { get; } =
    [
        new LanguageOption("en-US", "English (United States)", false),
        new LanguageOption("ru-RU", "Русский (Россия)", false),
        new LanguageOption("de-DE", "Deutsch", false),
        new LanguageOption("tr-TR", "Türkçe", false),
        new LanguageOption("fa-IR", "فارسی (RTL)", true),
        new LanguageOption("zh-CN", "简体中文", false),
        new LanguageOption("es-ES", "Español", false)
    ];

    /// <summary>
    /// Raised immediately after <see cref="SetLanguage"/> changes the active UI culture.
    /// </summary>
    public event EventHandler<CultureChangedEventArgs>? CultureChanged;

    /// <summary>
    /// Gets the currently active <see cref="CultureInfo"/>.
    /// </summary>
    public CultureInfo CurrentCulture => _currentCulture;

    /// <summary>
    /// Gets the normalized BCP-47 language tag (e.g., <c>en-US</c>, <c>ru-RU</c>, <c>fa-IR</c>).
    /// </summary>
    public string CurrentLanguageCode => _currentCulture.Name;

    /// <summary>
    /// Gets the layout <see cref="System.Windows.FlowDirection"/> for the active culture (<see cref="System.Windows.FlowDirection.RightToLeft"/> for RTL cultures such as <c>fa-IR</c>).
    /// </summary>
    public System.Windows.FlowDirection FlowDirection => _currentCulture.TextInfo.IsRightToLeft
        ? System.Windows.FlowDirection.RightToLeft
        : System.Windows.FlowDirection.LeftToRight;

    /// <summary>
    /// Gets a value indicating whether the active culture reads right-to-left.
    /// </summary>
    public bool IsRightToLeft => _currentCulture.TextInfo.IsRightToLeft;

    /// <summary>
    /// Gets the localized string for <paramref name="key"/> in <see cref="CurrentCulture"/>,
    /// falling back to canonical <c>en-US</c> and finally <paramref name="key"/> if missing.
    /// </summary>
    [IndexerName("Item")]
    public string this[string key] => GetString(key);

    /// <summary>
    /// Resolves a localized resource value for <paramref name="key"/> in the active culture.
    /// </summary>
    public string GetString(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        string? value = StringsResourceManager.GetString(key, _currentCulture);
        if (!string.IsNullOrEmpty(value))
        {
            return value;
        }

        string? fallback = StringsResourceManager.GetString(key, CultureInfo.GetCultureInfo(DefaultLanguageCode));
        return !string.IsNullOrEmpty(fallback) ? fallback : key;
    }

    /// <summary>
    /// Resolves a localized string for a specific <paramref name="culture"/> (useful for parity/translation verification).
    /// </summary>
    public static string? GetStringForCulture(string key, CultureInfo culture)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(culture);
        return StringsResourceManager.GetString(key, culture);
    }

    /// <summary>
    /// Resolves and formats a composite localized string using <see cref="CurrentCulture"/>.
    /// </summary>
    public string Format(string key, params object?[] args)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(args);

        string template = GetString(key);
        return string.Format(_currentCulture, template, args);
    }

    /// <summary>
    /// Switches the active UI language at runtime without restarting the application.
    /// </summary>
    public void SetLanguage(string cultureCode, bool updateThreadCulture = true)
    {
        CultureInfo target = ResolveCulture(cultureCode);
        if (string.Equals(_currentCulture.Name, target.Name, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _currentCulture = target;
        if (updateThreadCulture)
        {
            CultureInfo.CurrentUICulture = target;
            CultureInfo.CurrentCulture = target;
            CultureInfo.DefaultThreadCurrentUICulture = target;
        }

        OnPropertyChanged(nameof(CurrentCulture));
        OnPropertyChanged(nameof(CurrentLanguageCode));
        OnPropertyChanged(nameof(FlowDirection));
        OnPropertyChanged(nameof(IsRightToLeft));
        OnPropertyChanged("Item[]");

        CultureChanged?.Invoke(this, new CultureChangedEventArgs(target));
    }

    /// <summary>
    /// Normalizes a culture identifier, falling back to <c>en-US</c> when invalid or empty.
    /// </summary>
    public static CultureInfo ResolveCulture(string? cultureCode)
    {
        if (string.IsNullOrWhiteSpace(cultureCode))
        {
            return CultureInfo.GetCultureInfo(DefaultLanguageCode);
        }

        string trimmed = cultureCode.Trim();
        try
        {
            CultureInfo candidate = CultureInfo.GetCultureInfo(trimmed);
            return string.IsNullOrWhiteSpace(candidate.Name)
                ? CultureInfo.GetCultureInfo(DefaultLanguageCode)
                : candidate;
        }
        catch (CultureNotFoundException)
        {
            return CultureInfo.GetCultureInfo(DefaultLanguageCode);
        }
    }
}
