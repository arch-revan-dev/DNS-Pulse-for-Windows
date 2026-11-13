using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Recovery;
using DnsPulse.Platform.Windows.Updates;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// ViewModel for Settings &amp; Safety: Windows autostart, tray behavior, interception modes
/// (with active anti-cheat guard), privacy/leak guards, runtime language/theme switching,
/// verified updates, emergency network restore, and redacted diagnostic ZIP bundle export.
/// </summary>
public sealed partial class SettingsSafetyViewModel : ObservableObject
{
    private readonly AppSettingsStore _settingsStore;
    private readonly WindowsAutostartService _autostartService;
    private readonly IPulseRuntimeService _runtimeService;
    private readonly LocalizationService _localization;
    private readonly ThemeAppearanceService _themeService;
    private readonly NetworkSnapshotJournal _journal;
    private readonly Func<(bool IsActive, IReadOnlyList<string> Names)> _antiCheatDetector;
    private readonly Func<VerifiedAppUpdateService>? _updateServiceFactory;

    private bool _isLoading;

    [ObservableProperty]
    private bool _startWithWindows;

    [ObservableProperty]
    private bool _startMinimizedToTray = true;

    [ObservableProperty]
    private bool _minimizeToTrayOnClose = true;

    [ObservableProperty]
    private InterceptionMode _selectedInterceptionMode = InterceptionMode.AdapterDns;

    [ObservableProperty]
    private bool _isAntiCheatActive;

    [ObservableProperty]
    private string _detectedAntiCheatNames = string.Empty;

    [ObservableProperty]
    private bool _blockIpv6OnBypass = true;

    [ObservableProperty]
    private bool _perRouteHttpsSvcbMode = true;

    [ObservableProperty]
    private bool _dnsRebindingProtectionEnabled = true;

    [ObservableProperty]
    private bool _zeroDiskQueryLogging = true;

    [ObservableProperty]
    private string _selectedLanguageCode = LocalizationService.DefaultLanguageCode;

    [ObservableProperty]
    private bool _isDarkTheme = true;

    [ObservableProperty]
    private string _selectedAccentPreset = "Emerald";

    [ObservableProperty]
    private bool _compactMode;

    [ObservableProperty]
    private int _probeTimeoutMs = 2600;

    [ObservableProperty]
    private int _benchmarkConcurrency = 6;

    [ObservableProperty]
    private bool _autoFailoverOnDrop = true;

    [ObservableProperty]
    private bool _autoSyncFeedsOnStartup = true;

    [ObservableProperty]
    private string _bootstrapDnsProvider = "Auto";

    [ObservableProperty]
    private PoolSelectionStrategy _selectedPoolStrategy = PoolSelectionStrategy.Fastest;

    [ObservableProperty]
    private UpdateChannel _selectedUpdateChannel = UpdateChannel.Stable;

    [ObservableProperty]
    private bool _autoCheckUpdates = true;

    [ObservableProperty]
    private string _gitHubToken = string.Empty;

    [ObservableProperty]
    private bool _isCheckingUpdates;

    [ObservableProperty]
    private string _updateStatusMessage = string.Empty;

    [ObservableProperty]
    private ReleaseInfo? _latestRelease;

    [ObservableProperty]
    private string _safetyStatusMessage = string.Empty;

    [ObservableProperty]
    private string? _lastExportedBundlePath;

    public SettingsSafetyViewModel(
        AppSettingsStore settingsStore,
        WindowsAutostartService autostartService,
        IPulseRuntimeService runtimeService,
        LocalizationService localization,
        ThemeAppearanceService themeService,
        NetworkSnapshotJournal? journal = null,
        Func<(bool IsActive, IReadOnlyList<string> Names)>? antiCheatDetector = null,
        Func<VerifiedAppUpdateService>? updateServiceFactory = null)
    {
        ArgumentNullException.ThrowIfNull(settingsStore);
        ArgumentNullException.ThrowIfNull(autostartService);
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(localization);
        ArgumentNullException.ThrowIfNull(themeService);

        _settingsStore = settingsStore;
        _autostartService = autostartService;
        _runtimeService = runtimeService;
        _localization = localization;
        _themeService = themeService;
        _journal = journal ?? new NetworkSnapshotJournal();
        _antiCheatDetector = antiCheatDetector ?? AntiCheatGuard.DetectActiveAntiCheat;
        _updateServiceFactory = updateServiceFactory;

        _localization.CultureChanged += OnCultureChanged;
        RefreshAntiCheatStatus();
    }

    public LocalizationService Localization => _localization;

    public ThemeAppearanceService ThemeService => _themeService;

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Exposed as instance property for XAML data binding.")]
    public IReadOnlyList<LanguageOption> AvailableLanguages => LocalizationService.AvailableLanguages;

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Exposed as instance property for XAML data binding.")]
    public IReadOnlyList<string> AvailableAccentPresets => ThemeAppearanceService.AvailableAccentPresets;

    public IReadOnlyList<InterceptionMode> AvailableInterceptionModes { get; } =
    [
        InterceptionMode.AdapterDns,
        InterceptionMode.SplitNrpt,
        InterceptionMode.LocalProxyPacOnly,
        InterceptionMode.WfpDivertPlugin
    ];

    public IReadOnlyList<UpdateChannel> AvailableUpdateChannels { get; } =
    [
        UpdateChannel.Stable,
        UpdateChannel.Beta
    ];

    public IReadOnlyList<PoolSelectionStrategy> AvailablePoolStrategies { get; } =
    [
        PoolSelectionStrategy.Fastest,
        PoolSelectionStrategy.Parallel,
        PoolSelectionStrategy.Failover,
        PoolSelectionStrategy.LoadBalance
    ];

    public IReadOnlyList<string> AvailableBootstrapProviders { get; } =
    [
        "Auto",
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9"
    ];

    public bool IsWfpAntiCheatBlocked => IsAntiCheatActive && SelectedInterceptionMode == InterceptionMode.WfpDivertPlugin;

    public string AntiCheatStatusMessage => IsAntiCheatActive
        ? string.Format(CultureInfo.CurrentCulture, _localization["Settings_AntiCheat_Detected"], DetectedAntiCheatNames)
        : _localization["Settings_AntiCheat_StatusOk"];

    public string BackdropStatusText => _themeService.IsMicaSupported
        ? _localization["Settings_Backdrop_Mica"]
        : _localization["Settings_Backdrop_Solid"];

    public void LoadFromSettings(PulseAppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        PulseAppSettings normalized = settings.Clone();
        AppSettingsStore.Normalize(normalized);

        _isLoading = true;
        try
        {
            StartWithWindows = normalized.StartWithWindows;
            StartMinimizedToTray = normalized.StartMinimizedToTray;
            MinimizeToTrayOnClose = normalized.MinimizeToTrayOnClose;
            SelectedInterceptionMode = normalized.InterceptionMode;
            BlockIpv6OnBypass = normalized.BlockIpv6OnBypass;
            PerRouteHttpsSvcbMode = normalized.UseLocalDohEndpoint || normalized.SplitTunnelEnabled;
            DnsRebindingProtectionEnabled = normalized.DnsRebindingProtectionEnabled;
            ZeroDiskQueryLogging = normalized.ZeroDiskQueryLogging;
            SelectedLanguageCode = normalized.UiLanguage;
            IsDarkTheme = normalized.IsDarkTheme;
            SelectedAccentPreset = normalized.AccentPreset;
            CompactMode = normalized.CompactMode;
            ProbeTimeoutMs = normalized.ProbeTimeoutMs;
            BenchmarkConcurrency = normalized.BenchmarkConcurrency;
            AutoFailoverOnDrop = normalized.AutoFailoverOnDrop;
            AutoSyncFeedsOnStartup = normalized.AutoSyncFeedsOnStartup;
            BootstrapDnsProvider = normalized.BootstrapDnsProvider;
            SelectedPoolStrategy = normalized.PoolStrategy;
            SelectedUpdateChannel = normalized.UpdateChannel;
            AutoCheckUpdates = normalized.AutoCheckUpdates;
            GitHubToken = normalized.GitHubToken;
        }
        finally
        {
            _isLoading = false;
        }

        _localization.SetLanguage(SelectedLanguageCode);
        _themeService.ApplyTheme(IsDarkTheme, SelectedAccentPreset);
        OnPropertyChanged(nameof(BackdropStatusText));
        OnPropertyChanged(nameof(IsWfpAntiCheatBlocked));
    }

    public PulseAppSettings BuildNormalizedSettings()
    {
        PulseAppSettings settings = new()
        {
            StartWithWindows = StartWithWindows,
            StartMinimizedToTray = StartMinimizedToTray,
            MinimizeToTrayOnClose = MinimizeToTrayOnClose,
            InterceptionMode = SelectedInterceptionMode,
            EnableLocalTlsSplitPac = true,
            SplitTunnelEnabled = true,
            BlockIpv6OnBypass = BlockIpv6OnBypass,
            UseLocalDohEndpoint = PerRouteHttpsSvcbMode,
            DnsRebindingProtectionEnabled = DnsRebindingProtectionEnabled,
            ZeroDiskQueryLogging = ZeroDiskQueryLogging,
            UiLanguage = SelectedLanguageCode,
            IsDarkTheme = IsDarkTheme,
            AccentPreset = SelectedAccentPreset,
            CompactMode = CompactMode,
            ProbeTimeoutMs = ProbeTimeoutMs,
            BenchmarkConcurrency = BenchmarkConcurrency,
            AutoFailoverOnDrop = AutoFailoverOnDrop,
            AutoSyncFeedsOnStartup = AutoSyncFeedsOnStartup,
            BootstrapDnsProvider = BootstrapDnsProvider,
            PoolStrategy = SelectedPoolStrategy,
            UpdateChannel = SelectedUpdateChannel,
            AutoCheckUpdates = AutoCheckUpdates,
            GitHubToken = GitHubToken
        };

        AppSettingsStore.Normalize(settings);
        return settings;
    }

    [RelayCommand]
    public async Task SaveSettingsAsync(CancellationToken cancellationToken = default)
    {
        PulseAppSettings normalized = BuildNormalizedSettings();

        // Sync clamped values back to bound properties.
        _isLoading = true;
        try
        {
            ProbeTimeoutMs = normalized.ProbeTimeoutMs;
            BenchmarkConcurrency = normalized.BenchmarkConcurrency;
            SelectedAccentPreset = normalized.AccentPreset;
            BootstrapDnsProvider = normalized.BootstrapDnsProvider;
        }
        finally
        {
            _isLoading = false;
        }

        await _settingsStore.SaveAsync(normalized, cancellationToken).ConfigureAwait(false);
        await _runtimeService.UpdateEngineOptionsAsync(normalized, cancellationToken).ConfigureAwait(false);

        if (normalized.StartWithWindows)
        {
            _autostartService.Enable(normalized.StartMinimizedToTray);
        }
        else
        {
            _autostartService.Disable();
        }

        SafetyStatusMessage = _localization["Settings_Saved"];
    }

    [RelayCommand]
    public void RefreshAntiCheatStatus()
    {
        (bool isActive, IReadOnlyList<string> detectedNames) = _antiCheatDetector();
        IsAntiCheatActive = isActive;
        DetectedAntiCheatNames = string.Join(", ", detectedNames);
        OnPropertyChanged(nameof(AntiCheatStatusMessage));
        OnPropertyChanged(nameof(IsWfpAntiCheatBlocked));
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Update check errors are surfaced to the user via UpdateStatusMessage.")]
    public async Task CheckForUpdatesAsync(CancellationToken cancellationToken = default)
    {
        if (IsCheckingUpdates)
        {
            return;
        }

        IsCheckingUpdates = true;
        try
        {
            UpdateCheckResult result;
            if (_updateServiceFactory is not null)
            {
                using VerifiedAppUpdateService customService = _updateServiceFactory();
                result = await customService.CheckForUpdateAsync(
                    SelectedUpdateChannel,
                    string.IsNullOrWhiteSpace(GitHubToken) ? null : GitHubToken.Trim(),
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                using VerifiedAppUpdateService defaultService = new(_runtimeService.BootstrapResolver);
                result = await defaultService.CheckForUpdateAsync(
                    SelectedUpdateChannel,
                    string.IsNullOrWhiteSpace(GitHubToken) ? null : GitHubToken.Trim(),
                    cancellationToken).ConfigureAwait(false);
            }

            LatestRelease = result.LatestRelease;
            if (!string.IsNullOrWhiteSpace(result.ErrorMessage))
            {
                UpdateStatusMessage = result.ErrorMessage;
            }
            else if (result.UpdateAvailable && result.LatestRelease is not null)
            {
                UpdateStatusMessage = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{result.LatestRelease.TagName} ({result.CurrentVersion} -> {result.LatestRelease.ParsedVersion})");
            }
            else
            {
                UpdateStatusMessage = string.Create(
                    CultureInfo.InvariantCulture,
                    $"Up to date ({result.CurrentVersion})");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            UpdateStatusMessage = ex.Message;
        }
        finally
        {
            IsCheckingUpdates = false;
        }
    }

    [RelayCommand]
    public async Task EmergencyNetworkRestoreAsync(CancellationToken cancellationToken = default)
    {
        NetworkRestoredResult result = await _runtimeService.EmergencyRestoreAsync(cancellationToken).ConfigureAwait(false);
        SafetyStatusMessage = result.Summary;
    }

    [RelayCommand]
    public async Task<string> ExportDiagnosticBundleAsync(CancellationToken cancellationToken = default)
    {
        string desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktopDir))
        {
            desktopDir = Path.GetTempPath();
        }

        string fileName = string.Create(
            CultureInfo.InvariantCulture,
            $"DnsPulse-Diagnostic-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.zip");
        string targetPath = Path.Combine(desktopDir, fileName);

        await ExportDiagnosticBundleToPathAsync(targetPath, cancellationToken).ConfigureAwait(false);
        return targetPath;
    }

    public async Task ExportDiagnosticBundleToPathAsync(string outputZipPath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputZipPath);

        PulseAppSettings currentSettings = BuildNormalizedSettings();
        PrePulseNetworkSnapshot? snapshot = _journal.TryLoadVerifiedSnapshot(out _);
        HostNetworkHealthSnapshot hostHealth = await _runtimeService.InspectHostHealthAsync(cancellationToken).ConfigureAwait(false);

        IReadOnlyList<DnsQueryTelemetryEvent>? eventsIfOptedIn = currentSettings.ZeroDiskQueryLogging
            ? null
            : await _runtimeService.GetRecentTelemetryAsync(500, cancellationToken).ConfigureAwait(false);

        await DiagnosticBundleExporter.ExportRedactedBundleAsync(
            outputZipPath,
            currentSettings,
            snapshot,
            hostHealth,
            eventsIfOptedIn,
            LoggingSetupService.GetDefaultLogDirectory(),
            cancellationToken).ConfigureAwait(false);

        LastExportedBundlePath = outputZipPath;
        SafetyStatusMessage = outputZipPath;
    }

    partial void OnSelectedLanguageCodeChanged(string value)
    {
        if (_isLoading || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        _localization.SetLanguage(value);
    }

    partial void OnIsDarkThemeChanged(bool value)
    {
        if (_isLoading)
        {
            return;
        }

        _themeService.ApplyTheme(value, SelectedAccentPreset);
        OnPropertyChanged(nameof(BackdropStatusText));
    }

    partial void OnSelectedAccentPresetChanged(string value)
    {
        if (_isLoading)
        {
            return;
        }

        _themeService.ApplyTheme(IsDarkTheme, value);
    }

    partial void OnSelectedInterceptionModeChanged(InterceptionMode value)
    {
        OnPropertyChanged(nameof(IsWfpAntiCheatBlocked));
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        OnPropertyChanged(nameof(AntiCheatStatusMessage));
        OnPropertyChanged(nameof(BackdropStatusText));
    }
}
