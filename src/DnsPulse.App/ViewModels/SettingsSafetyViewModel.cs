using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Threading;
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
    private readonly Func<VerifiedUpdateResult, CancellationToken, Task>? _applyUpdateHandler;

    private PulseAppSettings _preservedSettings = new();
    private bool _isLoading;
    private bool _autoCheckTriggered;

    public event EventHandler? ShutdownRequested;

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
    [NotifyPropertyChangedFor(nameof(IsUpdateBusy))]
    [NotifyCanExecuteChangedFor(nameof(DownloadAndInstallUpdateCommand))]
    private bool _isCheckingUpdates;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsUpdateBusy))]
    [NotifyCanExecuteChangedFor(nameof(CheckForUpdatesCommand))]
    [NotifyCanExecuteChangedFor(nameof(DownloadAndInstallUpdateCommand))]
    private bool _isUpdating;

    [ObservableProperty]
    private double _updateProgressPercent;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DownloadAndInstallUpdateCommand))]
    private bool _isUpdateAvailable;

    [ObservableProperty]
    private string _updateStatusMessage = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasLatestRelease))]
    [NotifyPropertyChangedFor(nameof(UpdateAvailableTitleText))]
    [NotifyCanExecuteChangedFor(nameof(DownloadAndInstallUpdateCommand))]
    [NotifyCanExecuteChangedFor(nameof(OpenReleasePageCommand))]
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
        Func<VerifiedAppUpdateService>? updateServiceFactory = null,
        Func<VerifiedUpdateResult, CancellationToken, Task>? applyUpdateHandler = null)
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
        _applyUpdateHandler = applyUpdateHandler;

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

    public bool IsUpdateBusy => IsCheckingUpdates || IsUpdating;

    public bool HasLatestRelease => LatestRelease is not null;

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Exposed as instance property for XAML data binding and culture updates.")]
    public string CurrentAppVersionText => string.Format(
        CultureInfo.CurrentCulture,
        _localization["Settings_UpdateCurrentVersion"],
        string.Concat("v", VerifiedAppUpdateService.GetCurrentVersion().ToString(3)));

    public string UpdateAvailableTitleText => LatestRelease is null
        ? string.Empty
        : string.Format(
            CultureInfo.CurrentCulture,
            _localization["Settings_UpdateAvailableTitle"],
            LatestRelease.TagName);

    public void SyncPreservedBannerFlags(
        bool dismissedBrowserDoh,
        bool dismissedPort53,
        bool dismissedVpn,
        bool dismissedAntiCheat)
    {
        _preservedSettings.DismissedBrowserDohBanner = dismissedBrowserDoh;
        _preservedSettings.DismissedPort53Banner = dismissedPort53;
        _preservedSettings.DismissedVpnBanner = dismissedVpn;
        _preservedSettings.DismissedAntiCheatBanner = dismissedAntiCheat;
    }

    public void SyncPreservedQuickService(string quickServiceId, string lastVerifiedTargetDomain)
    {
        if (!string.IsNullOrWhiteSpace(quickServiceId))
        {
            _preservedSettings.SelectedQuickServiceId = quickServiceId.Trim();
        }

        if (!string.IsNullOrWhiteSpace(lastVerifiedTargetDomain))
        {
            _preservedSettings.LastVerifiedTargetDomain = lastVerifiedTargetDomain.Trim();
        }
    }

    public void LoadFromSettings(PulseAppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        PulseAppSettings normalized = settings.Clone();
        AppSettingsStore.Normalize(normalized);
        _preservedSettings = normalized.Clone();

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
        ApplyThemeSafely(IsDarkTheme, SelectedAccentPreset);
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
            GitHubToken = GitHubToken,
            DismissedBrowserDohBanner = _preservedSettings.DismissedBrowserDohBanner,
            DismissedPort53Banner = _preservedSettings.DismissedPort53Banner,
            DismissedVpnBanner = _preservedSettings.DismissedVpnBanner,
            DismissedAntiCheatBanner = _preservedSettings.DismissedAntiCheatBanner,
            SelectedQuickServiceId = _preservedSettings.SelectedQuickServiceId,
            LastVerifiedTargetDomain = _preservedSettings.LastVerifiedTargetDomain
        };

        AppSettingsStore.Normalize(settings);
        return settings;
    }

    private void ApplyThemeSafely(bool isDarkTheme, string accentPreset)
    {
        Dispatcher? dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is not null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(() => _themeService.ApplyTheme(isDarkTheme, accentPreset));
            return;
        }

        _themeService.ApplyTheme(isDarkTheme, accentPreset);
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
        _preservedSettings = normalized.Clone();
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

    private bool CanCheckForUpdates() => !IsCheckingUpdates && !IsUpdating;

    private bool CanDownloadAndInstallUpdate() =>
        !IsCheckingUpdates && !IsUpdating && IsUpdateAvailable && LatestRelease is not null;

    [RelayCommand(CanExecute = nameof(CanCheckForUpdates))]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Update check errors are surfaced to the user via UpdateStatusMessage.")]
    public async Task CheckForUpdatesAsync(CancellationToken cancellationToken = default)
    {
        if (IsCheckingUpdates || IsUpdating)
        {
            return;
        }

        IsCheckingUpdates = true;
        try
        {
            UpdateCheckResult result = await ExecuteWithUpdateServiceAsync(
                service => service.CheckForUpdateAsync(
                    SelectedUpdateChannel,
                    string.IsNullOrWhiteSpace(GitHubToken) ? null : GitHubToken.Trim(),
                    cancellationToken)).ConfigureAwait(true);

            ApplyUpdateCheckResult(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            IsUpdateAvailable = false;
            UpdateStatusMessage = ex.Message;
        }
        finally
        {
            IsCheckingUpdates = false;
        }
    }

    /// <summary>
    /// Runs a quiet startup update check when <see cref="AutoCheckUpdates"/> is enabled,
    /// swallowing offline/transient errors so startup is never disrupted.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Background startup check ignores offline/transient errors intentionally.")]
    public async Task TryAutoCheckUpdatesOnStartupAsync(CancellationToken cancellationToken = default)
    {
        if (_autoCheckTriggered || !AutoCheckUpdates || IsCheckingUpdates || IsUpdating)
        {
            return;
        }

        _autoCheckTriggered = true;
        try
        {
            UpdateCheckResult result = await ExecuteWithUpdateServiceAsync(
                service => service.CheckForUpdateAsync(
                    SelectedUpdateChannel,
                    string.IsNullOrWhiteSpace(GitHubToken) ? null : GitHubToken.Trim(),
                    cancellationToken)).ConfigureAwait(true);

            if (result.UpdateAvailable && result.LatestRelease is not null)
            {
                ApplyUpdateCheckResult(result);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Quiet startup check should never surface spurious offline errors.
        }
    }

    [RelayCommand(CanExecute = nameof(CanDownloadAndInstallUpdate))]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Update download/verification failures are surfaced to the user via UpdateStatusMessage.")]
    public async Task DownloadAndInstallUpdateAsync(CancellationToken cancellationToken = default)
    {
        if (!CanDownloadAndInstallUpdate() || LatestRelease is null)
        {
            return;
        }

        ReleaseInfo targetRelease = LatestRelease;
        IsUpdating = true;
        UpdateProgressPercent = 2;

        try
        {
            Progress<(double Percent, string Status)> progress = new(report =>
            {
                UpdateProgressPercent = Math.Clamp(report.Percent, 0, 100);
                if (!string.IsNullOrWhiteSpace(report.Status))
                {
                    UpdateStatusMessage = report.Status;
                }
            });

            VerifiedUpdateResult verifiedResult = await ExecuteWithUpdateServiceAsync(
                service => service.DownloadAndVerifyUpdateAsync(
                    targetRelease,
                    progress: progress,
                    githubToken: string.IsNullOrWhiteSpace(GitHubToken) ? null : GitHubToken.Trim(),
                    cancellationToken: cancellationToken)).ConfigureAwait(true);

            UpdateProgressPercent = 100;

            if (_applyUpdateHandler is not null)
            {
                await _applyUpdateHandler(verifiedResult, cancellationToken).ConfigureAwait(true);
                UpdateStatusMessage = verifiedResult.Summary;
                return;
            }

            ApplyVerifiedUpdateAndRestart(verifiedResult);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            UpdateProgressPercent = 0;
            UpdateStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Settings_UpdateFailed"],
                ex.Message);
        }
        finally
        {
            IsUpdating = false;
        }
    }

    [RelayCommand(CanExecute = nameof(HasLatestRelease))]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "External browser launch errors are surfaced cleanly via UpdateStatusMessage.")]
    public void OpenReleasePage()
    {
        string? url = LatestRelease?.HtmlUrl;
        if (string.IsNullOrWhiteSpace(url) ||
            !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            using Process? proc = Process.Start(new ProcessStartInfo
            {
                FileName = uri.ToString(),
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            UpdateStatusMessage = ex.Message;
        }
    }

    private async Task<T> ExecuteWithUpdateServiceAsync<T>(Func<VerifiedAppUpdateService, Task<T>> action)
    {
        if (_updateServiceFactory is not null)
        {
            using VerifiedAppUpdateService customService = _updateServiceFactory();
            return await action(customService).ConfigureAwait(true);
        }

        using VerifiedAppUpdateService defaultService = new(_runtimeService.BootstrapResolver);
        return await action(defaultService).ConfigureAwait(true);
    }

    private void ApplyUpdateCheckResult(UpdateCheckResult result)
    {
        LatestRelease = result.LatestRelease;

        if (!string.IsNullOrWhiteSpace(result.ErrorMessage))
        {
            IsUpdateAvailable = false;
            UpdateStatusMessage = result.ErrorMessage;
            return;
        }

        if (result.UpdateAvailable && result.LatestRelease is not null)
        {
            IsUpdateAvailable = true;
            UpdateStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Settings_UpdateAvailableStatus"],
                result.LatestRelease.TagName,
                result.CurrentVersion.ToString(3));
            return;
        }

        IsUpdateAvailable = false;
        UpdateStatusMessage = string.Format(
            CultureInfo.CurrentCulture,
            _localization["Settings_UpdateUpToDate"],
            result.CurrentVersion.ToString(3));
    }

    private void ApplyVerifiedUpdateAndRestart(VerifiedUpdateResult verifiedResult)
    {
        if (verifiedResult.IsInstaller)
        {
            UpdateStatusMessage = _localization["Settings_UpdateLaunchingInstaller"];
            using Process? installer = Process.Start(VerifiedAppUpdateService.CreateSilentInstallerStartInfo(verifiedResult.PreparedFilePath));
        }
        else
        {
            UpdateStatusMessage = _localization["Settings_UpdateApplyingPortable"];
            string updatedExePath = VerifiedAppUpdateService.ApplyPortableUpdate(verifiedResult.PreparedFilePath);
            using Process? relaunched = Process.Start(VerifiedAppUpdateService.CreateRelaunchStartInfo(updatedExePath));
        }

        if (ShutdownRequested is not null)
        {
            ShutdownRequested.Invoke(this, EventArgs.Empty);
        }
        else
        {
            Dispatcher? dispatcher = System.Windows.Application.Current?.Dispatcher;
            dispatcher?.Invoke(() => System.Windows.Application.Current?.Shutdown());
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

        ApplyThemeSafely(value, SelectedAccentPreset);
        OnPropertyChanged(nameof(BackdropStatusText));
    }

    partial void OnSelectedAccentPresetChanged(string value)
    {
        if (_isLoading)
        {
            return;
        }

        ApplyThemeSafely(IsDarkTheme, value);
    }

    partial void OnSelectedInterceptionModeChanged(InterceptionMode value)
    {
        OnPropertyChanged(nameof(IsWfpAntiCheatBlocked));
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        OnPropertyChanged(nameof(AntiCheatStatusMessage));
        OnPropertyChanged(nameof(BackdropStatusText));
        OnPropertyChanged(nameof(CurrentAppVersionText));
        OnPropertyChanged(nameof(UpdateAvailableTitleText));
    }
}
