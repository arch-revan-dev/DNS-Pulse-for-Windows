using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Recovery;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Top-level navigation pages in the PulseCore shell.
/// </summary>
public enum ShellPageKind
{
    Overview = 0,
    Routing = 1,
    Servers = 2,
    Diagnostics = 3,
    Settings = 4
}

/// <summary>
/// Localized descriptor for one of the 5 primary shell navigation items.
/// </summary>
public sealed partial class ShellNavigationItem : ObservableObject
{
    [ObservableProperty]
    private string _title;

    [ObservableProperty]
    private string _automationName;

    public ShellNavigationItem(
        ShellPageKind page,
        string titleResourceKey,
        string automationResourceKey,
        string symbolName,
        string title,
        string automationName)
    {
        Page = page;
        TitleResourceKey = titleResourceKey;
        AutomationResourceKey = automationResourceKey;
        SymbolName = symbolName;
        _title = title;
        _automationName = automationName;
    }

    public ShellPageKind Page { get; }

    public string TitleResourceKey { get; }

    public string AutomationResourceKey { get; }

    public string SymbolName { get; }
}

/// <summary>
/// Root MVVM shell coordinator managing startup initialization, dirty-crash recovery,
/// Browser DoH / Port 53 / VPN / Anti-Cheat proactive advisory banners, and 5-page navigation.
/// </summary>
public sealed partial class MainShellViewModel : ObservableObject
{
    private readonly LocalizationService _localization;
    private readonly IPulseRuntimeService _runtimeService;
    private readonly PulseCatalogRepository _catalogRepository;
    private readonly AppSettingsStore _settingsStore;
    private readonly ThemeAppearanceService _themeService;
    private readonly NetworkSnapshotJournal _journal;
    private readonly BrowserDohInspector _browserDohInspector;
    private readonly Func<(bool IsActive, IReadOnlyList<string> Names)> _antiCheatDetector;

    private bool _dismissedBrowserDohBanner;
    private bool _dismissedPort53Banner;
    private bool _dismissedVpnBanner;
    private bool _dismissedAntiCheatBanner;

    [ObservableProperty]
    private ShellPageKind _selectedPage = ShellPageKind.Overview;

    [ObservableProperty]
    private ObservableObject _currentPageViewModel;

    [ObservableProperty]
    private bool _isInitialized;

    [ObservableProperty]
    private bool _showDirtyRecoveryBanner;

    [ObservableProperty]
    private string _dirtyRecoverySummary = string.Empty;

    [ObservableProperty]
    private bool _showBrowserDohBanner;

    [ObservableProperty]
    private string _browserDohBrowsersText = string.Empty;

    [ObservableProperty]
    private bool _showPort53ConflictBanner;

    [ObservableProperty]
    private string _port53OccupantName = string.Empty;

    [ObservableProperty]
    private int? _port53OccupantProcessId;

    [ObservableProperty]
    private bool _showVpnAdvisoryBanner;

    [ObservableProperty]
    private bool _showAntiCheatBanner;

    [ObservableProperty]
    private string _antiCheatNamesText = string.Empty;

    [ObservableProperty]
    private bool _isNotificationPanelExpanded;

    [ObservableProperty]
    private bool _isSimpleMode = true;

    public MainShellViewModel(
        LocalizationService localization,
        IPulseRuntimeService runtimeService,
        PulseCatalogRepository catalogRepository,
        AppSettingsStore settingsStore,
        ThemeAppearanceService themeService,
        OverviewViewModel overview,
        RoutingInspectorViewModel routing,
        ServersCatalogViewModel servers,
        DiagnosticsDoctorViewModel diagnostics,
        SettingsSafetyViewModel settings,
        NetworkSnapshotJournal? journal = null,
        BrowserDohInspector? browserDohInspector = null,
        Func<(bool IsActive, IReadOnlyList<string> Names)>? antiCheatDetector = null)
    {
        ArgumentNullException.ThrowIfNull(localization);
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(catalogRepository);
        ArgumentNullException.ThrowIfNull(settingsStore);
        ArgumentNullException.ThrowIfNull(themeService);
        ArgumentNullException.ThrowIfNull(overview);
        ArgumentNullException.ThrowIfNull(routing);
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentNullException.ThrowIfNull(diagnostics);
        ArgumentNullException.ThrowIfNull(settings);

        _localization = localization;
        _runtimeService = runtimeService;
        _catalogRepository = catalogRepository;
        _settingsStore = settingsStore;
        _themeService = themeService;
        Overview = overview;
        Routing = routing;
        Servers = servers;
        Diagnostics = diagnostics;
        Settings = settings;
        _journal = journal ?? new NetworkSnapshotJournal();
        _browserDohInspector = browserDohInspector ?? new BrowserDohInspector();
        _antiCheatDetector = antiCheatDetector ?? AntiCheatGuard.DetectActiveAntiCheat;

        _currentPageViewModel = Overview;

        WireCrossViewModelCoordination();
        InitializeNavigationItems();
        _localization.CultureChanged += OnCultureChanged;
    }

    public LocalizationService Localization => _localization;

    public ThemeAppearanceService ThemeService => _themeService;

    public OverviewViewModel Overview { get; }

    public RoutingInspectorViewModel Routing { get; }

    public ServersCatalogViewModel Servers { get; }

    public DiagnosticsDoctorViewModel Diagnostics { get; }

    public SettingsSafetyViewModel Settings { get; }

    public ObservableCollection<ShellNavigationItem> NavigationItems { get; } = [];

    public string WindowTitle => _localization["App_Title"];

    public string ModeToggleButtonText => IsSimpleMode
        ? _localization["Mode_Expert"]
        : _localization["Mode_Simple"];

    public string BrowserDohBannerMessage => string.Format(
        CultureInfo.CurrentCulture,
        _localization["Banner_BrowserDoh_Desc"],
        BrowserDohBrowsersText);

    public string Port53ConflictBannerMessage => string.Format(
        CultureInfo.CurrentCulture,
        _localization["Banner_Port53_Desc"],
        Port53OccupantName,
        Port53OccupantProcessId ?? 0);

    public string AntiCheatBannerMessage => string.Format(
        CultureInfo.CurrentCulture,
        _localization["Banner_AntiCheat_Desc"],
        AntiCheatNamesText);

    public int DismissedBannerCount =>
        (_dismissedBrowserDohBanner ? 1 : 0) +
        (_dismissedPort53Banner ? 1 : 0) +
        (_dismissedVpnBanner ? 1 : 0) +
        (_dismissedAntiCheatBanner ? 1 : 0);

    public bool HasDismissedBanners => DismissedBannerCount > 0;

    /// <summary>
    /// Exposes the background startup feed sync task started by <see cref="InitializeAsync"/>, if any.
    /// </summary>
    public Task? LastStartupFeedSyncTask { get; private set; }

    public int ActiveBannerCount =>
        (ShowDirtyRecoveryBanner ? 1 : 0) +
        (ShowBrowserDohBanner ? 1 : 0) +
        (ShowPort53ConflictBanner ? 1 : 0) +
        (ShowVpnAdvisoryBanner ? 1 : 0) +
        (ShowAntiCheatBanner ? 1 : 0);

    public int AdditionalBannerCount => Math.Max(0, ActiveBannerCount - 1);

    public bool HasActiveBanners => ActiveBannerCount > 0;

    public bool HasMultipleActiveBanners => ActiveBannerCount > 1;

    public bool IsPrimaryBannerDanger => ShowAntiCheatBanner;

    public bool IsPrimaryBannerInfo =>
        !ShowAntiCheatBanner &&
        !ShowDirtyRecoveryBanner &&
        !ShowPort53ConflictBanner &&
        !ShowBrowserDohBanner &&
        ShowVpnAdvisoryBanner;

    public string PrimaryBannerTitle
    {
        get
        {
            if (ShowAntiCheatBanner)
            {
                return _localization["Banner_AntiCheat_Title"];
            }

            if (ShowDirtyRecoveryBanner)
            {
                return _localization["Banner_DirtyRecovery_Title"];
            }

            if (ShowPort53ConflictBanner)
            {
                return _localization["Banner_Port53_Title"];
            }

            if (ShowBrowserDohBanner)
            {
                return _localization["Banner_BrowserDoh_Title"];
            }

            if (ShowVpnAdvisoryBanner)
            {
                return _localization["Banner_VpnAdvisory_Title"];
            }

            return string.Empty;
        }
    }

    public string PrimaryBannerSummary
    {
        get
        {
            if (ShowAntiCheatBanner)
            {
                return AntiCheatBannerMessage;
            }

            if (ShowDirtyRecoveryBanner)
            {
                return DirtyRecoverySummary;
            }

            if (ShowPort53ConflictBanner)
            {
                return Port53ConflictBannerMessage;
            }

            if (ShowBrowserDohBanner)
            {
                return BrowserDohBannerMessage;
            }

            if (ShowVpnAdvisoryBanner)
            {
                return _localization["Banner_VpnAdvisory_Desc"];
            }

            return string.Empty;
        }
    }

    public bool PrimaryBannerHasAction =>
        !ShowAntiCheatBanner &&
        !ShowDirtyRecoveryBanner &&
        (ShowPort53ConflictBanner || ShowBrowserDohBanner);

    public string PrimaryBannerActionText
    {
        get
        {
            if (!ShowAntiCheatBanner && !ShowDirtyRecoveryBanner)
            {
                if (ShowPort53ConflictBanner)
                {
                    return _localization["Banner_Port53_Fix"];
                }

                if (ShowBrowserDohBanner)
                {
                    return _localization["Banner_BrowserDoh_Fix"];
                }
            }

            return string.Empty;
        }
    }

    public IRelayCommand? PrimaryBannerActionCommand
    {
        get
        {
            if (!ShowAntiCheatBanner && !ShowDirtyRecoveryBanner)
            {
                if (ShowPort53ConflictBanner)
                {
                    return FixPort53ConflictCommand;
                }

                if (ShowBrowserDohBanner)
                {
                    return FixBrowserDohCommand;
                }
            }

            return null;
        }
    }

    public async Task InitializeAsync(
        CliLaunchOptions? cliOptions = null,
        CancellationToken cancellationToken = default)
    {
        PulseAppSettings loadedSettings = await _settingsStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        Settings.LoadFromSettings(loadedSettings);
        ApplyLoadedBannerFlags(loadedSettings);
        Overview.LoadPersistedQuickService(loadedSettings);
        await _runtimeService.UpdateEngineOptionsAsync(loadedSettings, cancellationToken).ConfigureAwait(false);

        bool skipDirtyRestore = cliOptions is not null && (cliOptions.ApplyTunnel || !string.IsNullOrWhiteSpace(cliOptions.ConnectServerId));
        if (!skipDirtyRestore)
        {
            await CheckDirtyRecoveryAsync(cancellationToken).ConfigureAwait(false);
        }

        await _catalogRepository.InitializeAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        await Servers.LoadCatalogAsync(cancellationToken).ConfigureAwait(false);
        if (_runtimeService is HybridPulseRuntimeService hybridRuntime)
        {
            hybridRuntime.SetCatalogSnapshot(Servers.AllServers);
        }

        Overview.EnsureDefaultUpstreamsSelected(Servers.AllServers);
        IsSimpleMode = loadedSettings.SimpleModeEnabled;
        Overview.IsSimpleMode = loadedSettings.SimpleModeEnabled;
        OnPropertyChanged(nameof(ModeToggleButtonText));

        await Routing.LoadFromSettingsAsync(loadedSettings, cancellationToken).ConfigureAwait(false);
        await RefreshHostAdvisoriesAsync(cancellationToken).ConfigureAwait(false);
        await _runtimeService.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);

        if (cliOptions is not null)
        {
            await ApplyCliStartupOptionsAsync(cliOptions, cancellationToken).ConfigureAwait(false);
        }

        string feedCachePath = GetFeedCacheFilePath();
        if (loadedSettings.AutoSyncFeedsOnStartup || File.Exists(feedCachePath))
        {
            LastStartupFeedSyncTask = RunStartupFeedSyncSafelyAsync(
                feedCachePath,
                networkSyncEnabled: loadedSettings.AutoSyncFeedsOnStartup,
                cancellationToken);
        }

        IsInitialized = true;
    }

    private string GetFeedCacheFilePath()
    {
        string? settingsDir = Path.GetDirectoryName(_settingsStore.SettingsFilePath);
        string resolvedDir = !string.IsNullOrWhiteSpace(settingsDir)
            ? settingsDir
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DnsPulse");
        return Path.Combine(resolvedDir, "dynamic_bypass_domains_cache.json");
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Startup feed sync runs in the background and must never fail shell startup.")]
    private async Task RunStartupFeedSyncSafelyAsync(
        string cacheFilePath,
        bool networkSyncEnabled,
        CancellationToken cancellationToken)
    {
        try
        {
            using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(12));
            await Servers.SyncStartupFeedsAsync(
                cacheFilePath,
                networkSyncEnabled: networkSyncEnabled,
                cancellationToken: timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
        }
    }

    [RelayCommand]
    public Task ToggleSimpleModeAsync(CancellationToken cancellationToken = default)
    {
        return SetSimpleModeAsync(!IsSimpleMode, cancellationToken);
    }

    [RelayCommand]
    public Task SelectSimpleModeAsync(CancellationToken cancellationToken = default)
    {
        return SetSimpleModeAsync(true, cancellationToken);
    }

    [RelayCommand]
    public Task SelectExpertModeAsync(CancellationToken cancellationToken = default)
    {
        return SetSimpleModeAsync(false, cancellationToken);
    }

    private async Task SetSimpleModeAsync(bool simpleMode, CancellationToken cancellationToken)
    {
        if (IsSimpleMode == simpleMode && Overview.IsSimpleMode == simpleMode)
        {
            return;
        }

        IsSimpleMode = simpleMode;
        Overview.IsSimpleMode = simpleMode;
        OnPropertyChanged(nameof(ModeToggleButtonText));
        if (IsSimpleMode)
        {
            NavigateTo(ShellPageKind.Overview);
        }

        await _settingsStore.UpdateAsync(settings =>
        {
            settings.SimpleModeEnabled = IsSimpleMode;
        }, cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public void NavigateTo(ShellPageKind page)
    {
        SelectedPage = page;
        CurrentPageViewModel = page switch
        {
            ShellPageKind.Routing => Routing,
            ShellPageKind.Servers => Servers,
            ShellPageKind.Diagnostics => Diagnostics,
            ShellPageKind.Settings => Settings,
            _ => Overview
        };
    }

    [RelayCommand]
    public async Task RefreshHostAdvisoriesAsync(CancellationToken cancellationToken = default)
    {
        HostNetworkHealthSnapshot health = await _runtimeService.InspectHostHealthAsync(cancellationToken).ConfigureAwait(false);

        if (health.DetectedBrowserDohBypassBrowsers.Count > 0)
        {
            BrowserDohBrowsersText = string.Join(", ", health.DetectedBrowserDohBypassBrowsers);
            ShowBrowserDohBanner = !_dismissedBrowserDohBanner;
            OnPropertyChanged(nameof(BrowserDohBannerMessage));
        }
        else
        {
            BrowserDohBrowsersText = string.Empty;
            ShowBrowserDohBanner = false;
        }

        if (!string.IsNullOrWhiteSpace(health.Port53OccupantName) || health.Port53OccupantProcessId.HasValue)
        {
            Port53OccupantName = string.IsNullOrWhiteSpace(health.Port53OccupantName) ? "System" : health.Port53OccupantName;
            Port53OccupantProcessId = health.Port53OccupantProcessId;
            ShowPort53ConflictBanner = !_dismissedPort53Banner;
            OnPropertyChanged(nameof(Port53ConflictBannerMessage));
        }
        else
        {
            ShowPort53ConflictBanner = false;
        }

        bool hasVpnAdvisory = !health.IsSmhnrDisabled && health.ActiveInterfaceNames.Count > 1;
        ShowVpnAdvisoryBanner = hasVpnAdvisory && !_dismissedVpnBanner;

        (bool antiCheatActive, IReadOnlyList<string> antiCheatNames) = _antiCheatDetector();
        if (antiCheatActive && Settings.SelectedInterceptionMode == InterceptionMode.WfpDivertPlugin)
        {
            AntiCheatNamesText = string.Join(", ", antiCheatNames);
            ShowAntiCheatBanner = !_dismissedAntiCheatBanner;
            OnPropertyChanged(nameof(AntiCheatBannerMessage));
        }
        else
        {
            ShowAntiCheatBanner = false;
        }
    }

    [RelayCommand]
    public async Task FixBrowserDohAsync(CancellationToken cancellationToken = default)
    {
        _browserDohInspector.SetBrowserDohPoliciesDisabled(apply: true);
        ShowBrowserDohBanner = false;
        if (_dismissedBrowserDohBanner)
        {
            _dismissedBrowserDohBanner = false;
            await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
        }

        await RefreshHostAdvisoriesAsync(cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public async Task FixPort53ConflictAsync(CancellationToken cancellationToken = default)
    {
        Settings.SelectedInterceptionMode = InterceptionMode.LocalProxyPacOnly;
        await Settings.SaveSettingsAsync(cancellationToken).ConfigureAwait(false);
        ShowPort53ConflictBanner = false;
    }

    [RelayCommand]
    public async Task DismissBrowserDohBannerAsync(CancellationToken cancellationToken = default)
    {
        ShowBrowserDohBanner = false;
        _dismissedBrowserDohBanner = true;
        await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public async Task DismissPort53ConflictBannerAsync(CancellationToken cancellationToken = default)
    {
        ShowPort53ConflictBanner = false;
        _dismissedPort53Banner = true;
        await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public async Task DismissVpnAdvisoryBannerAsync(CancellationToken cancellationToken = default)
    {
        ShowVpnAdvisoryBanner = false;
        _dismissedVpnBanner = true;
        await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public Task DismissVpnAdvisoryAsync(CancellationToken cancellationToken = default)
    {
        return DismissVpnAdvisoryBannerAsync(cancellationToken);
    }

    [RelayCommand]
    public async Task DismissAntiCheatBannerAsync(CancellationToken cancellationToken = default)
    {
        ShowAntiCheatBanner = false;
        _dismissedAntiCheatBanner = true;
        await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public async Task RestoreDismissedBannersAsync(CancellationToken cancellationToken = default)
    {
        _dismissedBrowserDohBanner = false;
        _dismissedPort53Banner = false;
        _dismissedVpnBanner = false;
        _dismissedAntiCheatBanner = false;
        await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
        await RefreshHostAdvisoriesAsync(cancellationToken).ConfigureAwait(false);
    }

    [RelayCommand]
    public void DismissDirtyRecoveryBanner()
    {
        ShowDirtyRecoveryBanner = false;
    }

    [RelayCommand]
    private void ToggleNotificationPanelExpanded()
    {
        IsNotificationPanelExpanded = !IsNotificationPanelExpanded;
    }

    [RelayCommand]
    public async Task DismissAllActiveBannersAsync(CancellationToken cancellationToken = default)
    {
        bool dirtyPersist = false;
        ShowDirtyRecoveryBanner = false;
        IsNotificationPanelExpanded = false;

        if (ShowBrowserDohBanner)
        {
            ShowBrowserDohBanner = false;
            _dismissedBrowserDohBanner = true;
            dirtyPersist = true;
        }

        if (ShowPort53ConflictBanner)
        {
            ShowPort53ConflictBanner = false;
            _dismissedPort53Banner = true;
            dirtyPersist = true;
        }

        if (ShowVpnAdvisoryBanner)
        {
            ShowVpnAdvisoryBanner = false;
            _dismissedVpnBanner = true;
            dirtyPersist = true;
        }

        if (ShowAntiCheatBanner)
        {
            ShowAntiCheatBanner = false;
            _dismissedAntiCheatBanner = true;
            dirtyPersist = true;
        }

        if (dirtyPersist)
        {
            await PersistBannerDismissalFlagsAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    partial void OnShowDirtyRecoveryBannerChanged(bool value) => NotifyActiveBannerSummaryChanged();

    partial void OnShowBrowserDohBannerChanged(bool value) => NotifyActiveBannerSummaryChanged();

    partial void OnShowPort53ConflictBannerChanged(bool value) => NotifyActiveBannerSummaryChanged();

    partial void OnShowVpnAdvisoryBannerChanged(bool value) => NotifyActiveBannerSummaryChanged();

    partial void OnShowAntiCheatBannerChanged(bool value) => NotifyActiveBannerSummaryChanged();

    partial void OnDirtyRecoverySummaryChanged(string value) => NotifyActiveBannerSummaryChanged();

    partial void OnBrowserDohBrowsersTextChanged(string value) => NotifyActiveBannerSummaryChanged();

    partial void OnPort53OccupantNameChanged(string value) => NotifyActiveBannerSummaryChanged();

    partial void OnAntiCheatNamesTextChanged(string value) => NotifyActiveBannerSummaryChanged();

    private void NotifyActiveBannerSummaryChanged()
    {
        if (ActiveBannerCount <= 1 && IsNotificationPanelExpanded)
        {
            IsNotificationPanelExpanded = false;
        }

        OnPropertyChanged(nameof(ActiveBannerCount));
        OnPropertyChanged(nameof(AdditionalBannerCount));
        OnPropertyChanged(nameof(HasActiveBanners));
        OnPropertyChanged(nameof(HasMultipleActiveBanners));
        OnPropertyChanged(nameof(IsPrimaryBannerDanger));
        OnPropertyChanged(nameof(IsPrimaryBannerInfo));
        OnPropertyChanged(nameof(PrimaryBannerTitle));
        OnPropertyChanged(nameof(PrimaryBannerSummary));
        OnPropertyChanged(nameof(PrimaryBannerHasAction));
        OnPropertyChanged(nameof(PrimaryBannerActionText));
        OnPropertyChanged(nameof(PrimaryBannerActionCommand));
    }

    private void ApplyLoadedBannerFlags(PulseAppSettings settings)
    {
        _dismissedBrowserDohBanner = settings.DismissedBrowserDohBanner;
        _dismissedPort53Banner = settings.DismissedPort53Banner;
        _dismissedVpnBanner = settings.DismissedVpnBanner;
        _dismissedAntiCheatBanner = settings.DismissedAntiCheatBanner;
        NotifyDismissedBannerCountChanged();
    }

    private async Task PersistBannerDismissalFlagsAsync(CancellationToken cancellationToken)
    {
        NotifyDismissedBannerCountChanged();
        Settings.SyncPreservedBannerFlags(
            _dismissedBrowserDohBanner,
            _dismissedPort53Banner,
            _dismissedVpnBanner,
            _dismissedAntiCheatBanner);

        PulseAppSettings updated = await _settingsStore.UpdateAsync(current =>
        {
            current.DismissedBrowserDohBanner = _dismissedBrowserDohBanner;
            current.DismissedPort53Banner = _dismissedPort53Banner;
            current.DismissedVpnBanner = _dismissedVpnBanner;
            current.DismissedAntiCheatBanner = _dismissedAntiCheatBanner;
        }, cancellationToken).ConfigureAwait(false);

        Settings.SyncPreservedBannerFlags(
            updated.DismissedBrowserDohBanner,
            updated.DismissedPort53Banner,
            updated.DismissedVpnBanner,
            updated.DismissedAntiCheatBanner);
    }

    private void NotifyDismissedBannerCountChanged()
    {
        OnPropertyChanged(nameof(DismissedBannerCount));
        OnPropertyChanged(nameof(HasDismissedBanners));
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Startup dirty-crash recovery must remain non-fatal even when unprivileged.")]
    private async Task CheckDirtyRecoveryAsync(CancellationToken cancellationToken)
    {
        try
        {
            NetworkRestoredResult result = await _journal.RecoverIfDirtyAsync(cancellationToken).ConfigureAwait(false);
            if (result.HadDirtyState)
            {
                DirtyRecoverySummary = result.Summary;
                ShowDirtyRecoveryBanner = true;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            DirtyRecoverySummary = ex.Message;
            ShowDirtyRecoveryBanner = true;
        }
    }

    private async Task ApplyCliStartupOptionsAsync(CliLaunchOptions cliOptions, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(cliOptions.ConnectServerId))
        {
            DnsServerEntry? requested = Servers.AllServers.FirstOrDefault(s =>
                string.Equals(s.Id, cliOptions.ConnectServerId, StringComparison.OrdinalIgnoreCase));

            if (requested is not null)
            {
                if (TrustTierPolicy.CanServeDefaultInternet(requested.TrustTier, requested.Protocol))
                {
                    Overview.SelectedTrustedUpstream = requested;
                }
                else if (TrustTierPolicy.CanServeGeoUnlock(requested.TrustTier))
                {
                    Overview.SelectedGeoUnlockUpstream = requested;
                }
            }
        }

        if ((cliOptions.ApplyTunnel || !string.IsNullOrWhiteSpace(cliOptions.ConnectServerId)) && !Overview.IsConnected)
        {
            await Overview.ToggleConnectionAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private void WireCrossViewModelCoordination()
    {
        Overview.ConfigureContextProviders(
            () => Servers.AllServers,
            () => Settings.BuildNormalizedSettings());

        Overview.ConfigureOverviewCoordinators(
            ensureRoutingPresetHandler: async (presetId, customDomain, ct) =>
            {
                await Routing.EnablePresetByIdAsync(presetId, ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(customDomain))
                {
                    await Routing.AddCustomGeoUnlockDomainAsync(customDomain, ct).ConfigureAwait(false);
                }
            },
            fixBrowserDohHandler: FixBrowserDohAsync,
            persistQuickServiceHandler: async (serviceId, domain, ct) =>
            {
                Settings.SyncPreservedQuickService(serviceId, domain);
                await _settingsStore.UpdateAsync(current =>
                {
                    current.SelectedQuickServiceId = serviceId;
                    current.LastVerifiedTargetDomain = domain;
                }, ct).ConfigureAwait(false);
            },
            catalogEntryUpdatedHandler: Servers.ApplyProbedServerUpdate,
            persistSelectionHandler: async (strategyProfile, trustedId, geoId, ct) =>
            {
                string profileName = strategyProfile.ToString();
                Settings.SyncPreservedOverviewSelections(profileName, trustedId, geoId);
                await _settingsStore.UpdateAsync(current =>
                {
                    current.StrategyProfile = profileName;
                    current.SelectedTrustedUpstreamId = trustedId;
                    current.SelectedGeoUnlockUpstreamId = geoId;
                }, ct).ConfigureAwait(false);
            },
            switchToSafeProxyModeHandler: FixPort53ConflictAsync);

        Routing.ConfigurePersistenceHandler(async (enabledPresetIds, customGeo, customBlock, customAllow, ct) =>
        {
            Settings.SyncPreservedRoutingRules(enabledPresetIds, customGeo, customBlock, customAllow);
            await _settingsStore.UpdateAsync(current =>
            {
                current.EnabledRoutingPresetIds = [.. enabledPresetIds];
                current.CustomGeoUnlockDomains = [.. customGeo];
                current.CustomBlockRules = [.. customBlock];
                current.CustomAllowRules = [.. customAllow];
            }, ct).ConfigureAwait(false);
        });

        Overview.StrategyProfileApplied += async (_, e) =>
        {
            await Routing.ApplyStrategyProfileAsync(e.Profile).ConfigureAwait(false);
        };

        Servers.ServerActivated += (_, e) =>
        {
            DnsServerEntry entry = e.Server;
            if (entry.TrustTier == TrustTier.Tier3CustomOrSelfHosted && entry.Protocol != DnsProtocol.SniProxy)
            {
                Overview.SelectedTrustedUpstream = entry;
                Overview.SelectedGeoUnlockUpstream = entry;
            }
            else if (TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
            {
                Overview.SelectedTrustedUpstream = entry;
            }
            else if (TrustTierPolicy.CanServeGeoUnlock(entry.TrustTier))
            {
                Overview.SelectedGeoUnlockUpstream = entry;
            }

            _ = Overview.ActivateServerAndConnectAsync(entry);
        };

        Servers.FeedBypassDomainsDiscovered += async (_, e) =>
        {
            await Routing.AddCustomGeoUnlockDomainsAsync(e.Domains.Take(500)).ConfigureAwait(false);
        };

        Servers.FeedIpRangesDiscovered += (_, e) =>
        {
            Routing.ApplyImportedIpRanges(e.IpRanges.Take(500));
        };

        Servers.AutoPickFastestRequested += (_, _) =>
        {
            NavigateTo(ShellPageKind.Overview);
            _ = Overview.AutoConnectBestAsync();
        };

        Diagnostics.ConfigureTargetProvider(
            () => Overview.SelectedTrustedUpstream,
            (domain, ct) => Routing.AddCustomGeoUnlockDomainAsync(domain, ct));

        Diagnostics.OpenVpsWizardRequested += (_, _) => NavigateTo(ShellPageKind.Servers);
    }

    private void InitializeNavigationItems()
    {
        NavigationItems.Add(new ShellNavigationItem(
            ShellPageKind.Overview,
            "Nav_Overview",
            "Auto_Nav_Overview",
            "ShieldCheckmark24",
            _localization["Nav_Overview"],
            _localization["Auto_Nav_Overview"]));

        NavigationItems.Add(new ShellNavigationItem(
            ShellPageKind.Routing,
            "Nav_Routing",
            "Auto_Nav_Routing",
            "BranchFork24",
            _localization["Nav_Routing"],
            _localization["Auto_Nav_Routing"]));

        NavigationItems.Add(new ShellNavigationItem(
            ShellPageKind.Servers,
            "Nav_Servers",
            "Auto_Nav_Servers",
            "Server24",
            _localization["Nav_Servers"],
            _localization["Auto_Nav_Servers"]));

        NavigationItems.Add(new ShellNavigationItem(
            ShellPageKind.Diagnostics,
            "Nav_Diagnostics",
            "Auto_Nav_Diagnostics",
            "Stethoscope24",
            _localization["Nav_Diagnostics"],
            _localization["Auto_Nav_Diagnostics"]));

        NavigationItems.Add(new ShellNavigationItem(
            ShellPageKind.Settings,
            "Nav_Settings",
            "Auto_Nav_Settings",
            "Settings24",
            _localization["Nav_Settings"],
            _localization["Auto_Nav_Settings"]));
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        foreach (ShellNavigationItem item in NavigationItems)
        {
            item.Title = _localization[item.TitleResourceKey];
            item.AutomationName = _localization[item.AutomationResourceKey];
        }

        OnPropertyChanged(nameof(WindowTitle));
        OnPropertyChanged(nameof(ModeToggleButtonText));
        OnPropertyChanged(nameof(BrowserDohBannerMessage));
        OnPropertyChanged(nameof(Port53ConflictBannerMessage));
        OnPropertyChanged(nameof(AntiCheatBannerMessage));
        NotifyActiveBannerSummaryChanged();
    }
}
