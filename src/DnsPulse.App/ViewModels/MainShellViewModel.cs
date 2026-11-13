using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
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

    public async Task InitializeAsync(
        CliLaunchOptions? cliOptions = null,
        CancellationToken cancellationToken = default)
    {
        PulseAppSettings loadedSettings = await _settingsStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        Settings.LoadFromSettings(loadedSettings);

        bool skipDirtyRestore = cliOptions is not null && (cliOptions.ApplyTunnel || !string.IsNullOrWhiteSpace(cliOptions.ConnectServerId));
        if (!skipDirtyRestore)
        {
            await CheckDirtyRecoveryAsync(cancellationToken).ConfigureAwait(false);
        }

        await _catalogRepository.InitializeAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        await Servers.LoadCatalogAsync(cancellationToken).ConfigureAwait(false);
        Overview.EnsureDefaultUpstreamsSelected(Servers.AllServers);

        await Routing.PushRouterConfigurationAsync(cancellationToken).ConfigureAwait(false);
        await RefreshHostAdvisoriesAsync(cancellationToken).ConfigureAwait(false);
        await _runtimeService.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);

        if (cliOptions is not null)
        {
            await ApplyCliStartupOptionsAsync(cliOptions, cancellationToken).ConfigureAwait(false);
        }

        IsInitialized = true;
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
            ShowBrowserDohBanner = true;
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
            ShowPort53ConflictBanner = true;
            OnPropertyChanged(nameof(Port53ConflictBannerMessage));
        }
        else
        {
            ShowPort53ConflictBanner = false;
        }

        ShowVpnAdvisoryBanner = !health.IsSmhnrDisabled && health.ActiveInterfaceNames.Count > 1;

        (bool antiCheatActive, IReadOnlyList<string> antiCheatNames) = _antiCheatDetector();
        if (antiCheatActive && Settings.SelectedInterceptionMode == InterceptionMode.WfpDivertPlugin)
        {
            AntiCheatNamesText = string.Join(", ", antiCheatNames);
            ShowAntiCheatBanner = true;
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
    public void DismissVpnAdvisory()
    {
        ShowVpnAdvisoryBanner = false;
    }

    [RelayCommand]
    public void DismissAntiCheatBanner()
    {
        ShowAntiCheatBanner = false;
    }

    [RelayCommand]
    public void DismissDirtyRecoveryBanner()
    {
        ShowDirtyRecoveryBanner = false;
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

        Overview.StrategyProfileApplied += async (_, e) =>
        {
            await Routing.ApplyStrategyProfileAsync(e.Profile).ConfigureAwait(false);
        };

        Servers.ServerActivated += (_, e) =>
        {
            DnsServerEntry entry = e.Server;
            if (TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
            {
                Overview.SelectedTrustedUpstream = entry;
            }
            else if (TrustTierPolicy.CanServeGeoUnlock(entry.TrustTier))
            {
                Overview.SelectedGeoUnlockUpstream = entry;
            }
        };

        Servers.FeedBypassDomainsDiscovered += async (_, e) =>
        {
            foreach (string domain in e.Domains.Take(50))
            {
                await Routing.AddCustomGeoUnlockDomainAsync(domain).ConfigureAwait(false);
            }
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
        OnPropertyChanged(nameof(BrowserDohBannerMessage));
        OnPropertyChanged(nameof(Port53ConflictBannerMessage));
        OnPropertyChanged(nameof(AntiCheatBannerMessage));
    }
}
