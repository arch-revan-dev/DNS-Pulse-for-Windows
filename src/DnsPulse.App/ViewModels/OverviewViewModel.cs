using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Event arguments raised when a strategy profile is applied.
/// </summary>
public sealed class StrategyProfileAppliedEventArgs(StrategyProfileKind profile) : EventArgs
{
    public StrategyProfileKind Profile { get; } = profile;
}

/// <summary>
/// Connection status state displayed in the Overview hero card.
/// </summary>
public enum HeroConnectionState
{
    Disconnected = 0,
    Protected = 1,
    SmartBypassActive = 2,
    Degraded = 3
}

/// <summary>
/// High-level routing and anti-DPI strategy profile selectable from the Overview page.
/// </summary>
public enum StrategyProfileKind
{
    EncryptedDnsOnly = 0,
    SmartSplitDnsGeo = 1,
    AntiDpiHybrid = 2,
    Custom = 3
}

/// <summary>
/// Localized descriptor for a <see cref="StrategyProfileKind"/> option.
/// </summary>
public sealed record StrategyProfileOption(
    StrategyProfileKind Profile,
    string Title,
    string Description);

/// <summary>
/// ViewModel for the Overview dashboard: Hero connection card, single large Connect/Disconnect CTA,
/// Strategy Profile selector, and Live Telemetry Strip.
/// </summary>
public sealed partial class OverviewViewModel : ObservableObject
{
    private const int MaxSparklineSamples = 30;

    private readonly IPulseRuntimeService _runtimeService;
    private readonly LocalizationService _localization;
    private Func<IReadOnlyList<DnsServerEntry>> _catalogProvider = static () => [];
    private Func<PulseAppSettings> _settingsProvider = static () => new PulseAppSettings();

    [ObservableProperty]
    private HeroConnectionState _heroState = HeroConnectionState.Disconnected;

    [ObservableProperty]
    private bool _isConnected;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _isConnecting;

    [ObservableProperty]
    private bool _isDisconnecting;

    [ObservableProperty]
    private StrategyProfileKind _selectedStrategyProfile = StrategyProfileKind.SmartSplitDnsGeo;

    [ObservableProperty]
    private DnsServerEntry? _selectedTrustedUpstream;

    [ObservableProperty]
    private DnsServerEntry? _selectedGeoUnlockUpstream;

    [ObservableProperty]
    private double _latencyP50Ms;

    [ObservableProperty]
    private double _cacheHitRatePercent;

    [ObservableProperty]
    private double _queriesPerMinute;

    [ObservableProperty]
    private InterceptionMode _activeInterceptionMode = InterceptionMode.None;

    [ObservableProperty]
    private bool _isServiceMode;

    [ObservableProperty]
    private string? _lastErrorMessage;

    [ObservableProperty]
    private bool _hasActiveSmartBypassRules = true;

    [ObservableProperty]
    private bool _hasDegradedCondition;

    public OverviewViewModel(
        IPulseRuntimeService runtimeService,
        LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(localization);

        _runtimeService = runtimeService;
        _localization = localization;

        _runtimeService.StatusChanged += OnRuntimeStatusChanged;
        _localization.CultureChanged += OnCultureChanged;

        RebuildStrategyProfiles();
        ApplySnapshot(_runtimeService.CurrentStatus);
    }

    public event EventHandler<StrategyProfileAppliedEventArgs>? StrategyProfileApplied;

    public LocalizationService Localization => _localization;

    public ObservableCollection<double> P50SparklineSamples { get; } = [];

    public ObservableCollection<StrategyProfileOption> StrategyProfiles { get; } = [];

    public string HeroStatusTitle => HeroState switch
    {
        HeroConnectionState.Protected => _localization["Overview_State_Protected"],
        HeroConnectionState.SmartBypassActive => _localization["Overview_State_SmartBypass"],
        HeroConnectionState.Degraded => _localization["Overview_State_Degraded"],
        _ => _localization["Overview_State_Disconnected"]
    };

    public string HeroStatusSubtitle => HeroState switch
    {
        HeroConnectionState.Protected => _localization["Overview_State_Protected_Sub"],
        HeroConnectionState.SmartBypassActive => _localization["Overview_State_SmartBypass_Sub"],
        HeroConnectionState.Degraded => _localization["Overview_State_Degraded_Sub"],
        _ => _localization["Overview_State_Disconnected_Sub"]
    };

    public string ConnectButtonText
    {
        get
        {
            if (IsConnecting)
            {
                return _localization["Overview_CTA_Connecting"];
            }

            if (IsDisconnecting)
            {
                return _localization["Overview_CTA_Disconnecting"];
            }

            return IsConnected
                ? _localization["Overview_CTA_Disconnect"]
                : _localization["Overview_CTA_Connect"];
        }
    }

    public string TrustedUpstreamName => SelectedTrustedUpstream?.Name ?? _localization["Overview_NoneSelected"];

    public string TrustedUpstreamBadge => SelectedTrustedUpstream?.ProtocolBadge ?? "—";

    public string ActiveGeoUnlockName => SelectedGeoUnlockUpstream?.Name ?? _localization["Overview_NoneSelected"];

    public string ActiveInterceptionModeLabel => ActiveInterceptionMode switch
    {
        InterceptionMode.AdapterDns => _localization["Settings_Mode_AdapterDns"],
        InterceptionMode.SplitNrpt => _localization["Settings_Mode_SplitNrpt"],
        InterceptionMode.LocalProxyPacOnly => _localization["Settings_Mode_LocalProxyPacOnly"],
        InterceptionMode.WfpDivertPlugin => _localization["Settings_Mode_WfpDivertPlugin"],
        _ => _localization["Overview_State_Disconnected"]
    };

    public string RuntimeModeLabel => IsServiceMode
        ? _localization["Overview_Runtime_Service"]
        : _localization["Overview_Runtime_Portable"];

    public void ConfigureContextProviders(
        Func<IReadOnlyList<DnsServerEntry>> catalogProvider,
        Func<PulseAppSettings> settingsProvider)
    {
        ArgumentNullException.ThrowIfNull(catalogProvider);
        ArgumentNullException.ThrowIfNull(settingsProvider);

        _catalogProvider = catalogProvider;
        _settingsProvider = settingsProvider;
    }

    public void RecordLatencySample(double p50Ms)
    {
        if (double.IsNaN(p50Ms) || double.IsInfinity(p50Ms) || p50Ms < 0)
        {
            return;
        }

        LatencyP50Ms = Math.Round(p50Ms, 1);
        if (P50SparklineSamples.Count >= MaxSparklineSamples)
        {
            P50SparklineSamples.RemoveAt(0);
        }

        P50SparklineSamples.Add(LatencyP50Ms);
    }

    public void SetDegradedCondition(bool degraded, string? reason = null)
    {
        HasDegradedCondition = degraded;
        if (!string.IsNullOrWhiteSpace(reason))
        {
            LastErrorMessage = reason;
        }

        UpdateHeroState();
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "UI connection command surfaces failures into LastErrorMessage without crashing the shell.")]
    public async Task ToggleConnectionAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        LastErrorMessage = null;

        try
        {
            if (IsConnected)
            {
                IsDisconnecting = true;
                NotifyButtonStateChanged();
                ServiceStatusSnapshot disconnected = await _runtimeService.DisconnectAsync(cancellationToken).ConfigureAwait(false);
                ApplySnapshot(disconnected);
            }
            else
            {
                IsConnecting = true;
                NotifyButtonStateChanged();

                IReadOnlyList<DnsServerEntry> catalog = _catalogProvider();
                EnsureDefaultUpstreamsSelected(catalog);

                List<DnsServerEntry> trustedPool =
                [
                    .. catalog.Where(static s => TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol)).Take(6)
                ];

                PulseAppSettings settings = _settingsProvider();
                ServiceStatusSnapshot connected = await _runtimeService.ConnectAsync(
                    SelectedTrustedUpstream,
                    SelectedStrategyProfile == StrategyProfileKind.EncryptedDnsOnly ? null : SelectedGeoUnlockUpstream,
                    trustedPool,
                    settings,
                    cancellationToken).ConfigureAwait(false);

                ApplySnapshot(connected);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LastErrorMessage = string.Format(CultureInfo.CurrentCulture, _localization["Error_ConnectionFailed"], ex.Message);
            HasDegradedCondition = true;
            UpdateHeroState();
        }
        finally
        {
            IsConnecting = false;
            IsDisconnecting = false;
            IsBusy = false;
            NotifyButtonStateChanged();
        }
    }

    [RelayCommand]
    public async Task RotateUpstreamAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<DnsServerEntry> catalog = _catalogProvider();
        DnsServerEntry? next = await _runtimeService.RotateUpstreamAsync(catalog, cancellationToken).ConfigureAwait(false);
        if (next is not null)
        {
            SelectedTrustedUpstream = next;
            OnPropertyChanged(nameof(TrustedUpstreamName));
            OnPropertyChanged(nameof(TrustedUpstreamBadge));
        }
    }

    [RelayCommand]
    public async Task RefreshTelemetryAsync(CancellationToken cancellationToken = default)
    {
        ServiceStatusSnapshot snapshot = await _runtimeService.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
        ApplySnapshot(snapshot);
    }

    [RelayCommand]
    public void SelectStrategyProfile(StrategyProfileKind profile)
    {
        if (SelectedStrategyProfile == profile)
        {
            return;
        }

        SelectedStrategyProfile = profile;
        HasActiveSmartBypassRules = profile != StrategyProfileKind.EncryptedDnsOnly;
        UpdateHeroState();
        StrategyProfileApplied?.Invoke(this, new StrategyProfileAppliedEventArgs(profile));
    }

    public void EnsureDefaultUpstreamsSelected(IReadOnlyList<DnsServerEntry> catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        if (SelectedTrustedUpstream is null ||
            !TrustTierPolicy.CanServeDefaultInternet(SelectedTrustedUpstream.TrustTier, SelectedTrustedUpstream.Protocol))
        {
            SelectedTrustedUpstream = catalog.FirstOrDefault(static s =>
                s.IsFavorite && TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol))
                ?? catalog.FirstOrDefault(static s =>
                    TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol));

            OnPropertyChanged(nameof(TrustedUpstreamName));
            OnPropertyChanged(nameof(TrustedUpstreamBadge));
        }

        if (SelectedGeoUnlockUpstream is null)
        {
            SelectedGeoUnlockUpstream = catalog.FirstOrDefault(static s =>
                s.IsFavorite && s.TrustTier == TrustTier.Tier2VerifiedGeoUnlock)
                ?? catalog.FirstOrDefault(static s => s.TrustTier == TrustTier.Tier2VerifiedGeoUnlock);

            OnPropertyChanged(nameof(ActiveGeoUnlockName));
        }
    }

    public void ApplySnapshot(ServiceStatusSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        IsConnected = snapshot.IsConnected;
        ActiveInterceptionMode = snapshot.ActiveMode;
        CacheHitRatePercent = Math.Round(snapshot.CacheHitRatePercent, 1);
        QueriesPerMinute = Math.Round(snapshot.QueriesPerMinute, 1);
        IsServiceMode = _runtimeService.IsServiceMode;
        if (!string.IsNullOrWhiteSpace(snapshot.LastErrorMessage))
        {
            LastErrorMessage = snapshot.LastErrorMessage;
        }

        HasDegradedCondition = snapshot.IsConnected && (!snapshot.IsHealthy || snapshot.DirtyRecoveryPending);

        if (_runtimeService.ActiveTrustedUpstream is not null)
        {
            SelectedTrustedUpstream = _runtimeService.ActiveTrustedUpstream;
        }

        if (_runtimeService.ActiveGeoUnlockUpstream is not null)
        {
            SelectedGeoUnlockUpstream = _runtimeService.ActiveGeoUnlockUpstream;
        }

        UpdateHeroState();
        OnPropertyChanged(nameof(TrustedUpstreamName));
        OnPropertyChanged(nameof(TrustedUpstreamBadge));
        OnPropertyChanged(nameof(ActiveGeoUnlockName));
        OnPropertyChanged(nameof(ActiveInterceptionModeLabel));
        OnPropertyChanged(nameof(RuntimeModeLabel));
        NotifyButtonStateChanged();
    }

    partial void OnSelectedTrustedUpstreamChanged(DnsServerEntry? value)
    {
        OnPropertyChanged(nameof(TrustedUpstreamName));
        OnPropertyChanged(nameof(TrustedUpstreamBadge));
    }

    partial void OnSelectedGeoUnlockUpstreamChanged(DnsServerEntry? value)
    {
        OnPropertyChanged(nameof(ActiveGeoUnlockName));
    }

    partial void OnSelectedStrategyProfileChanged(StrategyProfileKind value)
    {
        HasActiveSmartBypassRules = value != StrategyProfileKind.EncryptedDnsOnly;
        UpdateHeroState();
    }

    private void UpdateHeroState()
    {
        HeroState = !IsConnected
            ? HeroConnectionState.Disconnected
            : HasDegradedCondition
                ? HeroConnectionState.Degraded
                : (HasActiveSmartBypassRules && SelectedStrategyProfile != StrategyProfileKind.EncryptedDnsOnly)
                    ? HeroConnectionState.SmartBypassActive
                    : HeroConnectionState.Protected;

        OnPropertyChanged(nameof(HeroStatusTitle));
        OnPropertyChanged(nameof(HeroStatusSubtitle));
    }

    private void NotifyButtonStateChanged()
    {
        OnPropertyChanged(nameof(ConnectButtonText));
    }

    private void RebuildStrategyProfiles()
    {
        StrategyProfiles.Clear();
        StrategyProfiles.Add(new StrategyProfileOption(
            StrategyProfileKind.EncryptedDnsOnly,
            _localization["Overview_Profile_EncryptedOnly"],
            _localization["Overview_Profile_EncryptedOnly_Desc"]));
        StrategyProfiles.Add(new StrategyProfileOption(
            StrategyProfileKind.SmartSplitDnsGeo,
            _localization["Overview_Profile_SmartSplitGeo"],
            _localization["Overview_Profile_SmartSplitGeo_Desc"]));
        StrategyProfiles.Add(new StrategyProfileOption(
            StrategyProfileKind.AntiDpiHybrid,
            _localization["Overview_Profile_AntiDpiHybrid"],
            _localization["Overview_Profile_AntiDpiHybrid_Desc"]));
        StrategyProfiles.Add(new StrategyProfileOption(
            StrategyProfileKind.Custom,
            _localization["Overview_Profile_Custom"],
            _localization["Overview_Profile_Custom_Desc"]));
    }

    private void OnRuntimeStatusChanged(object? sender, RuntimeStatusChangedEventArgs e)
    {
        ApplySnapshot(e.Snapshot);
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        RebuildStrategyProfiles();
        OnPropertyChanged(nameof(HeroStatusTitle));
        OnPropertyChanged(nameof(HeroStatusSubtitle));
        OnPropertyChanged(nameof(ConnectButtonText));
        OnPropertyChanged(nameof(TrustedUpstreamName));
        OnPropertyChanged(nameof(ActiveGeoUnlockName));
        OnPropertyChanged(nameof(ActiveInterceptionModeLabel));
        OnPropertyChanged(nameof(RuntimeModeLabel));
    }
}
