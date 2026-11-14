using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Networking;
using Serilog;

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
/// Quick-select target service for 1-click Find &amp; Connect and real access verification.
/// </summary>
public sealed partial class QuickServiceOption : ObservableObject
{
    [ObservableProperty]
    private string _title;

    public QuickServiceOption(
        string id,
        string title,
        string defaultDomain,
        string routingPresetId,
        string? resourceKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(routingPresetId);

        Id = id;
        _title = title;
        DefaultDomain = defaultDomain;
        RoutingPresetId = routingPresetId;
        ResourceKey = resourceKey;
    }

    public string Id { get; }

    public string DefaultDomain { get; }

    public string RoutingPresetId { get; }

    public string? ResourceKey { get; }
}

/// <summary>
/// ViewModel for the Overview dashboard: Hero connection card, Quick Service 1-click Auto-Connect &amp; Verify,
/// Strategy Profile selector, and Live Telemetry Strip.
/// </summary>
public sealed partial class OverviewViewModel : ObservableObject, IDisposable
{
    private const int MaxSparklineSamples = 30;
    private const int MaxTelemetryWindowSamples = 64;

    private readonly IPulseRuntimeService _runtimeService;
    private readonly LocalizationService _localization;
    private readonly PulseCatalogRepository? _catalogRepository;
    private readonly AppSettingsStore? _settingsStore;
    private readonly BrowserDohInspector _browserDohInspector;
    private readonly List<QuickServiceOption> _quickServices = [];
    private readonly List<double> _recentTelemetryLatencies = [];
    private readonly Lock _telemetrySampleLock = new();

    private Func<IReadOnlyList<DnsServerEntry>> _catalogProvider = static () => [];
    private Func<PulseAppSettings> _settingsProvider = static () => new PulseAppSettings();
    private Func<string, string?, CancellationToken, Task>? _ensureRoutingPresetHandler;
    private Func<CancellationToken, Task>? _fixBrowserDohHandler;
    private Func<string, string, CancellationToken, Task>? _persistQuickServiceHandler;
    private Func<StrategyProfileKind, string?, string?, CancellationToken, Task>? _persistSelectionHandler;
    private Action<DnsServerEntry>? _catalogEntryUpdatedHandler;
    private string? _preferredTrustedUpstreamId;
    private string? _preferredGeoUnlockUpstreamId;
    private bool _suppressQuickServicePersistence;
    private bool _suppressSelectionPersistence;
    private bool _disposed;

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

    [ObservableProperty]
    private QuickServiceOption? _selectedQuickService;

    [ObservableProperty]
    private string _customQuickDomain = "aistudio.google.com";

    [ObservableProperty]
    private bool _isAutoFinding;

    [ObservableProperty]
    private int _autoSetupProgress;

    [ObservableProperty]
    private string _autoSetupStepMessage = string.Empty;

    [ObservableProperty]
    private bool _hasVerificationResult;

    [ObservableProperty]
    private bool _isTargetVerifiedWorking;

    [ObservableProperty]
    private string _verificationHeadline = string.Empty;

    [ObservableProperty]
    private string _verificationDetails = string.Empty;

    [ObservableProperty]
    private bool _needsBrowserDohAction;

    [ObservableProperty]
    private string _detectedBrowserDohText = string.Empty;

    public OverviewViewModel(
        IPulseRuntimeService runtimeService,
        LocalizationService localization,
        PulseCatalogRepository? catalogRepository = null,
        AppSettingsStore? settingsStore = null,
        BrowserDohInspector? browserDohInspector = null)
    {
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(localization);

        _runtimeService = runtimeService;
        _localization = localization;
        _catalogRepository = catalogRepository;
        _settingsStore = settingsStore;
        _browserDohInspector = browserDohInspector ?? new BrowserDohInspector();

        _runtimeService.StatusChanged += OnRuntimeStatusChanged;
        _runtimeService.TelemetryReceived += OnRuntimeTelemetryReceived;
        _localization.CultureChanged += OnCultureChanged;

        InitializeQuickServices();
        RebuildStrategyProfiles();
        ApplySnapshot(_runtimeService.CurrentStatus);
    }

    public event EventHandler<StrategyProfileAppliedEventArgs>? StrategyProfileApplied;

    public LocalizationService Localization => _localization;

    public IReadOnlyList<QuickServiceOption> QuickServices => _quickServices;

    public bool IsCustomQuickServiceSelected =>
        string.Equals(SelectedQuickService?.Id, "custom", StringComparison.OrdinalIgnoreCase);

    public string EffectiveTargetDomain
    {
        get
        {
            if (IsCustomQuickServiceSelected)
            {
                string cleaned = NormalizeTargetDomain(CustomQuickDomain);
                return string.IsNullOrWhiteSpace(cleaned) ? "aistudio.google.com" : cleaned;
            }

            return !string.IsNullOrWhiteSpace(SelectedQuickService?.DefaultDomain)
                ? SelectedQuickService.DefaultDomain
                : "aistudio.google.com";
        }
    }

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

    public void ConfigureOverviewCoordinators(
        Func<string, string?, CancellationToken, Task>? ensureRoutingPresetHandler = null,
        Func<CancellationToken, Task>? fixBrowserDohHandler = null,
        Func<string, string, CancellationToken, Task>? persistQuickServiceHandler = null,
        Action<DnsServerEntry>? catalogEntryUpdatedHandler = null,
        Func<StrategyProfileKind, string?, string?, CancellationToken, Task>? persistSelectionHandler = null)
    {
        _ensureRoutingPresetHandler = ensureRoutingPresetHandler;
        _fixBrowserDohHandler = fixBrowserDohHandler;
        _persistQuickServiceHandler = persistQuickServiceHandler;
        _catalogEntryUpdatedHandler = catalogEntryUpdatedHandler;
        _persistSelectionHandler = persistSelectionHandler;
    }

    public void LoadPersistedQuickService(PulseAppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        _suppressQuickServicePersistence = true;
        _suppressSelectionPersistence = true;
        try
        {
            if (!string.IsNullOrWhiteSpace(settings.LastVerifiedTargetDomain))
            {
                CustomQuickDomain = settings.LastVerifiedTargetDomain.Trim();
            }

            QuickServiceOption? match = _quickServices.FirstOrDefault(q =>
                string.Equals(q.Id, settings.SelectedQuickServiceId, StringComparison.OrdinalIgnoreCase));
            SelectedQuickService = match ?? _quickServices[0];

            if (Enum.TryParse(settings.StrategyProfile, ignoreCase: true, out StrategyProfileKind parsedProfile))
            {
                SelectedStrategyProfile = parsedProfile;
                HasActiveSmartBypassRules = parsedProfile != StrategyProfileKind.EncryptedDnsOnly;
                UpdateHeroState();
            }

            _preferredTrustedUpstreamId = settings.SelectedTrustedUpstreamId;
            _preferredGeoUnlockUpstreamId = settings.SelectedGeoUnlockUpstreamId;
        }
        finally
        {
            _suppressSelectionPersistence = false;
            _suppressQuickServicePersistence = false;
        }
    }

    public void RecordLatencySample(double p50Ms)
    {
        if (double.IsNaN(p50Ms) || double.IsInfinity(p50Ms) || p50Ms < 0)
        {
            return;
        }

        double rounded = Math.Round(p50Ms, 1);
        RunOnUiThread(() =>
        {
            LatencyP50Ms = rounded;
            if (P50SparklineSamples.Count >= MaxSparklineSamples)
            {
                P50SparklineSamples.RemoveAt(0);
            }

            P50SparklineSamples.Add(rounded);
        });
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
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Auto-connect surfaces probe or connection failures inline without crashing the shell.")]
    public async Task AutoConnectBestAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy || IsAutoFinding)
        {
            return;
        }

        IsBusy = true;
        IsAutoFinding = true;
        IsConnecting = true;
        AutoSetupProgress = 5;
        AutoSetupStepMessage = _localization["Overview_Step_FindingDns"];
        HasVerificationResult = false;
        IsTargetVerifiedWorking = false;
        NeedsBrowserDohAction = false;
        VerificationHeadline = string.Empty;
        VerificationDetails = string.Empty;
        LastErrorMessage = null;
        NotifyButtonStateChanged();

        try
        {
            string targetDomain = EffectiveTargetDomain;
            string presetId = SelectedQuickService?.RoutingPresetId ?? "google_ai_studio";

            if (SelectedStrategyProfile == StrategyProfileKind.EncryptedDnsOnly)
            {
                SelectedStrategyProfile = StrategyProfileKind.SmartSplitDnsGeo;
                HasActiveSmartBypassRules = true;
                StrategyProfileApplied?.Invoke(this, new StrategyProfileAppliedEventArgs(SelectedStrategyProfile));
            }

            if (_ensureRoutingPresetHandler is not null)
            {
                await _ensureRoutingPresetHandler(presetId, IsCustomQuickServiceSelected ? targetDomain : null, cancellationToken).ConfigureAwait(false);
            }

            IReadOnlyList<DnsServerEntry> catalog = _catalogProvider();
            EnsureDefaultUpstreamsSelected(catalog);

            PulseAppSettings settings = _settingsProvider();
            List<DnsServerEntry> candidates = await GetRankedGeoCandidatesAsync(targetDomain, catalog, cancellationToken).ConfigureAwait(false);

            DnsServerEntry? bestGeoServer = null;
            DiagnosticReport? bestFailureReport = null;

            if (candidates.Count > 0)
            {
                List<DnsServerEntry> probeBatch = [.. candidates.Take(10)];
                DiagnosticProbeOptions probeOptions = new()
                {
                    TransportProbeSamples = 2,
                    ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(settings.ProbeTimeoutMs, 1200, 3500)),
                    IncludeTlsAndApplicationProbes = true,
                    ProbeCompanionDomains = true
                };

                List<(DnsServerEntry Server, DiagnosticReport Report)> probed = [];
                using CancellationTokenSource earlyStopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                using SemaphoreSlim gate = new(4, 4);
                int completedCount = 0;
                int healthyFound = 0;
                Lock probeLock = new();

                Task[] probeTasks = new Task[probeBatch.Count];
                for (int i = 0; i < probeBatch.Count; i++)
                {
                    DnsServerEntry candidate = probeBatch[i];
                    probeTasks[i] = Task.Run(async () =>
                    {
                        await gate.WaitAsync(earlyStopCts.Token).ConfigureAwait(false);
                        try
                        {
                            DiagnosticReport? report = await RunQuickProbeAsync(candidate, targetDomain, probeOptions, earlyStopCts.Token).ConfigureAwait(false);
                            if (report is null)
                            {
                                return;
                            }

                            DnsServerEntry updated = ApplyReportToServerEntry(candidate, report);
                            if (_catalogRepository is not null)
                            {
                                await _catalogRepository.UpdateProbeMetricsAsync(updated, cancellationToken).ConfigureAwait(false);
                            }

                            _catalogEntryUpdatedHandler?.Invoke(updated);

                            bool shouldCancel;
                            lock (probeLock)
                            {
                                probed.Add((updated, report));
                                if (report.Verdict == DiagnosticVerdict.Healthy && report.TlsHandshakeSucceeded && report.CompanionPassed != false)
                                {
                                    healthyFound++;
                                }

                                completedCount++;
                                int progress = 10 + (int)Math.Round(completedCount / (double)probeBatch.Count * 45.0, MidpointRounding.AwayFromZero);
                                AutoSetupProgress = Math.Clamp(progress, 10, 55);

                                shouldCancel = healthyFound >= 2;
                            }

                            if (shouldCancel)
                            {
                                await earlyStopCts.CancelAsync().ConfigureAwait(false);
                            }
                        }
                        catch (OperationCanceledException) when (earlyStopCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                        {
                            // Early stop after finding healthy fast servers.
                        }
                        finally
                        {
                            gate.Release();
                        }
                    }, earlyStopCts.Token);
                }

                try
                {
                    await Task.WhenAll(probeTasks).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (earlyStopCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    // Early stop triggered by finding >= 2 healthy fast candidates.
                }

                (DnsServerEntry Server, DiagnosticReport Report)? healthyWinner = probed
                    .Where(static item => item.Report.Verdict == DiagnosticVerdict.Healthy
                        && item.Report.TlsHandshakeSucceeded
                        && item.Report.CompanionPassed != false)
                    .OrderBy(static item => item.Server.IsEncrypted ? 0 : 1)
                    .ThenBy(static item => item.Report.LatencyP50Ms ?? item.Server.LatencyP50Ms ?? double.MaxValue)
                    .Cast<(DnsServerEntry Server, DiagnosticReport Report)?>()
                    .FirstOrDefault();

                if (healthyWinner.HasValue)
                {
                    bestGeoServer = healthyWinner.Value.Server;
                }
                else
                {
                    (DnsServerEntry Server, DiagnosticReport Report)? sniFallback = probed
                        .Where(static item => item.Report.Verdict == DiagnosticVerdict.TlsSniDpiReset)
                        .OrderBy(static item => item.Report.LatencyP50Ms ?? item.Server.LatencyP50Ms ?? double.MaxValue)
                        .Cast<(DnsServerEntry Server, DiagnosticReport Report)?>()
                        .FirstOrDefault();

                    if (sniFallback.HasValue && settings.EnableLocalTlsSplitPac)
                    {
                        bestGeoServer = sniFallback.Value.Server;
                    }
                    else
                    {
                        bestFailureReport = probed
                            .Select(static item => item.Report)
                            .FirstOrDefault();
                    }
                }
            }

            if (bestGeoServer is null)
            {
                AutoSetupProgress = 100;
                AutoSetupStepMessage = _localization["Overview_Step_Failed"];
                HasVerificationResult = true;
                IsTargetVerifiedWorking = false;
                VerificationHeadline = _localization["Overview_Step_Failed"];
                VerificationDetails = bestFailureReport?.Reason ?? _localization["Overview_State_Degraded_Sub"];
                HasDegradedCondition = true;
                UpdateHeroState();
                await PersistQuickServiceChoiceAsync(targetDomain, cancellationToken).ConfigureAwait(false);
                return;
            }

            SelectedGeoUnlockUpstream = bestGeoServer;
            AutoSetupProgress = 65;
            AutoSetupStepMessage = _localization["Overview_Step_Connecting"];

            if (IsConnected)
            {
                await _runtimeService.DisconnectAsync(cancellationToken).ConfigureAwait(false);
            }

            List<DnsServerEntry> trustedPool =
            [
                .. catalog.Where(static s => TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol)).Take(6)
            ];

            ServiceStatusSnapshot connected = await _runtimeService.ConnectAsync(
                SelectedTrustedUpstream,
                SelectedGeoUnlockUpstream,
                trustedPool,
                settings,
                cancellationToken).ConfigureAwait(false);

            ApplySnapshot(connected);

            AutoSetupProgress = 85;
            AutoSetupStepMessage = _localization["Overview_Step_Verifying"];

            await VerifyTargetInternalAsync(targetDomain, settings, cancellationToken).ConfigureAwait(false);
            await PersistQuickServiceChoiceAsync(targetDomain, cancellationToken).ConfigureAwait(false);
            AutoSetupProgress = 100;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LastErrorMessage = string.Format(CultureInfo.CurrentCulture, _localization["Error_ConnectionFailed"], ex.Message);
            HasDegradedCondition = true;
            HasVerificationResult = true;
            IsTargetVerifiedWorking = false;
            VerificationHeadline = _localization["Overview_Step_Failed"];
            VerificationDetails = ex.Message;
            AutoSetupStepMessage = VerificationHeadline;
            UpdateHeroState();
        }
        finally
        {
            IsConnecting = false;
            IsAutoFinding = false;
            IsBusy = false;
            NotifyButtonStateChanged();
        }
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Verification command surfaces probe failures inline without crashing the shell.")]
    public async Task VerifyAccessNowAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy || IsAutoFinding)
        {
            return;
        }

        IsBusy = true;
        IsAutoFinding = true;
        AutoSetupProgress = 40;
        AutoSetupStepMessage = _localization["Overview_Step_Verifying"];

        try
        {
            string targetDomain = EffectiveTargetDomain;
            PulseAppSettings settings = _settingsProvider();
            await VerifyTargetInternalAsync(targetDomain, settings, cancellationToken).ConfigureAwait(false);
            await PersistQuickServiceChoiceAsync(targetDomain, cancellationToken).ConfigureAwait(false);
            AutoSetupProgress = 100;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            HasVerificationResult = true;
            IsTargetVerifiedWorking = false;
            VerificationHeadline = _localization["Overview_Step_Failed"];
            VerificationDetails = ex.Message;
            AutoSetupStepMessage = VerificationHeadline;
            HasDegradedCondition = true;
            UpdateHeroState();
        }
        finally
        {
            IsAutoFinding = false;
            IsBusy = false;
        }
    }

    [RelayCommand]
    public async Task FixBrowserDohFromOverviewAsync(CancellationToken cancellationToken = default)
    {
        if (_fixBrowserDohHandler is not null)
        {
            await _fixBrowserDohHandler(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            _browserDohInspector.SetBrowserDohPoliciesDisabled(apply: true);
        }

        NeedsBrowserDohAction = false;
        DetectedBrowserDohText = string.Empty;

        if (IsConnected)
        {
            await VerifyAccessNowAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Opening a URL in the default browser must not crash the UI if shell launch fails.")]
    public void OpenTargetInBrowser()
    {
        string targetDomain = EffectiveTargetDomain;
        string url = string.Create(CultureInfo.InvariantCulture, $"https://{targetDomain}/");
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
        {
            return;
        }

        try
        {
            ProcessStartInfo startInfo = new(uri.AbsoluteUri)
            {
                UseShellExecute = true
            };
            Process.Start(startInfo);
        }
        catch (Exception ex)
        {
            LastErrorMessage = ex.Message;
        }
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
        _ = PersistSelectionStateAsync(CancellationToken.None);
    }

    public void EnsureDefaultUpstreamsSelected(IReadOnlyList<DnsServerEntry> catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        _suppressSelectionPersistence = true;
        try
        {
            if (SelectedTrustedUpstream is null ||
                !TrustTierPolicy.CanServeDefaultInternet(SelectedTrustedUpstream.TrustTier, SelectedTrustedUpstream.Protocol))
            {
                DnsServerEntry? preferredTrusted = !string.IsNullOrWhiteSpace(_preferredTrustedUpstreamId)
                    ? catalog.FirstOrDefault(s =>
                        string.Equals(s.Id, _preferredTrustedUpstreamId, StringComparison.OrdinalIgnoreCase) &&
                        TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol))
                    : null;

                SelectedTrustedUpstream = preferredTrusted ?? catalog
                    .Where(static s => TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol))
                    .OrderBy(static s => s.Verdict switch
                    {
                        DiagnosticVerdict.Healthy => 0,
                        DiagnosticVerdict.TlsSniDpiReset => 1,
                        DiagnosticVerdict.Unknown => 2,
                        _ => 3
                    })
                    .ThenBy(static s => s.IsFavorite ? 0 : 1)
                    .ThenBy(static s => s.IsEncrypted ? 0 : 1)
                    .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue)
                    .FirstOrDefault();

                OnPropertyChanged(nameof(TrustedUpstreamName));
                OnPropertyChanged(nameof(TrustedUpstreamBadge));
            }

            string targetDomain = EffectiveTargetDomain;
            bool aiTarget = ServerCategoryClassifier.IsAiDomain(targetDomain);

            bool currentGeoValid = SelectedGeoUnlockUpstream is not null
                && TrustTierPolicy.CanServeGeoUnlock(SelectedGeoUnlockUpstream.TrustTier)
                && SelectedGeoUnlockUpstream.Protocol != DnsProtocol.SniProxy
                && (!aiTarget || ServerCategoryClassifier.SupportsAiDomain(SelectedGeoUnlockUpstream));

            if (!currentGeoValid)
            {
                DnsServerEntry? preferredGeo = !string.IsNullOrWhiteSpace(_preferredGeoUnlockUpstreamId)
                    ? catalog.FirstOrDefault(s =>
                        string.Equals(s.Id, _preferredGeoUnlockUpstreamId, StringComparison.OrdinalIgnoreCase) &&
                        TrustTierPolicy.CanServeGeoUnlock(s.TrustTier) &&
                        s.Protocol != DnsProtocol.SniProxy &&
                        (!aiTarget || ServerCategoryClassifier.SupportsAiDomain(s)))
                    : null;

                SelectedGeoUnlockUpstream = preferredGeo ?? catalog
                    .Where(s => TrustTierPolicy.CanServeGeoUnlock(s.TrustTier)
                        && s.Protocol != DnsProtocol.SniProxy
                        && (!aiTarget || ServerCategoryClassifier.SupportsAiDomain(s)))
                    .OrderBy(static s => s.Verdict switch
                    {
                        DiagnosticVerdict.Healthy => 0,
                        DiagnosticVerdict.TlsSniDpiReset => 1,
                        DiagnosticVerdict.Unknown => 2,
                        _ => 3
                    })
                    .ThenBy(static s => s.CompanionPassed == true ? 0 : 1)
                    .ThenBy(static s => s.IsEncrypted ? 0 : 1)
                    .ThenBy(s => ServerCategoryClassifier.HasExplicitAiTag(s) ? 0 : 1)
                    .ThenBy(static s => s.IsFavorite ? 0 : 1)
                    .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue)
                    .FirstOrDefault()
                    ?? catalog.FirstOrDefault(static s =>
                        TrustTierPolicy.CanServeGeoUnlock(s.TrustTier)
                        && s.Protocol != DnsProtocol.SniProxy
                        && !ServerCategoryClassifier.IsGamingOnlyGeoServer(s));

                OnPropertyChanged(nameof(ActiveGeoUnlockName));
            }
        }
        finally
        {
            _suppressSelectionPersistence = false;
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

        if (!snapshot.IsConnected)
        {
            lock (_telemetrySampleLock)
            {
                _recentTelemetryLatencies.Clear();
            }

            LatencyP50Ms = 0;
        }
        else if (snapshot.LatencyP50Ms is double p50 && p50 > 0)
        {
            RecordLatencySample(p50);
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
        else if (!string.IsNullOrWhiteSpace(snapshot.ActiveGeoUnlockUpstreamId))
        {
            DnsServerEntry? matched = _catalogProvider().FirstOrDefault(s =>
                string.Equals(s.Id, snapshot.ActiveGeoUnlockUpstreamId, StringComparison.OrdinalIgnoreCase));
            if (matched is not null)
            {
                SelectedGeoUnlockUpstream = matched;
            }
        }

        UpdateHeroState();
        OnPropertyChanged(nameof(TrustedUpstreamName));
        OnPropertyChanged(nameof(TrustedUpstreamBadge));
        OnPropertyChanged(nameof(ActiveGeoUnlockName));
        OnPropertyChanged(nameof(ActiveInterceptionModeLabel));
        OnPropertyChanged(nameof(RuntimeModeLabel));
        NotifyButtonStateChanged();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _runtimeService.StatusChanged -= OnRuntimeStatusChanged;
        _runtimeService.TelemetryReceived -= OnRuntimeTelemetryReceived;
        _localization.CultureChanged -= OnCultureChanged;
    }

    partial void OnSelectedTrustedUpstreamChanged(DnsServerEntry? value)
    {
        OnPropertyChanged(nameof(TrustedUpstreamName));
        OnPropertyChanged(nameof(TrustedUpstreamBadge));
        if (!_suppressSelectionPersistence && value is not null)
        {
            _preferredTrustedUpstreamId = value.Id;
            _ = PersistSelectionStateAsync(CancellationToken.None);
        }
    }

    partial void OnSelectedGeoUnlockUpstreamChanged(DnsServerEntry? value)
    {
        OnPropertyChanged(nameof(ActiveGeoUnlockName));
        if (!_suppressSelectionPersistence && value is not null)
        {
            _preferredGeoUnlockUpstreamId = value.Id;
            _ = PersistSelectionStateAsync(CancellationToken.None);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Selection persistence runs fire-and-forget from property change hooks and must remain non-fatal.")]
    private async Task PersistSelectionStateAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_persistSelectionHandler is not null)
            {
                await _persistSelectionHandler(
                    SelectedStrategyProfile,
                    SelectedTrustedUpstream?.Id,
                    SelectedGeoUnlockUpstream?.Id,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (_settingsStore is not null)
            {
                await _settingsStore.UpdateAsync(settings =>
                {
                    settings.StrategyProfile = SelectedStrategyProfile.ToString();
                    settings.SelectedTrustedUpstreamId = SelectedTrustedUpstream?.Id;
                    settings.SelectedGeoUnlockUpstreamId = SelectedGeoUnlockUpstream?.Id;
                }, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to persist overview upstream/strategy selections.");
        }
    }

    partial void OnSelectedStrategyProfileChanged(StrategyProfileKind value)
    {
        HasActiveSmartBypassRules = value != StrategyProfileKind.EncryptedDnsOnly;
        UpdateHeroState();
    }

    partial void OnSelectedQuickServiceChanged(QuickServiceOption? value)
    {
        OnPropertyChanged(nameof(IsCustomQuickServiceSelected));
        OnPropertyChanged(nameof(EffectiveTargetDomain));

        if (!_suppressQuickServicePersistence && value is not null)
        {
            _ = PersistQuickServiceChoiceAsync(EffectiveTargetDomain, CancellationToken.None);
        }
    }

    partial void OnCustomQuickDomainChanged(string value)
    {
        OnPropertyChanged(nameof(EffectiveTargetDomain));
    }

    private async Task<List<DnsServerEntry>> GetRankedGeoCandidatesAsync(
        string targetDomain,
        IReadOnlyList<DnsServerEntry> catalog,
        CancellationToken cancellationToken)
    {
        bool aiTarget = ServerCategoryClassifier.IsAiDomain(targetDomain);

        IReadOnlyList<DnsServerEntry> rawCandidates = _catalogRepository is not null
            ? await _catalogRepository.GetGeoUnlockCandidatesAsync(targetDomain, verifiedOnly: false, cancellationToken).ConfigureAwait(false)
            : catalog;

        return
        [
            .. rawCandidates
                .Where(s => TrustTierPolicy.CanServeGeoUnlock(s.TrustTier)
                    && s.Protocol != DnsProtocol.SniProxy
                    && ServerCategoryClassifier.SupportsTargetDomain(s, targetDomain)
                    && (!aiTarget || !ServerCategoryClassifier.IsGamingOnlyGeoServer(s)))
                .OrderBy(static s => s.Verdict switch
                {
                    DiagnosticVerdict.Healthy => 0,
                    DiagnosticVerdict.TlsSniDpiReset => 1,
                    DiagnosticVerdict.Unknown => 2,
                    _ => 3
                })
                .ThenBy(static s => s.CompanionPassed == true ? 0 : 1)
                .ThenBy(static s => s.IsEncrypted ? 0 : 1)
                .ThenBy(s => aiTarget && ServerCategoryClassifier.HasExplicitAiTag(s) ? 0 : 1)
                .ThenBy(static s => s.IsFavorite ? 0 : 1)
                .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue)
        ];
    }

    private async Task<DiagnosticReport?> RunQuickProbeAsync(
        DnsServerEntry upstream,
        string targetDomain,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        if (_runtimeService is HybridPulseRuntimeService hybridRuntime)
        {
            return await hybridRuntime.ResolveEffectiveQuickProbeAsync(upstream, targetDomain, options, cancellationToken).ConfigureAwait(false);
        }

        SixLayerDiagnosticEngine? engine = _runtimeService.CreateDiagnosticEngine();
        if (engine is null)
        {
            return null;
        }

        return await engine.DiagnoseAsync(targetDomain, upstream, options, cancellationToken).ConfigureAwait(false);
    }

    private async Task VerifyTargetInternalAsync(
        string targetDomain,
        PulseAppSettings settings,
        CancellationToken cancellationToken)
    {
        HostNetworkHealthSnapshot hostHealth = await _runtimeService.InspectHostHealthAsync(cancellationToken).ConfigureAwait(false);
        bool hasBrowserDoh = hostHealth.DetectedBrowserDohBypassBrowsers.Count > 0;
        NeedsBrowserDohAction = hasBrowserDoh;
        DetectedBrowserDohText = hasBrowserDoh
            ? string.Join(", ", hostHealth.DetectedBrowserDohBypassBrowsers)
            : string.Empty;

        RouteDecision? routeDecision = _runtimeService.Router?.Route(targetDomain);
        bool routeUsesGeo = SelectedStrategyProfile != StrategyProfileKind.EncryptedDnsOnly
            && (routeDecision is null || routeDecision.Zone == RouteZone.Zone3GeoUnlock);

        DnsServerEntry? upstreamToVerify = (routeUsesGeo ? SelectedGeoUnlockUpstream : SelectedTrustedUpstream)
            ?? SelectedGeoUnlockUpstream
            ?? SelectedTrustedUpstream;

        if (upstreamToVerify is null)
        {
            IReadOnlyList<DnsServerEntry> catalog = _catalogProvider();
            EnsureDefaultUpstreamsSelected(catalog);
            upstreamToVerify = SelectedGeoUnlockUpstream ?? SelectedTrustedUpstream;
        }

        DiagnosticReport? report = null;
        if (upstreamToVerify is not null)
        {
            DiagnosticProbeOptions probeOptions = new()
            {
                TransportProbeSamples = 2,
                ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(settings.ProbeTimeoutMs, 1200, 4000)),
                IncludeTlsAndApplicationProbes = true,
                ProbeCompanionDomains = true
            };
            report = await RunQuickProbeAsync(upstreamToVerify, targetDomain, probeOptions, cancellationToken).ConfigureAwait(false);
        }

        if (report is null)
        {
            bool connectedHealthy = IsConnected && _runtimeService.CurrentStatus.IsHealthy && !hasBrowserDoh;
            HasVerificationResult = true;
            IsTargetVerifiedWorking = connectedHealthy;
            VerificationHeadline = hasBrowserDoh
                ? _localization["Banner_BrowserDoh_Title"]
                : connectedHealthy
                    ? _localization["Overview_Step_Success"]
                    : _localization["Overview_Step_Failed"];
            VerificationDetails = hasBrowserDoh
                ? string.Format(CultureInfo.CurrentCulture, _localization["Banner_BrowserDoh_Desc"], DetectedBrowserDohText)
                : _runtimeService.CurrentStatus.LastErrorMessage ?? ActiveInterceptionModeLabel;
            AutoSetupStepMessage = VerificationHeadline;
            HasDegradedCondition = IsConnected && (!connectedHealthy || hasBrowserDoh);
            UpdateHeroState();
            return;
        }

        if (upstreamToVerify is not null)
        {
            DnsServerEntry updated = ApplyReportToServerEntry(upstreamToVerify, report);
            if (_catalogRepository is not null)
            {
                await _catalogRepository.UpdateProbeMetricsAsync(updated, cancellationToken).ConfigureAwait(false);
            }

            _catalogEntryUpdatedHandler?.Invoke(updated);
        }

        bool probeHealthy = report.Verdict == DiagnosticVerdict.Healthy
            && report.TlsHandshakeSucceeded
            && report.CompanionPassed != false;
        bool pacSniBypass = report.Verdict == DiagnosticVerdict.TlsSniDpiReset
            && _runtimeService.CurrentStatus.ActiveMode == InterceptionMode.LocalProxyPacOnly
            && settings.EnableLocalTlsSplitPac;
        bool targetWorking = IsConnected && (probeHealthy || pacSniBypass) && !hasBrowserDoh;

        HasVerificationResult = true;
        IsTargetVerifiedWorking = targetWorking;

        if (hasBrowserDoh)
        {
            VerificationHeadline = _localization["Banner_BrowserDoh_Title"];
            VerificationDetails = string.Format(CultureInfo.CurrentCulture, _localization["Banner_BrowserDoh_Desc"], DetectedBrowserDohText);
            HasDegradedCondition = IsConnected;
        }
        else if (!IsConnected)
        {
            VerificationHeadline = _localization["Overview_State_Disconnected"];
            VerificationDetails = report.Reason;
            HasDegradedCondition = false;
        }
        else if (targetWorking)
        {
            string latencyText = report.LatencyP50Ms.HasValue
                ? string.Create(CultureInfo.InvariantCulture, $"{report.LatencyP50Ms.Value:F0} ms")
                : "—";
            string httpText = report.HttpStatusCode.HasValue
                ? string.Create(CultureInfo.InvariantCulture, $"HTTP {report.HttpStatusCode.Value}")
                : "TLS OK";

            VerificationHeadline = _localization["Overview_Step_Success"];
            VerificationDetails = string.Create(
                CultureInfo.CurrentCulture,
                $"{targetDomain} • {upstreamToVerify?.Name} ({upstreamToVerify?.ProtocolBadge}, {latencyText}, {httpText}) • {ActiveInterceptionModeLabel}");
            HasDegradedCondition = !_runtimeService.CurrentStatus.IsHealthy;
        }
        else
        {
            VerificationHeadline = _localization["Overview_Step_Failed"];
            VerificationDetails = !string.IsNullOrWhiteSpace(report.Reason)
                ? report.Reason
                : report.Remediation.Title;
            HasDegradedCondition = true;
        }

        AutoSetupStepMessage = VerificationHeadline;
        UpdateHeroState();

        Log.Information(
            "Target verification completed: Target={Target}, Upstream={UpstreamId}, Connected={IsConnected}, Mode={Mode}, Working={Working}, Verdict={Verdict}, Reason={Reason}",
            targetDomain,
            upstreamToVerify?.Id ?? "none",
            IsConnected,
            ActiveInterceptionMode,
            targetWorking,
            report.Verdict,
            report.Reason ?? string.Empty);
    }

    private async Task PersistQuickServiceChoiceAsync(string targetDomain, CancellationToken cancellationToken)
    {
        string serviceId = SelectedQuickService?.Id ?? "google_ai_studio";
        if (_persistQuickServiceHandler is not null)
        {
            await _persistQuickServiceHandler(serviceId, targetDomain, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (_settingsStore is not null)
        {
            await _settingsStore.UpdateAsync(settings =>
            {
                settings.SelectedQuickServiceId = serviceId;
                settings.LastVerifiedTargetDomain = targetDomain;
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    private static DnsServerEntry ApplyReportToServerEntry(DnsServerEntry server, DiagnosticReport report)
    {
        int successRate = (int)Math.Round(Math.Clamp(100.0 - report.PacketLossPercent, 0.0, 100.0), MidpointRounding.AwayFromZero);
        List<int> updatedHistory = [.. server.HistoryMs];
        if (report.LatencyP50Ms is double p50)
        {
            updatedHistory.Add((int)Math.Round(p50, MidpointRounding.AwayFromZero));
            if (updatedHistory.Count > 20)
            {
                updatedHistory.RemoveRange(0, updatedHistory.Count - 20);
            }
        }

        double? minLatency = server.MinLatencyMs;
        if (report.LatencyP50Ms is double currentLatency)
        {
            minLatency = minLatency.HasValue
                ? Math.Min(minLatency.Value, currentLatency)
                : currentLatency;
        }

        double? avgLatency = updatedHistory.Count > 0 ? updatedHistory.Average() : server.AvgLatencyMs;
        string[] resolvedStrings = new string[report.ResolvedAddresses.Count];
        for (int i = 0; i < report.ResolvedAddresses.Count; i++)
        {
            resolvedStrings[i] = report.ResolvedAddresses[i].ToString();
        }

        return server with
        {
            LastLatencyMs = report.LatencyP50Ms,
            MinLatencyMs = minLatency,
            AvgLatencyMs = avgLatency,
            LatencyP50Ms = report.LatencyP50Ms,
            LatencyP95Ms = report.LatencyP95Ms,
            JitterMs = report.JitterMs,
            SuccessRatePercent = successRate,
            Verdict = report.Verdict,
            VerdictReason = report.Reason,
            ResolvedIps = resolvedStrings,
            CompanionPassed = report.CompanionPassed,
            Port443Ok = report.TlsHandshakeSucceeded ? true : server.Port443Ok,
            HttpStatus = report.HttpStatusCode,
            LastCheckedDomain = report.TargetDomain,
            LastCheckedAt = report.StartedAtUtc,
            HistoryMs = updatedHistory
        };
    }

    private static string NormalizeTargetDomain(string? rawInput)
    {
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            return string.Empty;
        }

        string trimmed = rawInput.Trim();
        if (trimmed.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? parsed))
        {
            return parsed.Host.TrimEnd('.');
        }

        int slashIdx = trimmed.IndexOf('/', StringComparison.Ordinal);
        if (slashIdx >= 0)
        {
            trimmed = trimmed[..slashIdx];
        }

        int colonIdx = trimmed.IndexOf(':', StringComparison.Ordinal);
        if (colonIdx >= 0)
        {
            trimmed = trimmed[..colonIdx];
        }

        return trimmed.Trim().TrimEnd('.');
    }

    private static void RunOnUiThread(Action action)
    {
        Dispatcher? dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is not null && !dispatcher.CheckAccess())
        {
            _ = dispatcher.BeginInvoke(action);
            return;
        }

        action();
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

    private void InitializeQuickServices()
    {
        _quickServices.Clear();
        _quickServices.Add(new QuickServiceOption(
            "google_ai_studio",
            _localization["Overview_QuickService_AiStudio"],
            "aistudio.google.com",
            "google_ai_studio",
            "Overview_QuickService_AiStudio"));
        _quickServices.Add(new QuickServiceOption(
            "gemini",
            "Google Gemini",
            "gemini.google.com",
            "google_ai_studio"));
        _quickServices.Add(new QuickServiceOption(
            "chatgpt",
            _localization["Overview_QuickService_ChatGpt"],
            "chatgpt.com",
            "openai",
            "Overview_QuickService_ChatGpt"));
        _quickServices.Add(new QuickServiceOption(
            "claude",
            _localization["Overview_QuickService_Claude"],
            "claude.ai",
            "claude",
            "Overview_QuickService_Claude"));
        _quickServices.Add(new QuickServiceOption(
            "youtube",
            _localization["Overview_QuickService_YouTube"],
            "youtube.com",
            "youtube",
            "Overview_QuickService_YouTube"));
        _quickServices.Add(new QuickServiceOption(
            "discord",
            _localization["Overview_QuickService_Discord"],
            "discord.com",
            "discord",
            "Overview_QuickService_Discord"));
        _quickServices.Add(new QuickServiceOption(
            "spotify",
            _localization["Overview_QuickService_Spotify"],
            "open.spotify.com",
            "spotify",
            "Overview_QuickService_Spotify"));
        _quickServices.Add(new QuickServiceOption(
            "gaming",
            _localization["Overview_QuickService_Gaming"],
            "xbox.com",
            "gaming",
            "Overview_QuickService_Gaming"));
        _quickServices.Add(new QuickServiceOption(
            "custom",
            _localization["Overview_QuickService_Custom"],
            string.Empty,
            "custom",
            "Overview_QuickService_Custom"));

        _suppressQuickServicePersistence = true;
        try
        {
            SelectedQuickService = _quickServices[0];
        }
        finally
        {
            _suppressQuickServicePersistence = false;
        }
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

    private void OnRuntimeTelemetryReceived(object? sender, DnsQueryTelemetryEventArgs e)
    {
        double? statusP50 = _runtimeService.CurrentStatus.LatencyP50Ms;
        double sampleToRecord;

        if (statusP50 is double authoritativeP50 && authoritativeP50 > 0)
        {
            sampleToRecord = authoritativeP50;
        }
        else
        {
            double eventLatency = e.TelemetryEvent.LatencyMs;
            if (double.IsNaN(eventLatency) || double.IsInfinity(eventLatency) || eventLatency < 0)
            {
                return;
            }

            lock (_telemetrySampleLock)
            {
                if (_recentTelemetryLatencies.Count >= MaxTelemetryWindowSamples)
                {
                    _recentTelemetryLatencies.RemoveAt(0);
                }

                _recentTelemetryLatencies.Add(eventLatency);
                double[] sorted = [.. _recentTelemetryLatencies];
                Array.Sort(sorted);
                int mid = sorted.Length / 2;
                sampleToRecord = (sorted.Length & 1) == 1
                    ? sorted[mid]
                    : (sorted[mid - 1] + sorted[mid]) / 2.0;
            }
        }

        RecordLatencySample(sampleToRecord);
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        foreach (QuickServiceOption item in _quickServices)
        {
            if (!string.IsNullOrWhiteSpace(item.ResourceKey))
            {
                item.Title = _localization[item.ResourceKey];
            }
        }

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
