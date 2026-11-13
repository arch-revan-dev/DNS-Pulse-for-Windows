using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Discovery;
using DnsPulse.Engine.Sidecar;
using DnsPulse.Platform.Windows.Networking;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Event arguments carrying the <see cref="RecommendedRemediation"/> that was applied.
/// </summary>
public sealed class RemediationAppliedEventArgs(RecommendedRemediation remediation) : EventArgs
{
    public RecommendedRemediation Remediation { get; } = remediation ?? throw new ArgumentNullException(nameof(remediation));
}

/// <summary>
/// ViewModel for the Diagnostics Doctor page: interactive 6-Layer Troubleshooter with
/// 1-click remediation, opt-in Advanced Network Lab subnet scanner, and LAN Gateway QR mode.
/// </summary>
public sealed partial class DiagnosticsDoctorViewModel : ObservableObject, IDisposable
{
    private readonly IPulseRuntimeService _runtimeService;
    private readonly PulseCatalogRepository _repository;
    private readonly LocalizationService _localization;
    private readonly BrowserDohInspector _browserDohInspector;
    private Func<DnsServerEntry?> _targetServerProvider = static () => null;
    private Func<string, CancellationToken, Task>? _customRemediationHandler;

    private CancellationTokenSource? _diagCts;
    private CancellationTokenSource? _labCts;
    private bool _disposed;

    [ObservableProperty]
    private ServicePresetGroup? _selectedPresetGroup;

    [ObservableProperty]
    private DomainPresetItem? _selectedPreset;

    [ObservableProperty]
    private string _customDomain = "gemini.google.com";

    [ObservableProperty]
    private bool _isDiagnosing;

    [ObservableProperty]
    private DiagnosticReport? _currentReport;

    [ObservableProperty]
    private string _remediationFeedback = string.Empty;

    [ObservableProperty]
    private bool _hasAcceptedLabDisclaimer;

    [ObservableProperty]
    private string _labCustomCidr = string.Empty;

    [ObservableProperty]
    private string _labTargetDomain = "gemini.google.com";

    [ObservableProperty]
    private bool _isScanningLab;

    [ObservableProperty]
    private string _labProgressText = string.Empty;

    [ObservableProperty]
    private bool _isLanGatewayEnabled;

    [ObservableProperty]
    private string _lanIpAddress = "192.168.1.10";

    [ObservableProperty]
    private int _lanDnsPort = 53;

    [ObservableProperty]
    private int _lanPacPort = 10809;

    [ObservableProperty]
    private int _lanProxyPort = 10808;

    [ObservableProperty]
    private LanGatewayDescriptor? _lanGateway;

    public DiagnosticsDoctorViewModel(
        IPulseRuntimeService runtimeService,
        PulseCatalogRepository repository,
        LocalizationService localization,
        BrowserDohInspector? browserDohInspector = null)
    {
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(localization);

        _runtimeService = runtimeService;
        _repository = repository;
        _localization = localization;
        _browserDohInspector = browserDohInspector ?? new BrowserDohInspector();

        _localization.CultureChanged += OnCultureChanged;

        _selectedPresetGroup = BuiltInCatalogPresets.PresetGroups[0];
        _selectedPreset = BuiltInCatalogPresets.AllPresets[0];
        LanIpAddress = DetectPrimaryLanIpv4();
    }

    public event EventHandler<RemediationAppliedEventArgs>? RemediationApplied;

    public event EventHandler? OpenVpsWizardRequested;

    public LocalizationService Localization => _localization;

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Exposed as instance property for XAML data binding.")]
    public IReadOnlyList<ServicePresetGroup> PresetGroups => BuiltInCatalogPresets.PresetGroups;

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Exposed as instance property for XAML data binding.")]
    public IReadOnlyList<DomainPresetItem> DomainPresets => BuiltInCatalogPresets.AllPresets;

    public ObservableCollection<DiagnosticLayerResult> Layers { get; } = [];

    public ObservableCollection<DnsServerEntry> LabDiscoveredNodes { get; } = [];

    public DiagnosticVerdict CurrentVerdict => CurrentReport?.Verdict ?? DiagnosticVerdict.Unknown;

    public string VerdictTitle => CurrentVerdict switch
    {
        DiagnosticVerdict.Healthy => _localization["Diag_Verdict_Healthy"],
        DiagnosticVerdict.LocalPort53Conflict => _localization["Diag_Verdict_LocalPort53Conflict"],
        DiagnosticVerdict.DnsPoisoned => _localization["Diag_Verdict_DnsPoisoned"],
        DiagnosticVerdict.EncryptedDnsDpiBlocked => _localization["Diag_Verdict_EncryptedDnsDpiBlocked"],
        DiagnosticVerdict.TlsSniDpiReset => _localization["Diag_Verdict_TlsSniDpiReset"],
        DiagnosticVerdict.IpBlockedByIsp => _localization["Diag_Verdict_IpBlockedByIsp"],
        DiagnosticVerdict.GeoBlockedByService => _localization["Diag_Verdict_GeoBlockedByService"],
        DiagnosticVerdict.TlsMitmRejected => _localization["Diag_Verdict_TlsMitmRejected"],
        DiagnosticVerdict.BrowserDohBypass => _localization["Diag_Verdict_BrowserDohBypass"],
        _ => _localization["Diag_Verdict_Unknown"]
    };

    public string VerdictReason => CurrentReport?.Reason ?? string.Empty;

    public RecommendedRemediation? RecommendedRemediation => CurrentReport?.Remediation;

    public string RemediationTitle => RecommendedRemediation is null
        ? _localization["Diag_Rem_None"]
        : RecommendedRemediation.Action switch
        {
            RemediationActionKind.SwitchToDoQOrFragmentedDoh => _localization["Diag_Rem_SwitchToDoQOrFragmentedDoh"],
            RemediationActionKind.EnableTlsSplitPacForDomain => _localization["Diag_Rem_EnableTlsSplitPacForDomain"],
            RemediationActionKind.RouteViaVerifiedGeoUnlock => _localization["Diag_Rem_RouteViaVerifiedGeoUnlock"],
            RemediationActionKind.FixLocalPort53Conflict => _localization["Diag_Rem_FixLocalPort53Conflict"],
            RemediationActionKind.DisableBrowserDohOverride => _localization["Diag_Rem_DisableBrowserDohOverride"],
            RemediationActionKind.DeploySelfHostedVps => _localization["Diag_Rem_DeploySelfHostedVps"],
            _ => _localization["Diag_Rem_None"]
        };

    public bool CanApplyRemediation => RecommendedRemediation is { Action: not RemediationActionKind.None };

    public void ConfigureTargetProvider(
        Func<DnsServerEntry?> targetServerProvider,
        Func<string, CancellationToken, Task>? geoUnlockDomainHandler = null)
    {
        ArgumentNullException.ThrowIfNull(targetServerProvider);
        _targetServerProvider = targetServerProvider;
        _customRemediationHandler = geoUnlockDomainHandler;
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Diagnostic probe errors are captured as diagnostic failure state.")]
    public async Task RunDiagnosticsAsync(CancellationToken cancellationToken = default)
    {
        if (IsDiagnosing)
        {
            return;
        }

        string domain = string.IsNullOrWhiteSpace(CustomDomain)
            ? (SelectedPreset?.Domain ?? "gemini.google.com")
            : CustomDomain.Trim();

        DnsServerEntry upstream = _targetServerProvider()
            ?? BuiltInCatalogPresets.BuildFlagshipServers().First(static s => TrustTierPolicy.CanServeDefaultInternet(s.TrustTier, s.Protocol));

        _diagCts?.Dispose();
        _diagCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        IsDiagnosing = true;
        RemediationFeedback = string.Empty;

        try
        {
            SixLayerDiagnosticEngine engine = _runtimeService.CreateDiagnosticEngine();
            DiagnosticReport report = await engine.DiagnoseAsync(domain, upstream, new DiagnosticProbeOptions(), _diagCts.Token).ConfigureAwait(false);
            ApplyReport(report);
        }
        catch (OperationCanceledException)
        {
            // Cancelled by user.
        }
        catch (Exception ex)
        {
            RemediationFeedback = ex.Message;
        }
        finally
        {
            IsDiagnosing = false;
        }
    }

    [RelayCommand]
    public void CancelDiagnostics()
    {
        _diagCts?.Cancel();
    }

    public void ApplyReport(DiagnosticReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        CurrentReport = report;
        Layers.Clear();
        foreach (DiagnosticLayerResult layer in report.Layers)
        {
            Layers.Add(layer);
        }

        NotifyVerdictPropertiesChanged();
    }

    [RelayCommand]
    public async Task ApplyRecommendedFixAsync(CancellationToken cancellationToken = default)
    {
        RecommendedRemediation? remediation = RecommendedRemediation;
        if (remediation is null || remediation.Action == RemediationActionKind.None)
        {
            return;
        }

        switch (remediation.Action)
        {
            case RemediationActionKind.DisableBrowserDohOverride:
                _browserDohInspector.SetBrowserDohPoliciesDisabled(apply: true);
                break;

            case RemediationActionKind.RouteViaVerifiedGeoUnlock:
            case RemediationActionKind.EnableTlsSplitPacForDomain:
                string target = remediation.TargetDomain ?? CustomDomain;
                if (_customRemediationHandler is not null && !string.IsNullOrWhiteSpace(target))
                {
                    await _customRemediationHandler(target, cancellationToken).ConfigureAwait(false);
                }

                break;

            case RemediationActionKind.DeploySelfHostedVps:
                OpenVpsWizardRequested?.Invoke(this, EventArgs.Empty);
                break;

            case RemediationActionKind.SwitchToDoQOrFragmentedDoh:
            case RemediationActionKind.FixLocalPort53Conflict:
                await _runtimeService.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
                break;
        }

        RemediationFeedback = RemediationTitle;
        RemediationApplied?.Invoke(this, new RemediationAppliedEventArgs(remediation));
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Subnet scan validation or probe errors are reported inline via LabProgressText.")]
    public async Task StartLabScanAsync(CancellationToken cancellationToken = default)
    {
        if (IsScanningLab || !HasAcceptedLabDisclaimer)
        {
            return;
        }

        _labCts?.Dispose();
        _labCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        IsScanningLab = true;
        LabDiscoveredNodes.Clear();

        try
        {
            AdvancedSubnetScannerService scanner = new();
            List<string> candidates = string.IsNullOrWhiteSpace(LabCustomCidr)
                ? [.. AdvancedSubnetScannerService.DefaultCuratedPrefixes.Take(2)]
                : [LabCustomCidr.Trim()];

            SubnetScanRequest request = new()
            {
                TargetDomain = string.IsNullOrWhiteSpace(LabTargetDomain) ? "gemini.google.com" : LabTargetDomain.Trim(),
                UserOptedIn = HasAcceptedLabDisclaimer,
                CandidateTargets = candidates,
                MaxConcurrency = 8
            };

            await foreach (SubnetScanProgress progress in scanner.ScanStreamAsync(request, _labCts.Token).ConfigureAwait(false))
            {
                LabProgressText = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{progress.ProbedCount}/{progress.TotalCandidateCount} (Accepted: {progress.AcceptedCount}, Excluded: {progress.ExcludedPrivateOrBogonCount})");

                if (progress.AcceptedNode is not null)
                {
                    DnsServerEntry tier4Node = progress.AcceptedNode with { TrustTier = TrustTier.Tier4ExperimentalLab };
                    LabDiscoveredNodes.Add(tier4Node);
                    await _repository.UpsertServerAsync(tier4Node, _labCts.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Scan stopped by user.
        }
        catch (Exception ex)
        {
            LabProgressText = ex.Message;
        }
        finally
        {
            IsScanningLab = false;
        }
    }

    [RelayCommand]
    public void StopLabScan()
    {
        _labCts?.Cancel();
    }

    [RelayCommand]
    public void RefreshLanGateway()
    {
        if (!IsLanGatewayEnabled)
        {
            LanGateway = null;
            return;
        }

        if (!IPAddress.TryParse(LanIpAddress, out IPAddress? parsedIp))
        {
            parsedIp = IPAddress.Loopback;
        }

        int dnsPort = Math.Clamp(LanDnsPort, 1, 65535);
        int pacPort = Math.Clamp(LanPacPort, 1, 65535);
        int proxyPort = Math.Clamp(LanProxyPort, 1, 65535);

        LanGateway = LanGatewayDescriptor.Create(parsedIp, dnsPort, pacPort, proxyPort);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _localization.CultureChanged -= OnCultureChanged;
        _diagCts?.Cancel();
        _diagCts?.Dispose();
        _diagCts = null;
        _labCts?.Cancel();
        _labCts?.Dispose();
        _labCts = null;
    }

    partial void OnSelectedPresetChanged(DomainPresetItem? value)
    {
        if (value is not null && !string.IsNullOrWhiteSpace(value.Domain))
        {
            CustomDomain = value.Domain;
        }
    }

    partial void OnIsLanGatewayEnabledChanged(bool value)
    {
        RefreshLanGateway();
    }

    private void NotifyVerdictPropertiesChanged()
    {
        OnPropertyChanged(nameof(CurrentVerdict));
        OnPropertyChanged(nameof(VerdictTitle));
        OnPropertyChanged(nameof(VerdictReason));
        OnPropertyChanged(nameof(RecommendedRemediation));
        OnPropertyChanged(nameof(RemediationTitle));
        OnPropertyChanged(nameof(CanApplyRemediation));
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        NotifyVerdictPropertiesChanged();
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "LAN IP detection gracefully falls back to loopback when offline.")]
    private static string DetectPrimaryLanIpv4()
    {
        try
        {
            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect("1.1.1.1", 53);
            if (socket.LocalEndPoint is IPEndPoint localEndPoint)
            {
                return localEndPoint.Address.ToString();
            }
        }
        catch (Exception)
        {
        }

        return IPAddress.Loopback.ToString();
    }
}
