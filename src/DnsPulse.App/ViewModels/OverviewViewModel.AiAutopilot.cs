using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using Serilog;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Live verification state for a single AI service displayed in the Simple Mode readiness strip.
/// </summary>
public sealed partial class AiServiceReadinessItem : ObservableObject
{
    [ObservableProperty]
    private bool _isChecking;

    [ObservableProperty]
    private bool? _isAccessible;

    [ObservableProperty]
    private string _statusDetail;

    [ObservableProperty]
    private string _resolvedIp = string.Empty;

    public AiServiceReadinessItem(string id, string displayName, string targetDomain, string initialDetail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDomain);

        Id = id;
        DisplayName = displayName;
        TargetDomain = targetDomain;
        _statusDetail = initialDetail;
    }

    public string Id { get; }

    public string DisplayName { get; }

    public string TargetDomain { get; }

    public bool IsHealthy => IsAccessible == true;

    public bool IsBlocked => IsAccessible == false;

    partial void OnIsAccessibleChanged(bool? value)
    {
        OnPropertyChanged(nameof(IsHealthy));
        OnPropertyChanged(nameof(IsBlocked));
    }
}

public sealed partial class OverviewViewModel
{
    private static readonly TimeSpan WatchdogProbeInterval = TimeSpan.FromSeconds(45);
    private const double WatchdogLatencyDegradationMs = 2500.0;

    private int _boundProxyPort;
    private int _boundPacPort;

    [ObservableProperty]
    private bool _isSimpleMode = true;

    [ObservableProperty]
    private bool _isWatchdogActive;

    [ObservableProperty]
    private bool _isCheckingAiServices;

    [ObservableProperty]
    private string _aiAppActionStatus = string.Empty;

    [ObservableProperty]
    private string _watchdogStatusSummary = string.Empty;

    public ObservableCollection<AiAppItemViewModel> DetectedAiApps { get; } = [];

    public ObservableCollection<AiServiceReadinessItem> AiServiceChecks { get; } = [];

    public bool IsElevated => _runtimeService.IsElevated;

    public bool NeedsAdminElevation => !IsElevated;

    public string SimplePrimaryButtonText
    {
        get
        {
            if (IsAutoFinding || IsConnecting)
            {
                return _localization["Simple_Btn_Working"];
            }

            return IsConnected
                ? _localization["Simple_Btn_Disable"]
                : _localization["Simple_Btn_Enable"];
        }
    }

    public string LocalProxyEndpointText
    {
        get
        {
            int effectivePort = _boundProxyPort > 0 ? _boundProxyPort : 18753;
            int effectivePac = _boundPacPort > 0 ? _boundPacPort : 18754;
            string endpoint = string.Create(CultureInfo.InvariantCulture, $"127.0.0.1:{effectivePort} · PAC :{effectivePac}");
            return string.Format(CultureInfo.CurrentCulture, _localization["Simple_Proxy_Endpoint"], endpoint);
        }
    }

    public string AdapterDnsStatusSummary
    {
        get
        {
            ServiceStatusSnapshot status = _runtimeService.CurrentStatus;
            if (!status.IsConnected)
            {
                return IsElevated
                    ? _localization["Simple_Adapter_Ready"]
                    : _localization["Simple_Adapter_AdminNeeded"];
            }

            if (!string.IsNullOrWhiteSpace(status.InterceptionStatusDetail))
            {
                return status.InterceptionStatusDetail;
            }

            if (status.ActiveMode == InterceptionMode.AdapterDns)
            {
                string loopback = string.IsNullOrWhiteSpace(status.ActiveLoopbackIp) ? "127.0.0.1" : status.ActiveLoopbackIp;
                return string.Format(CultureInfo.CurrentCulture, _localization["Simple_Adapter_Active"], loopback);
            }

            return IsElevated
                ? ActiveInterceptionModeLabel
                : _localization["Simple_Adapter_AdminNeeded"];
        }
    }

    public string ActiveNodeSubtitle
    {
        get
        {
            if (!IsConnected)
            {
                return _localization["Simple_Subtitle"];
            }

            string nodeName = SelectedGeoUnlockUpstream?.Name ?? ActiveGeoUnlockName;
            if (LatencyP50Ms > 0)
            {
                return string.Create(CultureInfo.InvariantCulture, $"{nodeName} · {LatencyP50Ms:F0} ms");
            }

            return nodeName;
        }
    }

    private void InitializeAiAutopilotState()
    {
        RefreshAiApps();
        InitializeAiServiceChecks();
    }

    private void InitializeAiServiceChecks()
    {
        if (AiServiceChecks.Count > 0)
        {
            return;
        }

        string pending = _localization["Simple_Service_Pending"];
        AiServiceChecks.Add(new AiServiceReadinessItem("antigravity", "Antigravity", "cloudcode-pa.googleapis.com", pending));
        AiServiceChecks.Add(new AiServiceReadinessItem("gemini", "Gemini", "aistudio.google.com", pending));
        AiServiceChecks.Add(new AiServiceReadinessItem("chatgpt", "ChatGPT", "chatgpt.com", pending));
        AiServiceChecks.Add(new AiServiceReadinessItem("claude", "Claude", "claude.ai", pending));
    }

    private void OnAiAutopilotStatusUpdated()
    {
        _boundProxyPort = _runtimeService.CurrentStatus.BoundProxyPort;
        _boundPacPort = _runtimeService.CurrentStatus.BoundPacPort;
        OnPropertyChanged(nameof(SimplePrimaryButtonText));
        OnPropertyChanged(nameof(LocalProxyEndpointText));
        OnPropertyChanged(nameof(AdapterDnsStatusSummary));
        OnPropertyChanged(nameof(ActiveNodeSubtitle));
        OnPropertyChanged(nameof(IsElevated));
        OnPropertyChanged(nameof(NeedsAdminElevation));

        if (!IsConnected)
        {
            if (IsWatchdogActive)
            {
                StopDynamicWatchdog();
            }

            string pending = _localization["Simple_Service_Pending"];
            foreach (AiServiceReadinessItem item in AiServiceChecks)
            {
                item.IsChecking = false;
                item.IsAccessible = null;
                item.StatusDetail = pending;
                item.ResolvedIp = string.Empty;
            }
        }
    }

    private void OnAiAutopilotCultureChanged()
    {
        RefreshAiApps();
        OnPropertyChanged(nameof(SimplePrimaryButtonText));
        OnPropertyChanged(nameof(LocalProxyEndpointText));
        OnPropertyChanged(nameof(AdapterDnsStatusSummary));
        OnPropertyChanged(nameof(ActiveNodeSubtitle));
        if (IsWatchdogActive)
        {
            WatchdogStatusSummary = _localization["Simple_Watchdog_Active"];
        }
    }

    /// <summary>
    /// One-button Simple Mode autopilot: finds the fastest verified AI Smart-DNS/SNI-Proxy node,
    /// activates Adapter DNS + NRPT + local loopback proxy, verifies all 4 AI services, and starts
    /// the dynamic health watchdog for automatic failover. Clicking again cleanly restores everything.
    /// </summary>
    [RelayCommand]
    public async Task ToggleAiAutopilotAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy || IsAutoFinding)
        {
            return;
        }

        if (IsConnected)
        {
            StopDynamicWatchdog();
            await ToggleConnectionAsync(cancellationToken).ConfigureAwait(false);
            OnPropertyChanged(nameof(SimplePrimaryButtonText));
            OnPropertyChanged(nameof(AdapterDnsStatusSummary));
            OnPropertyChanged(nameof(ActiveNodeSubtitle));
            return;
        }

        await AutoConnectBestAsync(cancellationToken).ConfigureAwait(false);
        OnPropertyChanged(nameof(SimplePrimaryButtonText));
        OnPropertyChanged(nameof(AdapterDnsStatusSummary));
        OnPropertyChanged(nameof(ActiveNodeSubtitle));

        PulseAppSettings settings = _settingsProvider();
        if (IsConnected)
        {
            if (settings.EnableDynamicAiWatchdog)
            {
                StartDynamicWatchdog();
            }

            await VerifyAllAiServicesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Probes all 4 core AI services (Antigravity, Gemini/AI Studio, ChatGPT, Claude) using the
    /// zero-false-positive 6-layer engine and active Geo-Unlock failover pool.
    /// </summary>
    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Per-service probe failures are reported cleanly in each readiness row.")]
    public async Task VerifyAllAiServicesAsync(CancellationToken cancellationToken = default)
    {
        if (IsCheckingAiServices)
        {
            return;
        }

        SixLayerDiagnosticEngine? engine = _runtimeService.CreateDiagnosticEngine();
        if (engine is null)
        {
            return;
        }

        List<DnsServerEntry> probePool = BuildActiveGeoProbePool();
        if (probePool.Count == 0)
        {
            return;
        }

        IsCheckingAiServices = true;
        string checkingText = _localization["Simple_Service_Checking"];
        foreach (AiServiceReadinessItem item in AiServiceChecks)
        {
            item.IsChecking = true;
            item.StatusDetail = checkingText;
        }

        try
        {
            PulseAppSettings settings = _settingsProvider();
            DiagnosticProbeOptions probeOptions = new()
            {
                TransportProbeSamples = 1,
                ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(settings.ProbeTimeoutMs, 1500, 4000)),
                IncludeTlsAndApplicationProbes = true,
                ProbeCompanionDomains = false
            };

            Task[] tasks = [.. AiServiceChecks.Select(item => ProbeSingleAiServiceAsync(engine, item, probePool, probeOptions, cancellationToken))];
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        finally
        {
            IsCheckingAiServices = false;
        }
    }

    /// <summary>
    /// Relaunches DNS Pulse with Windows Administrator UAC elevation so Adapter DNS and NRPT policies can be applied.
    /// </summary>
    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "UAC cancellation or launch failure must be reported cleanly instead of crashing the UI.")]
    public void RestartAsAdministrator()
    {
        string? processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return;
        }

        try
        {
            ProcessStartInfo startInfo = new()
            {
                FileName = processPath,
                UseShellExecute = true,
                Verb = "runas"
            };

            using Process? elevated = Process.Start(startInfo);
            if (elevated is not null)
            {
                System.Windows.Application.Current?.Shutdown();
            }
        }
        catch (Exception ex)
        {
            LastErrorMessage = ex.Message;
        }
    }

    /// <summary>
    /// Scans the Windows host for installed and running desktop/CLI AI applications.
    /// </summary>
    [RelayCommand]
    public void RefreshAiApps()
    {
        IReadOnlyList<DetectedAiAppStatus> statuses = AiAppProxyCaptureService.DetectInstalledAndRunningApps();
        DetectedAiApps.Clear();

        foreach (DetectedAiAppStatus status in statuses)
        {
            string badge = status.IsRunning
                ? _localization["Simple_App_Running"]
                : status.IsInstalled
                    ? _localization["Simple_App_Installed"]
                    : _localization["Simple_App_NotFound"];

            DetectedAiApps.Add(new AiAppItemViewModel(
                status.Profile,
                status.IsInstalled,
                status.IsRunning,
                status.ExecutablePath,
                badge));
        }
    }

    /// <summary>
    /// Launches (or cleanly relaunches if already open unproxied) a desktop or CLI AI application
    /// directly through DNS Pulse's local loopback proxy.
    /// </summary>
    [RelayCommand]
    public void LaunchAiApp(AiAppItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        int port = _boundProxyPort > 0 ? _boundProxyPort : _runtimeService.CurrentStatus.BoundProxyPort;
        AiAppLaunchResult result = item.IsRunning && item.Profile.SupportsChromiumProxyFlag
            ? AiAppProxyCaptureService.RelaunchAppThroughLocalProxy(item.Profile, item.ExecutablePath, port)
            : AiAppProxyCaptureService.LaunchAppThroughLocalProxy(item.Profile, item.ExecutablePath, port);
        AiAppActionStatus = result.Message;
        RefreshAiApps();
    }

    /// <summary>
    /// Copies a ready-to-run PowerShell command that launches the given AI app or CLI through DNS Pulse's local proxy.
    /// </summary>
    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Clipboard access may fail in headless test environments or locked desktops.")]
    public void CopyAiAppSnippet(AiAppItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        int port = _boundProxyPort > 0 ? _boundProxyPort : _runtimeService.CurrentStatus.BoundProxyPort;
        string snippet = AiAppProxyCaptureService.BuildPowerShellLaunchSnippet(item.Profile, port);

        try
        {
            System.Windows.Clipboard.SetText(snippet);
            AiAppActionStatus = string.Create(CultureInfo.InvariantCulture, $"{item.DisplayName}: PowerShell command copied.");
        }
        catch (Exception ex)
        {
            AiAppActionStatus = ex.Message;
        }
    }

    private List<DnsServerEntry> BuildActiveGeoProbePool()
    {
        List<DnsServerEntry> pool = [];
        if (SelectedGeoUnlockUpstream is not null)
        {
            pool.Add(SelectedGeoUnlockUpstream);
        }

        foreach (DnsServerEntry candidate in _catalogProvider()
            .Where(static s => TrustTierPolicy.CanServeGeoUnlock(s.TrustTier) && ServerCategoryClassifier.SupportsAiDomain(s))
            .OrderBy(static s => s.Verdict == DiagnosticVerdict.Healthy ? 0 : 1)
            .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue)
            .Take(3))
        {
            if (!pool.Any(existing => string.Equals(existing.Id, candidate.Id, StringComparison.OrdinalIgnoreCase)))
            {
                pool.Add(candidate);
            }
        }

        return pool;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Individual service probe errors are captured as blocked status on that service row.")]
    private async Task ProbeSingleAiServiceAsync(
        SixLayerDiagnosticEngine engine,
        AiServiceReadinessItem item,
        IReadOnlyList<DnsServerEntry> probePool,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        DiagnosticReport? bestReport = null;
        try
        {
            foreach (DnsServerEntry upstream in probePool)
            {
                DiagnosticReport report = await engine.DiagnoseAsync(
                    item.TargetDomain,
                    upstream,
                    options,
                    cancellationToken).ConfigureAwait(false);

                bestReport = report;
                if (report.Verdict == DiagnosticVerdict.Healthy && report.TlsHandshakeSucceeded)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "AI readiness check failed for {Domain}.", item.TargetDomain);
        }

        bool ok = bestReport is not null && bestReport.Verdict == DiagnosticVerdict.Healthy && bestReport.TlsHandshakeSucceeded;
        string ip = bestReport is { ResolvedAddresses.Count: > 0 }
            ? bestReport.ResolvedAddresses[0].ToString()
            : string.Empty;
        string detail = ok
            ? bestReport!.LatencyP50Ms is double ms
                ? string.Create(CultureInfo.InvariantCulture, $"{_localization["Simple_Service_Ok"]} · {ms:F0} ms")
                : _localization["Simple_Service_Ok"]
            : _localization["Simple_Service_Blocked"];

        await RunOnUiThreadAsync(() =>
        {
            item.IsChecking = false;
            item.IsAccessible = ok;
            item.StatusDetail = detail;
            item.ResolvedIp = ip;
            return Task.CompletedTask;
        }).ConfigureAwait(false);
    }

    private void StartDynamicWatchdog()
    {
        StopDynamicWatchdog();

        _watchdogCts = new CancellationTokenSource();
        CancellationToken token = _watchdogCts.Token;
        IsWatchdogActive = true;
        WatchdogStatusSummary = _localization["Simple_Watchdog_Active"];

        _ = Task.Run(() => RunDynamicWatchdogLoopAsync(token), token);
    }

    private void StopDynamicWatchdog()
    {
        _watchdogCts?.Cancel();
        _watchdogCts?.Dispose();
        _watchdogCts = null;

        IsWatchdogActive = false;
        WatchdogStatusSummary = string.Empty;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Background AI health watchdog must never crash the UI process on transient network errors.")]
    private async Task RunDynamicWatchdogLoopAsync(CancellationToken cancellationToken)
    {
        using PeriodicTimer timer = new(WatchdogProbeInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                if (_disposed || !IsConnected || IsBusy || IsAutoFinding)
                {
                    continue;
                }

                DnsServerEntry? currentGeo = SelectedGeoUnlockUpstream;
                if (currentGeo is null)
                {
                    continue;
                }

                SixLayerDiagnosticEngine? engine = _runtimeService.CreateDiagnosticEngine();
                if (engine is null)
                {
                    continue;
                }

                PulseAppSettings settings = _settingsProvider();
                DiagnosticProbeOptions probeOptions = new()
                {
                    TransportProbeSamples = 1,
                    ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(settings.ProbeTimeoutMs, 1500, 3500)),
                    IncludeTlsAndApplicationProbes = true,
                    ProbeCompanionDomains = false
                };

                DiagnosticReport report = await engine.DiagnoseAsync(
                    EffectiveTargetDomain,
                    currentGeo,
                    probeOptions,
                    cancellationToken).ConfigureAwait(false);

                bool healthy = report.Verdict == DiagnosticVerdict.Healthy
                    && report.TlsHandshakeSucceeded
                    && (report.LatencyP50Ms ?? 0) < WatchdogLatencyDegradationMs;

                if (!healthy)
                {
                    Log.Warning(
                        "Dynamic AI Watchdog detected degradation on {UpstreamId} (Verdict={Verdict}, P50={LatencyMs}ms); auto-rotating to next best AI node.",
                        currentGeo.Id,
                        report.Verdict,
                        report.LatencyP50Ms?.ToString("F0", CultureInfo.InvariantCulture) ?? "n/a");

                    await RunOnUiThreadAsync(async () =>
                    {
                        if (!IsBusy && !IsAutoFinding && IsConnected)
                        {
                            await AutoConnectBestAsync(cancellationToken).ConfigureAwait(false);
                        }
                    }).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Dynamic AI Watchdog stopped due to unexpected error.");
        }
    }

    private static async Task RunOnUiThreadAsync(Func<Task> action)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            await dispatcher.InvokeAsync(action).Task.Unwrap().ConfigureAwait(false);
            return;
        }

        await action().ConfigureAwait(false);
    }
}
