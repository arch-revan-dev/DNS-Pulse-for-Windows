using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Interception;
using Serilog;

namespace DnsPulse.App.ViewModels;

public sealed partial class OverviewViewModel
{
    private static readonly TimeSpan WatchdogProbeInterval = TimeSpan.FromSeconds(45);
    private const double WatchdogLatencyDegradationMs = 2500.0;

    private CancellationTokenSource? _watchdogCts;
    private int _boundProxyPort;

    [ObservableProperty]
    private bool _isSimpleMode = true;

    [ObservableProperty]
    private bool _isWatchdogActive;

    [ObservableProperty]
    private string _aiAppActionStatus = string.Empty;

    [ObservableProperty]
    private string _watchdogStatusSummary = string.Empty;

    public ObservableCollection<AiAppItemViewModel> DetectedAiApps { get; } = [];

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
            string endpoint = string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{effectivePort}");
            return string.Format(CultureInfo.CurrentCulture, _localization["Simple_Proxy_Endpoint"], endpoint);
        }
    }

    private void InitializeAiAutopilotState()
    {
        RefreshAiApps();
    }

    private void OnAiAutopilotStatusUpdated()
    {
        _boundProxyPort = _runtimeService.CurrentStatus.BoundProxyPort;
        OnPropertyChanged(nameof(SimplePrimaryButtonText));
        OnPropertyChanged(nameof(LocalProxyEndpointText));

        if (!IsConnected && IsWatchdogActive)
        {
            StopDynamicWatchdog();
        }
    }

    private void OnAiAutopilotCultureChanged()
    {
        RefreshAiApps();
        OnPropertyChanged(nameof(SimplePrimaryButtonText));
        OnPropertyChanged(nameof(LocalProxyEndpointText));
        if (IsWatchdogActive)
        {
            WatchdogStatusSummary = _localization["Simple_Watchdog_Active"];
        }
    }

    /// <summary>
    /// One-button Simple Mode ("Режим для чайников") autopilot:
    /// finds the fastest verified AI Smart-DNS/SNI-Proxy node, enables local DNS + AI App proxy capture,
    /// and starts the dynamic health watchdog for automatic failover. Clicking again cleanly disconnects.
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
            return;
        }

        await AutoConnectBestAsync(cancellationToken).ConfigureAwait(false);
        OnPropertyChanged(nameof(SimplePrimaryButtonText));

        PulseAppSettings settings = _settingsProvider();
        if (IsConnected && settings.EnableDynamicAiWatchdog)
        {
            StartDynamicWatchdog();
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
    /// Launches a desktop or CLI AI application directly through DNS Pulse's local loopback proxy.
    /// </summary>
    [RelayCommand]
    public void LaunchAiApp(AiAppItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        int port = _boundProxyPort > 0 ? _boundProxyPort : _runtimeService.CurrentStatus.BoundProxyPort;
        AiAppLaunchResult result = AiAppProxyCaptureService.LaunchAppThroughLocalProxy(
            item.Profile,
            item.ExecutablePath,
            port);
        AiAppActionStatus = result.Message;
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

    private void StartDynamicWatchdog()
    {
        StopDynamicWatchdog();

        CancellationTokenSource cts = new();
        _watchdogCts = cts;
        IsWatchdogActive = true;
        WatchdogStatusSummary = _localization["Simple_Watchdog_Active"];

        _ = Task.Run(() => RunDynamicWatchdogLoopAsync(cts.Token), cts.Token);
    }

    private void StopDynamicWatchdog()
    {
        CancellationTokenSource? previous = Interlocked.Exchange(ref _watchdogCts, null);
        if (previous is not null)
        {
            try
            {
                previous.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }

            previous.Dispose();
        }

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
