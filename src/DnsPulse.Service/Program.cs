using System.Globalization;
using System.Net;
using System.ServiceProcess;
using System.Text.Json;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Bootstrap;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Engine.Transports;
using DnsPulse.Platform.Windows;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Ipc;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Recovery;
using DnsPulse.Platform.Windows.Updates;
using DnsPulse.Service;
using Microsoft.Extensions.Logging;

JsonSerializerOptions ipcJsonOptions = new()
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true
};

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSingleton<ILoggerProvider, ServiceFileLoggerProvider>();
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "DnsPulseService";
});

builder.Services.Configure<HostOptions>(options =>
{
    options.ShutdownTimeout = TimeSpan.FromSeconds(10);
});

builder.Services.AddSingleton(_ => new NetworkSnapshotJournal());
builder.Services.AddSingleton(_ => new AppSettingsStore());
builder.Services.AddSingleton(sp => new HostNetworkHealthProvider(
    enableOsProbes: true,
    desiredDnsPortProvider: () => sp.GetRequiredService<DefaultPulseRuntimeBackend>().ConfiguredDnsPort));
builder.Services.AddSingleton<IHostNetworkHealthProvider>(sp => sp.GetRequiredService<HostNetworkHealthProvider>());
builder.Services.AddSingleton(_ => new LoopbackPortSelector());
builder.Services.AddSingleton(_ => new WfpDivertInterceptor(AntiCheatGuard.DetectActiveAntiCheat));

builder.Services.AddSingleton(sp =>
{
    LoopbackPortSelector portSelector = sp.GetRequiredService<LoopbackPortSelector>();
    IPAddress preferredLoopback = IPAddress.Loopback;
    if (portSelector.TrySelectAvailableDnsEndpoint(53, out IPAddress? selectedEndpoint))
    {
        preferredLoopback = selectedEndpoint;
    }

    return new PulseServiceOptions
    {
        PreferredLoopbackAddress = preferredLoopback
    };
});

builder.Services.AddSingleton(_ => new SplitNamespaceRouter());
builder.Services.AddSingleton(_ => new OptimisticDnsCache());
builder.Services.AddSingleton(_ => new UpstreamPoolManager());
builder.Services.AddSingleton(_ => UpstreamClientRegistry.CreateDefault());
builder.Services.AddSingleton<IBootstrapResolver>(_ => new EncryptedBootstrapResolver());
builder.Services.AddSingleton(sp =>
{
    SplitNamespaceRouter router = sp.GetRequiredService<SplitNamespaceRouter>();
    OptimisticDnsCache cache = sp.GetRequiredService<OptimisticDnsCache>();
    UpstreamPoolManager poolManager = sp.GetRequiredService<UpstreamPoolManager>();
    UpstreamClientRegistry registry = sp.GetRequiredService<UpstreamClientRegistry>();
    return new PulseCoreDnsEngine(router, cache, poolManager, registry.GetClient);
});

builder.Services.AddSingleton(sp =>
{
    IBootstrapResolver bootstrapResolver = sp.GetRequiredService<IBootstrapResolver>();
    UpstreamClientRegistry registry = sp.GetRequiredService<UpstreamClientRegistry>();
    IHostNetworkHealthProvider healthProvider = sp.GetRequiredService<IHostNetworkHealthProvider>();
    return new SixLayerDiagnosticEngine(bootstrapResolver, registry.GetClient, healthProvider);
});

builder.Services.AddSingleton(sp =>
{
    IHostNetworkHealthProvider healthProvider = sp.GetRequiredService<IHostNetworkHealthProvider>();
    return new NetworkResilienceWatcher(async ct =>
    {
        _ = await healthProvider.InspectAsync(ct).ConfigureAwait(false);
        Win32NetworkInterop.FlushDnsResolverCache();
    });
});

builder.Services.AddSingleton(sp =>
{
    PulseServiceOptions options = sp.GetRequiredService<PulseServiceOptions>();
    PulseCoreDnsEngine engine = sp.GetRequiredService<PulseCoreDnsEngine>();
    SplitNamespaceRouter splitRouter = sp.GetRequiredService<SplitNamespaceRouter>();
    OptimisticDnsCache cache = sp.GetRequiredService<OptimisticDnsCache>();
    UpstreamPoolManager poolManager = sp.GetRequiredService<UpstreamPoolManager>();
    LoopbackPortSelector portSelector = sp.GetRequiredService<LoopbackPortSelector>();
    NetworkSnapshotJournal journal = sp.GetRequiredService<NetworkSnapshotJournal>();
    IBootstrapResolver bootstrapResolver = sp.GetRequiredService<IBootstrapResolver>();
    WfpDivertInterceptor wfpInterceptor = sp.GetRequiredService<WfpDivertInterceptor>();
    ILogger<DefaultPulseRuntimeBackend> logger = sp.GetRequiredService<ILogger<DefaultPulseRuntimeBackend>>();

    string[] initialSplitDomains =
    [
        .. BuiltInCatalogPresets.BuiltinAiDomains,
        .. BuiltInCatalogPresets.BuiltinStreamingDomains,
        .. BuiltInCatalogPresets.BuiltinGamingDomains
    ];

    return new DefaultPulseRuntimeBackend(
        options,
        engine,
        cache,
        poolManager,
        dnsInterceptor: null,
        emergencyRollbackHandler: async ct =>
        {
            NetworkRestoredResult result = await journal.RecoverIfDirtyAsync(ct).ConfigureAwait(false);
            return result.HadDirtyState
                ? result
                : NetworkSnapshotJournal.ExecuteNativeRestore(null);
        },
        sidecarHostResolver: (host, ct) => bootstrapResolver.ResolveHostAsync(host, ct),
        initialSplitDomains: initialSplitDomains,
        logger: logger,
        router: splitRouter,
        loopbackPortSelector: portSelector,
        journal: journal,
        interceptorFactory: (mode, pacUrl, blockIpv6OnBypass) => mode switch
        {
            InterceptionMode.SplitNrpt => new NrptSplitInterceptor(),
            InterceptionMode.LocalProxyPacOnly => new LocalProxyPacInterceptor(pacUrl: pacUrl),
            InterceptionMode.WfpDivertPlugin => wfpInterceptor,
            _ => new AdapterDnsInterceptor(blockIpv6OnBypass: blockIpv6OnBypass)
        });
});
builder.Services.AddSingleton<IPulseRuntimeBackend>(sp => sp.GetRequiredService<DefaultPulseRuntimeBackend>());

builder.Services.AddHostedService(sp =>
{
    DefaultPulseRuntimeBackend concreteBackend = sp.GetRequiredService<DefaultPulseRuntimeBackend>();
    PulseServiceOptions options = sp.GetRequiredService<PulseServiceOptions>();
    ILogger<DnsPulseWorkerService> logger = sp.GetRequiredService<ILogger<DnsPulseWorkerService>>();
    IHostApplicationLifetime lifetime = sp.GetRequiredService<IHostApplicationLifetime>();
    IHostNetworkHealthProvider healthProvider = sp.GetRequiredService<IHostNetworkHealthProvider>();
    SixLayerDiagnosticEngine diagnosticEngine = sp.GetRequiredService<SixLayerDiagnosticEngine>();
    UpstreamPoolManager poolManager = sp.GetRequiredService<UpstreamPoolManager>();
    NetworkSnapshotJournal journal = sp.GetRequiredService<NetworkSnapshotJournal>();
    AppSettingsStore settingsStore = sp.GetRequiredService<AppSettingsStore>();

    return new DnsPulseWorkerService(
        concreteBackend,
        options,
        logger,
        lifetime,
        extensionHandler: async (request, ct) =>
        {
            switch (request.Command)
            {
                case PipeCommandNames.RunDiagnostics:
                    {
                        ServiceDiagnosticsRequest? diagRequest = null;
                        if (!string.IsNullOrWhiteSpace(request.PayloadJson))
                        {
                            diagRequest = JsonSerializer.Deserialize<ServiceDiagnosticsRequest>(request.PayloadJson, ipcJsonOptions);
                        }

                        HostNetworkHealthSnapshot hostHealth = await healthProvider.InspectAsync(ct).ConfigureAwait(false);
                        DiagnosticReport? report = null;
                        if (!string.IsNullOrWhiteSpace(diagRequest?.TargetDomain))
                        {
                            DnsServerEntry? upstream = diagRequest.Upstream ??
                                (poolManager.Zone4Servers.Count > 0 ? poolManager.Zone4Servers[0] : null);
                            if (upstream is not null)
                            {
                                DiagnosticProbeOptions probeOptions = new()
                                {
                                    ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(diagRequest.TimeoutMs ?? 4000, 500, 15000))
                                };
                                report = await diagnosticEngine.DiagnoseAsync(
                                    diagRequest.TargetDomain.Trim(),
                                    upstream,
                                    probeOptions,
                                    ct).ConfigureAwait(false);
                            }
                        }

                        ServiceDiagnosticsResponse responsePayload = new(
                            concreteBackend.GetStatus(),
                            hostHealth,
                            report);
                        return new PipeRpcResponse(
                            request.RequestId,
                            true,
                            PayloadJson: JsonSerializer.Serialize(responsePayload, ipcJsonOptions));
                    }

                case PipeCommandNames.ExportBundle:
                    {
                        ServiceExportBundleRequest? exportRequest = null;
                        if (!string.IsNullOrWhiteSpace(request.PayloadJson))
                        {
                            exportRequest = JsonSerializer.Deserialize<ServiceExportBundleRequest>(request.PayloadJson, ipcJsonOptions);
                        }

                        string outputPath = !string.IsNullOrWhiteSpace(exportRequest?.OutputZipPath)
                            ? Path.GetFullPath(exportRequest.OutputZipPath.Trim())
                            : Path.Combine(
                                Path.GetTempPath(),
                                string.Create(CultureInfo.InvariantCulture, $"DnsPulse-Diagnostics-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.zip"));

                        PulseAppSettings settings = await settingsStore.LoadAsync(ct).ConfigureAwait(false);
                        HostNetworkHealthSnapshot hostHealth = await healthProvider.InspectAsync(ct).ConfigureAwait(false);
                        PrePulseNetworkSnapshot? snapshot = journal.TryLoadVerifiedSnapshot(out _);
                        IReadOnlyList<DnsQueryTelemetryEvent>? telemetry =
                            !settings.ZeroDiskQueryLogging
                                ? concreteBackend.GetRecentTelemetry(200)
                                : null;
                        string logDirectory = ServiceFileLoggerProvider.GetDefaultServiceLogDirectory();

                        await DiagnosticBundleExporter.ExportRedactedBundleAsync(
                            outputPath,
                            settings,
                            snapshot,
                            hostHealth,
                            telemetry,
                            logDirectory,
                            ct).ConfigureAwait(false);

                        ServiceExportBundleResponse responsePayload = new(outputPath);
                        return new PipeRpcResponse(
                            request.RequestId,
                            true,
                            PayloadJson: JsonSerializer.Serialize(responsePayload, ipcJsonOptions));
                    }

                default:
                    return new PipeRpcResponse(
                        request.RequestId,
                        false,
                        "NotSupported",
                        string.Create(CultureInfo.InvariantCulture, $"Command '{request.Command}' is not supported."));
            }
        });
});

using IHost host = builder.Build();
ILogger platformLogger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("DnsPulse.Platform");
Action<ILogger, string, Exception?> logPlatformWarning = LoggerMessage.Define<string>(
    LogLevel.Warning,
    new EventId(1, "PlatformWarning"),
    "{Message}");
Action<ILogger, string, Exception?> logPlatformInfo = LoggerMessage.Define<string>(
    LogLevel.Information,
    new EventId(2, "PlatformInfo"),
    "{Message}");
PlatformDiagnosticLog.Configure((msg, ex) =>
{
    if (ex is not null)
    {
        if (platformLogger.IsEnabled(LogLevel.Warning))
        {
            logPlatformWarning(platformLogger, msg, ex);
        }
    }
    else if (platformLogger.IsEnabled(LogLevel.Information))
    {
        logPlatformInfo(platformLogger, msg, null);
    }
});

NetworkSnapshotJournal journal = host.Services.GetRequiredService<NetworkSnapshotJournal>();
NetworkSnapshotJournal.RegisterEmergencyProcessHooks(journal);

NetworkResilienceWatcher watcher = host.Services.GetRequiredService<NetworkResilienceWatcher>();
watcher.Start();

if (host.Services.GetService<IHostLifetime>() is ServiceBase serviceBase)
{
    serviceBase.CanShutdown = true;
}

await host.RunAsync();
