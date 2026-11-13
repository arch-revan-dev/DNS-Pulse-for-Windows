using System.Net;
using System.ServiceProcess;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Bootstrap;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Engine.Transports;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Recovery;
using DnsPulse.Service;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "DnsPulseService";
});

builder.Services.Configure<HostOptions>(options =>
{
    options.ShutdownTimeout = TimeSpan.FromSeconds(10);
});

builder.Services.AddSingleton(_ => new NetworkSnapshotJournal());
builder.Services.AddSingleton(_ => new HostNetworkHealthProvider(enableOsProbes: true));
builder.Services.AddSingleton<IHostNetworkHealthProvider>(sp => sp.GetRequiredService<HostNetworkHealthProvider>());
builder.Services.AddSingleton(_ => new LoopbackPortSelector());
builder.Services.AddSingleton(_ => new AdapterDnsInterceptor());
builder.Services.AddSingleton(_ => new NrptSplitInterceptor());
builder.Services.AddSingleton(_ => new LocalProxyPacInterceptor());
builder.Services.AddSingleton(_ => new WfpDivertInterceptor(AntiCheatGuard.DetectActiveAntiCheat));

builder.Services.AddSingleton(sp =>
{
    LoopbackPortSelector portSelector = sp.GetRequiredService<LoopbackPortSelector>();
    IPAddress preferredLoopback = IPAddress.Loopback;
    try
    {
        preferredLoopback = portSelector.SelectAvailableDnsEndpoint(53);
    }
    catch (InvalidOperationException)
    {
        // Keep 127.0.0.1 fallback if port 53 cannot be probed prior to service activation.
    }

    return new PulseServiceOptions
    {
        PreferredLoopbackAddress = preferredLoopback
    };
});

builder.Services.AddSingleton<IDnsInterceptor>(sp =>
{
    PulseServiceOptions options = sp.GetRequiredService<PulseServiceOptions>();
    return options.InterceptionMode switch
    {
        InterceptionMode.SplitNrpt => sp.GetRequiredService<NrptSplitInterceptor>(),
        InterceptionMode.LocalProxyPacOnly => sp.GetRequiredService<LocalProxyPacInterceptor>(),
        InterceptionMode.WfpDivertPlugin => sp.GetRequiredService<WfpDivertInterceptor>(),
        _ => sp.GetRequiredService<AdapterDnsInterceptor>()
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
    IHostNetworkHealthProvider healthProvider = sp.GetRequiredService<IHostNetworkHealthProvider>();
    return new NetworkResilienceWatcher(async ct =>
    {
        _ = await healthProvider.InspectAsync(ct).ConfigureAwait(false);
        Win32NetworkInterop.FlushDnsResolverCache();
    });
});

builder.Services.AddSingleton<IPulseRuntimeBackend>(sp =>
{
    PulseServiceOptions options = sp.GetRequiredService<PulseServiceOptions>();
    PulseCoreDnsEngine engine = sp.GetRequiredService<PulseCoreDnsEngine>();
    OptimisticDnsCache cache = sp.GetRequiredService<OptimisticDnsCache>();
    UpstreamPoolManager poolManager = sp.GetRequiredService<UpstreamPoolManager>();
    IDnsInterceptor interceptor = sp.GetRequiredService<IDnsInterceptor>();
    NetworkSnapshotJournal journal = sp.GetRequiredService<NetworkSnapshotJournal>();
    IBootstrapResolver bootstrapResolver = sp.GetRequiredService<IBootstrapResolver>();
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
        dnsInterceptor: interceptor,
        emergencyRollbackHandler: async ct =>
        {
            NetworkRestoredResult result = await journal.RecoverIfDirtyAsync(ct).ConfigureAwait(false);
            return result.HadDirtyState
                ? result
                : NetworkSnapshotJournal.ExecuteNativeRestore(null);
        },
        sidecarHostResolver: (host, ct) => bootstrapResolver.ResolveHostAsync(host, ct),
        initialSplitDomains: initialSplitDomains,
        logger: logger);
});

builder.Services.AddHostedService<DnsPulseWorkerService>();

using IHost host = builder.Build();
NetworkSnapshotJournal journal = host.Services.GetRequiredService<NetworkSnapshotJournal>();
NetworkSnapshotJournal.RegisterEmergencyProcessHooks(journal);

NetworkResilienceWatcher watcher = host.Services.GetRequiredService<NetworkResilienceWatcher>();
watcher.Start();

if (host.Services.GetService<IHostLifetime>() is ServiceBase serviceBase)
{
    serviceBase.CanShutdown = true;
}

await host.RunAsync();
