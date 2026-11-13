using System.ServiceProcess;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Engine.Transports;
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

builder.Services.AddSingleton(new PulseServiceOptions());
builder.Services.AddSingleton(_ => new SplitNamespaceRouter());
builder.Services.AddSingleton(_ => new OptimisticDnsCache());
builder.Services.AddSingleton(_ => new UpstreamPoolManager());
builder.Services.AddSingleton(_ => UpstreamClientRegistry.CreateDefault());
builder.Services.AddSingleton(sp =>
{
    SplitNamespaceRouter router = sp.GetRequiredService<SplitNamespaceRouter>();
    OptimisticDnsCache cache = sp.GetRequiredService<OptimisticDnsCache>();
    UpstreamPoolManager poolManager = sp.GetRequiredService<UpstreamPoolManager>();
    UpstreamClientRegistry registry = sp.GetRequiredService<UpstreamClientRegistry>();
    return new PulseCoreDnsEngine(router, cache, poolManager, registry.GetClient);
});
builder.Services.AddSingleton<IPulseRuntimeBackend>(sp =>
{
    PulseServiceOptions options = sp.GetRequiredService<PulseServiceOptions>();
    PulseCoreDnsEngine engine = sp.GetRequiredService<PulseCoreDnsEngine>();
    OptimisticDnsCache cache = sp.GetRequiredService<OptimisticDnsCache>();
    UpstreamPoolManager poolManager = sp.GetRequiredService<UpstreamPoolManager>();
    ILogger<DefaultPulseRuntimeBackend> logger = sp.GetRequiredService<ILogger<DefaultPulseRuntimeBackend>>();
    return new DefaultPulseRuntimeBackend(
        options,
        engine,
        cache,
        poolManager,
        logger: logger);
});
builder.Services.AddHostedService<DnsPulseWorkerService>();

using IHost host = builder.Build();
if (host.Services.GetService<IHostLifetime>() is ServiceBase serviceBase)
{
    serviceBase.CanShutdown = true;
}

await host.RunAsync();
