using DnsPulse.Service;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "DnsPulseService";
});
builder.Services.AddHostedService<PulseBackgroundWorker>();

IHost host = builder.Build();
await host.RunAsync();
