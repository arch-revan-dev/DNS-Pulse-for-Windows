using System.IO;
using System.Windows;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App;

public partial class App : System.Windows.Application
{
    public static string[] StartupArgs { get; private set; } = Array.Empty<string>();
    private WindowsNetworkAdapterService? _adapterService;

    protected override async void OnStartup(StartupEventArgs e)
    {
        StartupArgs = e.Args ?? Array.Empty<string>();
        base.OnStartup(e);
        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse");
        DynamicBypassRegistry.LoadOfflineCache(appData);
        _adapterService = new WindowsNetworkAdapterService(appData);
        // Crash recovery: restore previous adapter DNS only when we are not immediately re-applying after UAC restart
        if (!StartupArgs.Any(a => a is "--apply-tunnel" or "--connect-id"))
        {
            await _adapterService.RestorePreviousDnsIfNeededAsync();
        }
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_adapterService is not null)
        {
            await _adapterService.RestorePreviousDnsIfNeededAsync();
        }
        base.OnExit(e);
    }
}
