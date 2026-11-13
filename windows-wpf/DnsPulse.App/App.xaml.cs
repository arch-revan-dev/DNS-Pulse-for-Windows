using System.IO;
using System.Windows;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App;

public partial class App : System.Windows.Application
{
    private WindowsNetworkAdapterService? _adapterService;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse");
        _adapterService = new WindowsNetworkAdapterService(appData);
        // Crash recovery: restore previous adapter DNS if previous run terminated abnormally
        await _adapterService.RestorePreviousDnsIfNeededAsync();
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
