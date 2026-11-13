using System.IO;
using System.Windows;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly TrayNotificationService _tray = new();

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel(new DnsDatabaseRepository());
        DataContext = _vm;

        _tray.OnDisconnectRequested += () => Dispatcher.Invoke(() => _vm.StopTunnel());
        _tray.OnShowWindowRequested += () => Dispatcher.Invoke(() => { Show(); WindowState = WindowState.Normal; Activate(); });
    }

    private void OnOpenDiscoveryClick(object sender, RoutedEventArgs e)
    {
        var scanner = new SubnetScannerService();
        _ = scanner.ScanAsync("AUTO", _vm.TargetDomain, _vm.RequiresBypass, true, true, null, CancellationToken.None);
    }

    private void OnToggleLiveClick(object sender, RoutedEventArgs e)
    {
        if (_vm.VisibleServers.Count > 0)
            _ = _vm.TestSingleAsync(_vm.VisibleServers[0], CancellationToken.None);
    }

    private void OnBenchmarkClick(object sender, RoutedEventArgs e)
    {
        foreach (var srv in _vm.VisibleServers.Take(10))
            _ = _vm.TestSingleAsync(srv, CancellationToken.None);
    }

    private void OnStartTunnelClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: DnsServerEntry entry })
        {
            _ = _vm.StartTunnelAsync(entry);
            _tray.UpdateActiveState(true, entry.Name, entry.DohUrl ?? entry.PrimaryIp, _vm.TargetDomain, 0);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _vm.StopTunnel();
        _tray.Dispose();
        base.OnClosed(e);
    }
}
