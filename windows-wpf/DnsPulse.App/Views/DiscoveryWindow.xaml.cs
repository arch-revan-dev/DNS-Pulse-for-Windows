using System.Windows;
using DnsPulse.App.Models;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

public partial class DiscoveryWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly SubnetScannerService _scanner = new();
    private CancellationTokenSource? _cts;
    private List<DnsServerEntry> _found = [];

    public DiscoveryWindow(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        TargetDomainInput.Text = _vm.TargetDomain;
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OnPresetDomainClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string domain })
            TargetDomainInput.Text = domain;
    }

    private async void OnScanClick(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        ScanBtn.IsEnabled = false;
        var domain = string.IsNullOrWhiteSpace(TargetDomainInput.Text) ? _vm.TargetDomain : TargetDomainInput.Text.Trim();
        StatusLabel.Text = $"Идёт 4-этапная проверка подсети для {domain}...";

        try
        {
            var progress = new Progress<double>(p => ScanProgress.Value = p * 100);
            _found = await _scanner.ScanAsync(
                SubnetInput.Text,
                domain,
                requiresBypass: true,
                scanUdp53: ScanUdp53Check.IsChecked == true,
                checkPort443: CheckPort443Check.IsChecked == true,
                progress,
                _cts.Token);

            FoundList.ItemsSource = _found;
            StatusLabel.Text = $"Найдено рабочих узлов: {_found.Count}";
        }
        catch (Exception ex)
        {
            StatusLabel.Text = $"Ошибка сканирования: {ex.Message}";
        }
        finally
        {
            ScanBtn.IsEnabled = true;
        }
    }

    private async void OnSyncFeedsClick(object sender, RoutedEventArgs e)
    {
        SyncFeedsBtn.IsEnabled = false;
        StatusLabel.Text = "Загрузка списков dns.malw.link и QuickDNS...";
        try
        {
            var (hosts, servers) = await _vm.SyncOnlineFeedsAsync(CancellationToken.None);
            StatusLabel.Text = $"Синхронизировано доменов: {hosts}, узлов: {servers}";
        }
        catch (Exception ex)
        {
            StatusLabel.Text = $"Ошибка синхронизации: {ex.Message}";
        }
        finally
        {
            SyncFeedsBtn.IsEnabled = true;
        }
    }

    private void OnSaveFoundClick(object sender, RoutedEventArgs e)
    {
        if (_found.Count > 0)
            _vm.AddDiscoveredServers(_found);
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _cts?.Cancel();
        base.OnClosed(e);
    }
}
