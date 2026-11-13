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
        RequiresBypassCheck.IsChecked = _vm.RequiresBypass;
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OnPresetDomainClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string domain })
            TargetDomainInput.Text = domain;
    }

    private void OnStopScanClick(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        StopScanBtn.IsEnabled = false;
        StatusLabel.Text = "Останавливаем сканирование...";
    }

    private async void OnScanClick(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        ScanBtn.IsEnabled = false;
        StopScanBtn.Visibility = Visibility.Visible;
        StopScanBtn.IsEnabled = true;

        var domain = string.IsNullOrWhiteSpace(TargetDomainInput.Text) ? _vm.TargetDomain : TargetDomainInput.Text.Trim();
        bool requiresBypass = RequiresBypassCheck.IsChecked == true;
        StatusLabel.Text = $"Старт 4-этапного сканирования под {domain}...";

        try
        {
            var progress = new Progress<double>(p => ScanProgress.Value = p);
            var detailed = new Progress<(int Done, int Total, int Found, string CurrentIp)>(info =>
            {
                StatusLabel.Text = $"Проверено {info.Done}/{info.Total} ({info.CurrentIp}) · Найдено: {info.Found}";
            });

            _found = await _scanner.ScanAsync(
                SubnetInput.Text,
                domain,
                requiresBypass: requiresBypass,
                scanUdp53: ScanUdp53Check.IsChecked == true,
                checkPort443: CheckPort443Check.IsChecked == true,
                progress,
                _cts.Token,
                detailed);

            FoundList.ItemsSource = _found;
            StatusLabel.Text = _found.Count > 0
                ? $"Готово! Найдено рабочих узлов: {_found.Count} (нажмите «Добавить найденные в базу»)"
                : "Рабочих узлов в указанной подсети не найдено — попробуйте режим AUTO или синхронизацию списков";
        }
        catch (OperationCanceledException)
        {
            StatusLabel.Text = $"Сканирование остановлено (найдено: {_found.Count})";
        }
        catch (Exception ex)
        {
            StatusLabel.Text = $"Ошибка сканирования: {ex.Message}";
        }
        finally
        {
            ScanBtn.IsEnabled = true;
            StopScanBtn.Visibility = Visibility.Collapsed;
        }
    }

    private async void OnSyncFeedsClick(object sender, RoutedEventArgs e)
    {
        SyncFeedsBtn.IsEnabled = false;
        StatusLabel.Text = "Загрузка списков dns.malw.link и QuickDNS (Bootstrap DNS)...";
        try
        {
            var (hosts, servers) = await _vm.SyncOnlineFeedsAsync(CancellationToken.None);
            StatusLabel.Text = $"Синхронизировано доменов: {hosts}, новых DNS-серверов: {servers}";
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
        {
            _vm.AddDiscoveredServers(_found);
        }
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _cts?.Cancel();
        base.OnClosed(e);
    }
}
