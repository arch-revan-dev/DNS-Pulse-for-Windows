using System.IO;
using System.Windows;
using System.Windows.Controls;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly TrayNotificationService _tray = new();
    private bool _isDarkTheme = true;

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel(new DnsDatabaseRepository());
        DataContext = _vm;

        _tray.OnRotateRequested += () => Dispatcher.Invoke(async () =>
        {
            await _vm.RotateTunnelAsync();
            RefreshTunnelBanner();
        });
        _tray.OnDisconnectRequested += () => Dispatcher.Invoke(async () =>
        {
            await _vm.StopTunnelAsync();
            RefreshTunnelBanner();
        });
        _tray.OnShowWindowRequested += () => Dispatcher.Invoke(() =>
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        });
    }

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        _isDarkTheme = !_isDarkTheme;
        var dictUri = _isDarkTheme
            ? new Uri("Themes/RestrainedGraphiteDark.xaml", UriKind.Relative)
            : new Uri("Themes/RestrainedGraphiteLight.xaml", UriKind.Relative);

        var dicts = System.Windows.Application.Current.Resources.MergedDictionaries;
        dicts.Clear();
        dicts.Add(new ResourceDictionary { Source = dictUri });
    }

    private void OnOpenDiscoveryClick(object sender, RoutedEventArgs e)
    {
        var dialog = new DiscoveryWindow(_vm) { Owner = this };
        dialog.ShowDialog();
    }

    private void OnToggleLiveClick(object sender, RoutedEventArgs e)
    {
        _vm.ToggleLive();
        LiveBtn.Content = _vm.IsLiveRunning ? "LIVE ●" : "LIVE";
    }

    private async void OnBenchmarkClick(object sender, RoutedEventArgs e)
    {
        await _vm.BenchmarkTopAsync(18, CancellationToken.None);
    }

    private void OnPresetClick(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button { Tag: string tag })
        {
            var parts = tag.Split('|');
            if (parts.Length >= 3)
            {
                _vm.TargetDomain = parts[0];
                _vm.RequiresBypass = parts[1] == "true";
                ModeLabel.Text = $"Режим: {parts[2]}";
            }
        }
    }

    private void OnCategoryChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_vm is null) return;
        if (CategoryCombo.SelectedItem is ComboBoxItem { Content: string cat })
            _vm.SelectedCategory = cat;
    }

    private void OnSortChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_vm is null) return;
        if (SortCombo.SelectedItem is ComboBoxItem { Tag: string tag } && Enum.TryParse<SortMode>(tag, out var mode))
            _vm.SelectedSortMode = mode;
    }

    private void OnMainTabChanged(object sender, SelectionChangedEventArgs e)
    {
        // Keep visible servers synced across tabs
        if (e.Source is System.Windows.Controls.TabControl)
            _vm?.ApplyFilterAndSort();
    }

    private async void OnTestSingleClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: DnsServerEntry entry })
            await _vm.TestSingleAsync(entry, CancellationToken.None);
    }

    private void OnFavoriteClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: DnsServerEntry entry })
            _vm.ToggleFavorite(entry);
    }

    private async void OnStartTunnelClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: DnsServerEntry entry })
        {
            await _vm.StartTunnelAsync(entry);
            RefreshTunnelBanner();
        }
    }

    private async void OnRotateTunnelClick(object sender, RoutedEventArgs e)
    {
        await _vm.RotateTunnelAsync();
        RefreshTunnelBanner();
    }

    private async void OnStopTunnelClick(object sender, RoutedEventArgs e)
    {
        await _vm.StopTunnelAsync();
        RefreshTunnelBanner();
    }

    private void RefreshTunnelBanner()
    {
        if (_vm.IsTunnelActive && _vm.ActiveTunnelServer is { } srv)
        {
            TunnelBanner.Visibility = Visibility.Visible;
            TunnelBannerTitle.Text = $"Активен туннель: {srv.Name}";
            TunnelBannerSubtitle.Text = $"{srv.DohUrl ?? srv.DotHost ?? srv.PrimaryIp}  •  127.0.0.1:53  •  Запросов: {_vm.TunnelQueries}";
            _tray.UpdateActiveState(true, srv.Name, srv.DohUrl ?? srv.PrimaryIp, _vm.TargetDomain, _vm.TunnelQueries);
        }
        else
        {
            TunnelBanner.Visibility = Visibility.Collapsed;
            _tray.UpdateActiveState(false, null, null, _vm.TargetDomain, 0);
        }
    }

    private void OnImportConfigsClick(object sender, RoutedEventArgs e)
    {
        int count = _vm.ImportRawConfigs(ImportEditor.Text);
        ConfigFeedbackText.Text = count > 0
            ? $"Импортировано в SQLite + JSON-сейф: {count}"
            : "Не найдено корректных адресов DNS";
    }

    private void OnExportCsvClick(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = "dns-pulse-export.csv",
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, ImportExportCodec.ExportToCsv(_vm.VisibleServers));
            ConfigFeedbackText.Text = $"Экспортировано: {dialog.FileName}";
        }
    }

    private async void OnSyncFeedsFromConfigsClick(object sender, RoutedEventArgs e)
    {
        var (hosts, servers) = await _vm.SyncOnlineFeedsAsync(CancellationToken.None);
        ConfigFeedbackText.Text = $"Синхронизировано: {hosts} доменов, {servers} DNS";
    }

    private void OnRestoreBuiltinsClick(object sender, RoutedEventArgs e)
    {
        int added = _vm.RestoreBuiltins();
        ConfigFeedbackText.Text = $"Встроенная база проверена (добавлено: {added})";
    }

    private void OnOpenWinSettingsClick(object sender, RoutedEventArgs e)
    {
        WindowsNetworkAdapterService.OpenWindowsNetworkSettings();
    }

    protected override async void OnClosed(EventArgs e)
    {
        await _vm.StopTunnelAsync();
        _tray.Dispose();
        base.OnClosed(e);
    }
}
