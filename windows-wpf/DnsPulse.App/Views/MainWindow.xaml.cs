using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using DnsPulse.App.Data;
using DnsPulse.App.NetworkEngine;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly TrayNotificationService _tray = new();
    private readonly DispatcherTimer _tunnelTimer;

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel(new DnsDatabaseRepository(), action => Dispatcher.Invoke(action));
        DataContext = _vm;

        _tunnelTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.2) };
        _tunnelTimer.Tick += (_, _) =>
        {
            if (_vm.IsTunnelActive && _vm.ActiveTunnelServer is { } srv)
            {
                _vm.RefreshTunnelCounters();
                _tray.UpdateActiveState(true, srv.Name, srv.EndpointLabel, _vm.TargetDomain, _vm.TunnelQueries);
            }
            else
            {
                _tray.UpdateActiveState(false, null, null, _vm.TargetDomain, 0);
            }
        };
        _tunnelTimer.Start();

        _tray.OnRotateRequested += () => Dispatcher.Invoke(async () => await _vm.RotateTunnelAsync());
        _tray.OnDisconnectRequested += () => Dispatcher.Invoke(async () => await _vm.StopTunnelAsync());
        _tray.OnShowWindowRequested += () => Dispatcher.Invoke(() =>
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        });
    }

    private void OnMinimizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeRestoreClick(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnCloseWindowClick(object sender, RoutedEventArgs e) => Close();

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        _vm.IsDarkTheme = !_vm.IsDarkTheme;
        var dictUri = _vm.IsDarkTheme
            ? new Uri("Themes/RestrainedGraphiteDark.xaml", UriKind.Relative)
            : new Uri("Themes/RestrainedGraphiteLight.xaml", UriKind.Relative);

        var dicts = System.Windows.Application.Current.Resources.MergedDictionaries;
        if (dicts.Count > 0)
        {
            dicts[0] = new ResourceDictionary { Source = dictUri };
        }
        else
        {
            dicts.Add(new ResourceDictionary { Source = dictUri });
        }
    }

    private void OnOpenDiscoveryClick(object sender, RoutedEventArgs e)
    {
        var dialog = new DiscoveryWindow(_vm) { Owner = this };
        dialog.ShowDialog();
    }

    private void OnOpenManualAddClick(object sender, RoutedEventArgs e)
    {
        var dialog = new ManualAddWindow(_vm) { Owner = this };
        dialog.ShowDialog();
    }

    private void OnCopyTagClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string text } && !string.IsNullOrWhiteSpace(text))
        {
            System.Windows.Clipboard.SetText(text);
            _vm.StatusMessage = "Скопировано в буфер обмена";
        }
    }

    private void OnLoadConfigFileClick(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "DNS configs (*.txt;*.json;*.csv)|*.txt;*.json;*.csv|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            _vm.ImportEditorText = File.ReadAllText(dialog.FileName);
            _vm.ImportFromEditorCommand.Execute(null);
        }
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
            _vm.ConfigFeedback = $"Экспортировано в CSV: {dialog.FileName}";
        }
    }

    private void OnExportJsonClick(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = "dns-pulse-export.json",
            Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(_vm.VisibleServers, new JsonSerializerOptions { WriteIndented = true }));
            _vm.ConfigFeedback = $"Экспортировано в JSON: {dialog.FileName}";
        }
    }

    private void OnOpenWinSettingsClick(object sender, RoutedEventArgs e) =>
        WindowsNetworkAdapterService.OpenWindowsNetworkSettings();

    protected override async void OnClosed(EventArgs e)
    {
        _tunnelTimer.Stop();
        await _vm.StopTunnelAsync();
        _tray.Dispose();
        base.OnClosed(e);
    }
}
