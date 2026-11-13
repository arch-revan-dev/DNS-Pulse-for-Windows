using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
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
    private bool _isExplicitExit;
    private bool _shownTrayMinimizeHint;

    public MainWindow()
    {
        InitializeComponent();
        _vm = new MainViewModel(new DnsDatabaseRepository(), action => Dispatcher.Invoke(action));
        DataContext = _vm;

        ApplyVisualTheme(_vm.IsDarkTheme, _vm.AccentPreset);
        _vm.OnVisualSettingsChanged += (dark, accent) => Dispatcher.Invoke(() => ApplyVisualTheme(dark, accent));

        // Handle silent Windows autostart (--minimized) without taskbar flash
        if (App.StartupArgs.Any(a => string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase)) &&
            _vm.StartMinimizedToTray)
        {
            ShowInTaskbar = false;
            WindowState = WindowState.Minimized;
            Visibility = Visibility.Hidden;
        }

        _tunnelTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.2) };
        _tunnelTimer.Tick += (_, _) =>
        {
            if (_vm.IsTunnelActive && _vm.ActiveTunnelServer is { } srv)
            {
                _vm.RefreshTunnelCounters();
                _tray.UpdateActiveState(true, srv.Name, srv.EndpointLabel, _vm.TargetDomain, _vm.TunnelQueries);
                _ = _vm.CheckActiveTunnelHealthForFailoverAsync();
            }
            else
            {
                _tray.UpdateActiveState(false, null, null, _vm.TargetDomain, 0);
            }
        };
        _tunnelTimer.Start();

        _tray.OnAutoConnectRequested += () => Dispatcher.Invoke(async () => await _vm.RunAutoModeAsync(true, CancellationToken.None));
        _tray.OnRotateRequested += () => Dispatcher.Invoke(async () => await _vm.RotateTunnelAsync());
        _tray.OnDisconnectRequested += () => Dispatcher.Invoke(async () => await _vm.StopTunnelAsync());
        _tray.OnShowWindowRequested += () => Dispatcher.Invoke(RestoreFromTray);
        _tray.OnExitRequested += () => Dispatcher.Invoke(ExitApplicationCompletely);

        Loaded += async (_, _) => await _vm.EnsureStartupSyncAsync(App.StartupArgs);
    }

    private void RestoreFromTray()
    {
        ShowInTaskbar = true;
        Visibility = Visibility.Visible;
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void ExitApplicationCompletely()
    {
        _isExplicitExit = true;
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_isExplicitExit && _vm.MinimizeToTrayOnClose)
        {
            e.Cancel = true;
            ShowInTaskbar = false;
            Hide();
            if (!_shownTrayMinimizeHint)
            {
                _shownTrayMinimizeHint = true;
                _tray.ShowTrayBalloon(
                    "DNS Pulse работает в трее",
                    "Нажмите по иконке в системном трее для открытия или полного закрытия программы.");
            }
            return;
        }

        base.OnClosing(e);
    }

    private void OnMinimizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeRestoreClick(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnCloseWindowClick(object sender, RoutedEventArgs e) => Close();

    private void OnExitCompletelyClick(object sender, RoutedEventArgs e) => ExitApplicationCompletely();

    private void OnToggleThemeClick(object sender, RoutedEventArgs e) =>
        _vm.IsDarkTheme = !_vm.IsDarkTheme;

    private static void ApplyVisualTheme(bool isDarkTheme, string accentPreset)
    {
        var dictUri = isDarkTheme
            ? new Uri("Themes/RestrainedGraphiteDark.xaml", UriKind.Relative)
            : new Uri("Themes/RestrainedGraphiteLight.xaml", UriKind.Relative);

        var dicts = System.Windows.Application.Current.Resources.MergedDictionaries;
        if (dicts.Count > 0)
            dicts[0] = new ResourceDictionary { Source = dictUri };
        else
            dicts.Add(new ResourceDictionary { Source = dictUri });

        var (accentHex, hoverHex, fgHex) = accentPreset switch
        {
            "Azure" => isDarkTheme ? ("#38BDF8", "#0EA5E9", "#082F49") : ("#0284C7", "#0369A1", "#FFFFFF"),
            "Violet" => isDarkTheme ? ("#A78BFA", "#8B5CF6", "#1E1B4B") : ("#7C3AED", "#6D28D9", "#FFFFFF"),
            "Amber" => isDarkTheme ? ("#FBBF24", "#F59E0B", "#2D1602") : ("#D97706", "#B45309", "#FFFFFF"),
            "Rose" => isDarkTheme ? ("#FB7185", "#F43F5E", "#2D0612") : ("#E11D48", "#BE123C", "#FFFFFF"),
            _ => isDarkTheme ? ("#22C55E", "#16A34A", "#062210") : ("#16A34A", "#15803D", "#FFFFFF")
        };

        var accentColor = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(accentHex);
        var hoverColor = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hoverHex);
        var fgColor = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(fgHex);
        var softColor = System.Windows.Media.Color.FromArgb(isDarkTheme ? (byte)32 : (byte)26, accentColor.R, accentColor.G, accentColor.B);
        var selectedColor = System.Windows.Media.Color.FromArgb(isDarkTheme ? (byte)36 : (byte)28, accentColor.R, accentColor.G, accentColor.B);

        var res = System.Windows.Application.Current.Resources;
        res["AccentBrush"] = new SolidColorBrush(accentColor);
        res["AccentHoverBrush"] = new SolidColorBrush(hoverColor);
        res["AccentFgBrush"] = new SolidColorBrush(fgColor);
        res["AccentSoftBrush"] = new SolidColorBrush(softColor);
        res["StatusOkBrush"] = new SolidColorBrush(accentColor);
        res["SelectedSurfaceBrush"] = new SolidColorBrush(selectedColor);
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
        try
        {
            await _vm.StopTunnelAsync();
        }
        catch
        {
            // Ignore shutdown tunnel errors
        }
        _tray.Dispose();
        base.OnClosed(e);
        System.Windows.Application.Current.Shutdown();
    }
}
