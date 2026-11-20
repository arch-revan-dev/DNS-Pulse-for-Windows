using System.Collections;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Wpf.Ui.Controls;

namespace DnsPulse.App.Views;

/// <summary>
/// Primary application shell hosting proactive advisories, custom glass sidebar navigation, and tray-minimize lifecycle.
/// </summary>
public sealed partial class MainWindow : FluentWindow
{
    private readonly MainShellViewModel _viewModel;
    private readonly IServiceProvider _serviceProvider;
    private readonly ThemeAppearanceService _themeService;
    private readonly object _collectionSyncLock = new();
    private bool _allowClose;

    public MainWindow(
        MainShellViewModel viewModel,
        IServiceProvider serviceProvider,
        ThemeAppearanceService themeService)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(themeService);

        _viewModel = viewModel;
        _serviceProvider = serviceProvider;
        _themeService = themeService;
        DataContext = viewModel;

        InitializeComponent();
        EnableCrossThreadCollectionSync();

        WindowBackdropType = _themeService.CurrentBackdrop;

        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        _themeService.PropertyChanged += OnThemeServicePropertyChanged;
        Loaded += OnLoaded;
    }

    /// <summary>
    /// Marks the window to exit completely on the next close instead of minimizing to the system tray.
    /// </summary>
    public void AllowClose()
    {
        _allowClose = true;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        if (!_allowClose && TrayIconService.ShouldMinimizeToTrayOnClose(_viewModel.Settings.BuildNormalizedSettings()))
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _themeService.PropertyChanged -= OnThemeServicePropertyChanged;
        base.OnClosed(e);

        if (_allowClose || !TrayIconService.ShouldMinimizeToTrayOnClose(_viewModel.Settings.BuildNormalizedSettings()))
        {
            System.Windows.Application.Current?.Shutdown();
        }
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        WindowBackdropType = _themeService.CurrentBackdrop;
        _themeService.ReapplyCurrentTheme();
        NavigateToSelectedPage();
        _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, _themeService.ReapplyCurrentTheme);
        _ = _viewModel.Settings.TryAutoCheckUpdatesOnStartupAsync();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(e.PropertyName, nameof(MainShellViewModel.SelectedPage), StringComparison.Ordinal))
        {
            Dispatcher.InvokeAsync(NavigateToSelectedPage);
        }
    }

    private void OnThemeServicePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(e.PropertyName, nameof(ThemeAppearanceService.CurrentBackdrop), StringComparison.Ordinal))
        {
            Dispatcher.InvokeAsync(() => WindowBackdropType = _themeService.CurrentBackdrop);
        }
    }

    private void NavigateToSelectedPage()
    {
        if (!IsLoaded)
        {
            return;
        }

        Type pageType = _viewModel.SelectedPage switch
        {
            ShellPageKind.Routing => typeof(RoutingInspectorPage),
            ShellPageKind.Servers => typeof(ServersCatalogPage),
            ShellPageKind.Diagnostics => typeof(DiagnosticsDoctorPage),
            ShellPageKind.Settings => typeof(SettingsSafetyPage),
            _ => typeof(OverviewPage)
        };

        object page = _serviceProvider.GetRequiredService(pageType);
        PageHost.Content = page;
    }

    private void EnableCrossThreadCollectionSync()
    {
        IEnumerable[] collections =
        [
            _viewModel.NavigationItems,
            _viewModel.Overview.P50SparklineSamples,
            _viewModel.Overview.StrategyProfiles,
            _viewModel.Overview.DetectedAiApps,
            _viewModel.Overview.AiServiceChecks,
            _viewModel.Routing.ServicePresets,
            _viewModel.Routing.TelemetryEvents,
            _viewModel.Routing.FilteredTelemetryEvents,
            _viewModel.Routing.ImportedIpRanges,
            _viewModel.Servers.FilteredServers,
            _viewModel.Servers.CategoryFilterOptions,
            _viewModel.Servers.AvailableFeeds,
            _viewModel.Servers.Tier1Servers,
            _viewModel.Servers.Tier2Servers,
            _viewModel.Servers.Tier3Servers,
            _viewModel.Servers.Tier4Servers,
            _viewModel.Servers.TrustTierSections,
            _viewModel.Diagnostics.Layers,
            _viewModel.Diagnostics.LabDiscoveredNodes
        ];

        foreach (IEnumerable collection in collections)
        {
            BindingOperations.EnableCollectionSynchronization(collection, _collectionSyncLock);
        }

        foreach (TrustTierSectionInfo section in _viewModel.Servers.TrustTierSections)
        {
            BindingOperations.EnableCollectionSynchronization(section.Servers, _collectionSyncLock);
        }
    }
}
