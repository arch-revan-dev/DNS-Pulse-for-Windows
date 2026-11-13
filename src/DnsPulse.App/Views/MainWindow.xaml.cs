using System.Collections;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;
using Wpf.Ui.Controls;

namespace DnsPulse.App.Views;

/// <summary>
/// Primary Fluent 2 application shell hosting proactive advisories, 5-page navigation, and tray-minimize lifecycle.
/// </summary>
public sealed partial class MainWindow : FluentWindow
{
    private readonly MainShellViewModel _viewModel;
    private readonly ThemeAppearanceService _themeService;
    private readonly object _collectionSyncLock = new();
    private bool _allowClose;
    private bool _isSyncingNavigation;

    public MainWindow(
        MainShellViewModel viewModel,
        IServiceProvider serviceProvider,
        ThemeAppearanceService themeService)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(themeService);

        _viewModel = viewModel;
        _themeService = themeService;
        DataContext = viewModel;

        InitializeComponent();
        EnableCrossThreadCollectionSync();

        RootNavigation.SetServiceProvider(serviceProvider);
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
        NavigateToSelectedPage();
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

    private void OnNavigationNavigated(NavigationView sender, NavigatedEventArgs args)
    {
        if (_isSyncingNavigation)
        {
            return;
        }

        ShellPageKind target = args.Page switch
        {
            RoutingInspectorPage => ShellPageKind.Routing,
            ServersCatalogPage => ShellPageKind.Servers,
            DiagnosticsDoctorPage => ShellPageKind.Diagnostics,
            SettingsSafetyPage => ShellPageKind.Settings,
            _ => ShellPageKind.Overview
        };

        if (_viewModel.SelectedPage != target)
        {
            _viewModel.NavigateTo(target);
        }
    }

    private void NavigateToSelectedPage()
    {
        if (!RootNavigation.IsLoaded)
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

        _isSyncingNavigation = true;
        try
        {
            RootNavigation.Navigate(pageType);
        }
        finally
        {
            _isSyncingNavigation = false;
        }
    }

    private void EnableCrossThreadCollectionSync()
    {
        IEnumerable[] collections =
        [
            _viewModel.NavigationItems,
            _viewModel.Overview.P50SparklineSamples,
            _viewModel.Overview.StrategyProfiles,
            _viewModel.Routing.ServicePresets,
            _viewModel.Routing.TelemetryEvents,
            _viewModel.Routing.FilteredTelemetryEvents,
            _viewModel.Servers.FilteredServers,
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
