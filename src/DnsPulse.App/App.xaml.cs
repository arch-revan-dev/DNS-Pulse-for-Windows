using System.Diagnostics.CodeAnalysis;
using System.Windows;
using DnsPulse.App.Converters;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;
using DnsPulse.App.Views;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Recovery;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace DnsPulse.App;

/// <summary>
/// WPF application entry point managing CLI early-exit recovery, DI container setup,
/// zero-PII logging, tray integration, Fluent 2 Mica theming, and crash-safe hooks.
/// </summary>
public sealed partial class App : System.Windows.Application, IDisposable
{
    private ServiceProvider? _serviceProvider;
    private TrayIconService? _trayIconService;
    private MainWindow? _mainWindow;
    private bool _disposed;

    /// <summary>
    /// Builds the application's dependency injection container, registering core services,
    /// all 6 ViewModels, and shell views. Supports optional overrides for headless testing.
    /// </summary>
    public static ServiceProvider BuildServiceProvider(Action<IServiceCollection>? configureOverrides = null)
    {
        ServiceCollection services = new();

        services.AddSingleton<LocalizationService>();
        services.AddSingleton<ThemeAppearanceService>();
        services.AddSingleton<AppSettingsStore>();
        services.AddSingleton<PulseCatalogRepository>();
        services.AddSingleton<NetworkSnapshotJournal>();
        services.AddSingleton<WindowsAutostartService>();
        services.AddSingleton<HybridPulseRuntimeService>();
        services.AddSingleton<IPulseRuntimeService>(static sp => sp.GetRequiredService<HybridPulseRuntimeService>());
        services.AddSingleton<TrayIconService>();

        services.AddSingleton<OverviewViewModel>();
        services.AddSingleton<RoutingInspectorViewModel>();
        services.AddSingleton<ServersCatalogViewModel>();
        services.AddSingleton<DiagnosticsDoctorViewModel>();
        services.AddSingleton<SettingsSafetyViewModel>();
        services.AddSingleton<MainShellViewModel>();

        services.AddSingleton<OverviewPage>();
        services.AddSingleton<RoutingInspectorPage>();
        services.AddSingleton<ServersCatalogPage>();
        services.AddSingleton<DiagnosticsDoctorPage>();
        services.AddSingleton<SettingsSafetyPage>();
        services.AddSingleton<MainWindow>();

        configureOverrides?.Invoke(services);

        return services.BuildServiceProvider();
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Top-level startup handler logs fatal errors before shutting down cleanly.")]
    protected override async void OnStartup(StartupEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);
        base.OnStartup(e);

        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        try
        {
            CliLaunchOptions cliOptions = CliArgumentHandler.Parse(e.Args);
            LoggingSetupService.InitializeGlobalLogger();

            int? earlyExitCode = await CliArgumentHandler.TryHandleEarlyExitAsync(cliOptions).ConfigureAwait(true);
            if (earlyExitCode.HasValue)
            {
                Shutdown(earlyExitCode.Value);
                return;
            }

            _serviceProvider = BuildServiceProvider();
            LocalizationService localization = _serviceProvider.GetRequiredService<LocalizationService>();
            LocalizationSource.Instance.Attach(localization);

            NetworkSnapshotJournal journal = _serviceProvider.GetRequiredService<NetworkSnapshotJournal>();
            NetworkSnapshotJournal.RegisterEmergencyProcessHooks(journal);

            MainShellViewModel shell = _serviceProvider.GetRequiredService<MainShellViewModel>();
            IPulseRuntimeService runtime = _serviceProvider.GetRequiredService<IPulseRuntimeService>();
            ThemeAppearanceService themeService = _serviceProvider.GetRequiredService<ThemeAppearanceService>();

            runtime.TelemetryReceived += (_, args) =>
            {
                LoggingSetupService.LogQueryIfOptedIn(
                    Log.Logger,
                    args.TelemetryEvent,
                    shell.Settings.ZeroDiskQueryLogging);
            };

            await shell.InitializeAsync(cliOptions).ConfigureAwait(true);

            _trayIconService = _serviceProvider.GetRequiredService<TrayIconService>();
            _trayIconService.Initialize();
            _trayIconService.UpdateConnectionState(shell.Overview.IsConnected, shell.Overview.HeroStatusTitle);

            runtime.StatusChanged += (_, args) =>
            {
                _ = Dispatcher.InvokeAsync(() =>
                {
                    _trayIconService?.UpdateConnectionState(args.Snapshot.IsConnected, shell.Overview.HeroStatusTitle);
                });
            };

            WireTrayEvents(_trayIconService, shell);

            _mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
            _mainWindow.WindowBackdropType = themeService.CurrentBackdrop;
            MainWindow = _mainWindow;

            PulseAppSettings normalizedSettings = shell.Settings.BuildNormalizedSettings();
            if (!TrayIconService.ShouldStartMinimized(normalizedSettings, cliOptions))
            {
                _mainWindow.Show();
            }
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Unhandled exception during PulseCore startup.");
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Dispose();
        LoggingSetupService.CloseAndFlush();
        base.OnExit(e);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _trayIconService?.Dispose();
        _trayIconService = null;

        _serviceProvider?.Dispose();
        _serviceProvider = null;
    }

    private void WireTrayEvents(TrayIconService tray, MainShellViewModel shell)
    {
        tray.ConnectDisconnectRequested += (_, _) =>
        {
            _ = Dispatcher.InvokeAsync(async () => await shell.Overview.ToggleConnectionCommand.ExecuteAsync(null).ConfigureAwait(true));
        };

        tray.RotateUpstreamRequested += (_, _) =>
        {
            _ = Dispatcher.InvokeAsync(async () => await shell.Overview.RotateUpstreamCommand.ExecuteAsync(null).ConfigureAwait(true));
        };

        tray.EmergencyRestoreRequested += (_, _) =>
        {
            _ = Dispatcher.InvokeAsync(async () => await shell.Settings.EmergencyNetworkRestoreCommand.ExecuteAsync(null).ConfigureAwait(true));
        };

        tray.OpenWindowRequested += (_, _) =>
        {
            _ = Dispatcher.InvokeAsync(ShowAndActivateMainWindow);
        };

        tray.ExitRequested += (_, _) =>
        {
            _ = Dispatcher.InvokeAsync(() =>
            {
                _mainWindow?.AllowClose();
                _mainWindow?.Close();
                Shutdown(0);
            });
        };
    }

    private void ShowAndActivateMainWindow()
    {
        if (_mainWindow is null)
        {
            return;
        }

        if (!_mainWindow.IsVisible)
        {
            _mainWindow.Show();
        }

        if (_mainWindow.WindowState == WindowState.Minimized)
        {
            _mainWindow.WindowState = WindowState.Normal;
        }

        _mainWindow.Activate();
    }
}
