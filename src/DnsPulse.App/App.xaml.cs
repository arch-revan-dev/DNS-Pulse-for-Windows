using System.Globalization;
using System.IO;
using System.Windows;
using DnsPulse.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace DnsPulse.App;

public sealed partial class App : Application, IDisposable
{
    private ServiceProvider? _serviceProvider;
    private bool _disposed;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        string logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DnsPulse",
            "logs");
        Directory.CreateDirectory(logDirectory);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                Path.Combine(logDirectory, "dnspulse-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                formatProvider: CultureInfo.InvariantCulture)
            .CreateLogger();

        ServiceCollection services = new();
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();

        _serviceProvider = services.BuildServiceProvider();

        MainWindow mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Dispose();
        Log.CloseAndFlush();
        base.OnExit(e);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _serviceProvider?.Dispose();
        _serviceProvider = null;
        _disposed = true;
    }
}
