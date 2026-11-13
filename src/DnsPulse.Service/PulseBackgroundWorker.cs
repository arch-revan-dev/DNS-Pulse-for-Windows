using DnsPulse.Platform.Windows;

namespace DnsPulse.Service;

public sealed class PulseBackgroundWorker : BackgroundService
{
    private readonly ILogger<PulseBackgroundWorker> _logger;

    public PulseBackgroundWorker(ILogger<PulseBackgroundWorker> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("{Product} Windows Service worker initialized.", WindowsPlatformInfo.Product);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }
}
