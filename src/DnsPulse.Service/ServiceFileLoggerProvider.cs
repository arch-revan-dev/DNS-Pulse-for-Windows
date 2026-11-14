using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace DnsPulse.Service;

/// <summary>
/// Zero-dependency daily rolling file <see cref="ILoggerProvider"/> for <c>DnsPulse.Service</c>.
/// Writes operational diagnostics under <c>%ProgramData%\DnsPulse\logs</c> (with local-appdata fallback).
/// </summary>
[ProviderAlias("PulseFile")]
internal sealed class ServiceFileLoggerProvider : ILoggerProvider
{
    private readonly string _logDirectory;
    private readonly Lock _writeLock = new();
    private readonly ConcurrentDictionary<string, ServiceFileLogger> _loggers = new(StringComparer.Ordinal);
    private bool _disposed;

    public ServiceFileLoggerProvider(string? logDirectory = null)
    {
        _logDirectory = string.IsNullOrWhiteSpace(logDirectory)
            ? GetDefaultServiceLogDirectory()
            : logDirectory;
    }

    public string LogDirectory => _logDirectory;

    public static string GetDefaultServiceLogDirectory()
    {
        string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrWhiteSpace(commonAppData))
        {
            return Path.Combine(commonAppData, "DnsPulse", "logs");
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(localAppData))
        {
            return Path.Combine(localAppData, "DnsPulse", "logs");
        }

        return Path.Combine(Path.GetTempPath(), "DnsPulse", "logs");
    }

    public ILogger CreateLogger(string categoryName)
    {
        return _loggers.GetOrAdd(categoryName, name => new ServiceFileLogger(this, name));
    }

    public void Dispose()
    {
        _disposed = true;
        _loggers.Clear();
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "File logger must never crash the Windows service host.")]
    internal void WriteLine(string category, LogLevel level, EventId eventId, string message, Exception? exception)
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            lock (_writeLock)
            {
                Directory.CreateDirectory(_logDirectory);
                DateTimeOffset now = DateTimeOffset.UtcNow;
                string filePath = Path.Combine(_logDirectory, string.Create(CultureInfo.InvariantCulture, $"service-{now:yyyyMMdd}.log"));
                string formatted = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{now:O} [{level}] [{category}] ({eventId.Id}) {message}");

                using StreamWriter writer = new(filePath, append: true);
                writer.WriteLine(formatted);
                if (exception is not null)
                {
                    writer.WriteLine(exception.ToString());
                }
            }
        }
        catch (Exception)
        {
            // Swallow file-system errors silently to protect service stability.
        }
    }

    private sealed class ServiceFileLogger(ServiceFileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            ArgumentNullException.ThrowIfNull(formatter);
            string message = formatter(state, exception);
            provider.WriteLine(category, logLevel, eventId, message, exception);
        }
    }
}
