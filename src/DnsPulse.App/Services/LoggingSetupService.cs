using System.Globalization;
using System.IO;
using DnsPulse.Engine.Contracts;
using Serilog;
using Serilog.Core;

namespace DnsPulse.App.Services;

/// <summary>
/// Configures daily rolling Serilog file logging (<c>%APPDATA%\DnsPulse\logs\pulse-.log</c>)
/// while strictly enforcing zero disk query PII logging unless explicitly opted in by the user.
/// </summary>
public static class LoggingSetupService
{
    private const string DefaultLogFilePattern = "pulse-.log";

    /// <summary>
    /// Resolves the default log directory (<c>%APPDATA%\DnsPulse\logs</c>).
    /// </summary>
    public static string GetDefaultLogDirectory()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrWhiteSpace(appData))
        {
            appData = Path.GetTempPath();
        }

        return Path.Combine(appData, "DnsPulse", "logs");
    }

    /// <summary>
    /// Creates a Serilog <see cref="Logger"/> writing daily rolling files into <paramref name="logDirectory"/>.
    /// </summary>
    public static Logger CreateFileLogger(string? logDirectory = null)
    {
        string resolvedDirectory = string.IsNullOrWhiteSpace(logDirectory)
            ? GetDefaultLogDirectory()
            : Path.GetFullPath(logDirectory.Trim());

        Directory.CreateDirectory(resolvedDirectory);

        return new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                Path.Combine(resolvedDirectory, DefaultLogFilePattern),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                formatProvider: CultureInfo.InvariantCulture)
            .CreateLogger();
    }

    /// <summary>
    /// Initializes global <see cref="Log.Logger"/> with daily rolling file output.
    /// </summary>
    public static void InitializeGlobalLogger(string? logDirectory = null)
    {
        Log.Logger = CreateFileLogger(logDirectory);
        Log.Information("PulseCore application logger initialized in {LogDirectory}.", string.IsNullOrWhiteSpace(logDirectory) ? GetDefaultLogDirectory() : logDirectory);
    }

    /// <summary>
    /// Logs a DNS query telemetry event ONLY when <paramref name="zeroDiskQueryLogging"/> is <see langword="false"/>
    /// (explicit user opt-in). When <see langword="true"/> (default), zero domain/query PII is ever written to disk.
    /// </summary>
    public static void LogQueryIfOptedIn(
        ILogger logger,
        DnsQueryTelemetryEvent telemetryEvent,
        bool zeroDiskQueryLogging)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(telemetryEvent);

        if (zeroDiskQueryLogging)
        {
            return;
        }

        logger.Information(
            "DNS Query {Domain} [{RecordType}] -> {Zone} via {Upstream} ({Protocol}) {LatencyMs:F1}ms [{ResponseCode}] {DecisionNote}",
            telemetryEvent.Domain,
            telemetryEvent.RecordType,
            telemetryEvent.Zone,
            telemetryEvent.UpstreamName,
            telemetryEvent.Protocol,
            telemetryEvent.LatencyMs,
            telemetryEvent.ResponseCode,
            telemetryEvent.DecisionNote);
    }

    /// <summary>
    /// Flushes and closes the global Serilog logger.
    /// </summary>
    public static void CloseAndFlush()
    {
        Log.CloseAndFlush();
    }
}
