using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.Platform.Windows.Updates;

/// <summary>
/// Exports a redacted, privacy-preserving diagnostic ZIP bundle containing sanitized settings,
/// optional network snapshot, host health, opted-in telemetry, and scrubbed log files.
/// </summary>
public static partial class DiagnosticBundleExporter
{
    private const int MaxLogFiles = 10;
    private const long MaxBytesPerLogFile = 2 * 1024 * 1024;
    private const string RedactedMarker = "[REDACTED]";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Exports a redacted diagnostic archive to <paramref name="outputZipPath"/>.
    /// Query telemetry is zeroed out unless <paramref name="eventsIfOptedIn"/> is explicitly provided.
    /// </summary>
    public static async Task ExportRedactedBundleAsync(
        string outputZipPath,
        PulseAppSettings settings,
        PrePulseNetworkSnapshot? snapshot,
        HostNetworkHealthSnapshot? hostHealth,
        IReadOnlyList<DnsQueryTelemetryEvent>? eventsIfOptedIn,
        string? logDirectory,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputZipPath);
        ArgumentNullException.ThrowIfNull(settings);
        ct.ThrowIfCancellationRequested();

        string fullOutputPath = Path.GetFullPath(outputZipPath.Trim());
        string? outputDir = Path.GetDirectoryName(fullOutputPath);
        if (!string.IsNullOrWhiteSpace(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }

        string tempZipPath = string.Create(CultureInfo.InvariantCulture, $"{fullOutputPath}.{Guid.NewGuid():N}.tmp");

        try
        {
            PulseAppSettings redactedSettings = CreateRedactedSettings(settings);
            List<DnsQueryTelemetryEvent> sanitizedEvents = SanitizeEvents(eventsIfOptedIn);
            List<(string EntryName, string Content)> scrubbedLogs = await ReadAndScrubLogsAsync(logDirectory, ct).ConfigureAwait(false);

            await using (FileStream zipFileStream = new(
                tempZipPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 81920,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                using (ZipArchive archive = new(zipFileStream, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8))
                {
                    var manifest = new
                    {
                        exportedAtUtc = DateTimeOffset.UtcNow,
                        product = WindowsPlatformInfo.Product,
                        telemetryIncluded = eventsIfOptedIn is not null,
                        telemetryEventCount = sanitizedEvents.Count,
                        snapshotIncluded = snapshot is not null,
                        hostHealthIncluded = hostHealth is not null,
                        logFileCount = scrubbedLogs.Count
                    };

                    await WriteJsonEntryAsync(archive, "manifest.json", manifest, ct).ConfigureAwait(false);
                    await WriteJsonEntryAsync(archive, "settings.json", redactedSettings, ct).ConfigureAwait(false);

                    var telemetryPayload = new
                    {
                        optedIn = eventsIfOptedIn is not null,
                        zeroDiskQueryLogging = settings.ZeroDiskQueryLogging,
                        events = sanitizedEvents
                    };
                    await WriteJsonEntryAsync(archive, "telemetry.json", telemetryPayload, ct).ConfigureAwait(false);

                    if (snapshot is not null)
                    {
                        await WriteJsonEntryAsync(archive, "network_snapshot.json", snapshot, ct).ConfigureAwait(false);
                    }

                    if (hostHealth is not null)
                    {
                        await WriteJsonEntryAsync(archive, "host_health.json", hostHealth, ct).ConfigureAwait(false);
                    }

                    foreach ((string entryName, string content) in scrubbedLogs)
                    {
                        await WriteTextEntryAsync(archive, entryName, content, ct).ConfigureAwait(false);
                    }
                }

                await zipFileStream.FlushAsync(ct).ConfigureAwait(false);
            }

            File.Move(tempZipPath, fullOutputPath, overwrite: true);
        }
        catch
        {
            TryDeleteTempFile(tempZipPath);
            throw;
        }
    }

    /// <summary>
    /// Scrubs bearer tokens, GitHub personal access tokens, <c>GitHubToken</c> values,
    /// authorization headers, and Windows/Unix user profile paths from diagnostic text.
    /// </summary>
    public static string ScrubSensitiveText(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        string scrubbed = input;

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            scrubbed = scrubbed.Replace(userProfile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        }

        scrubbed = WindowsUsersPathRegex().Replace(scrubbed, @"$1[REDACTED]");
        scrubbed = EscapedWindowsUsersPathRegex().Replace(scrubbed, @"$1[REDACTED]");
        scrubbed = BearerTokenRegex().Replace(scrubbed, "Bearer [REDACTED]");
        scrubbed = AuthorizationHeaderRegex().Replace(scrubbed, "Authorization: [REDACTED]");
        scrubbed = GitHubTokenPatternRegex().Replace(scrubbed, "[REDACTED_TOKEN]");
        scrubbed = JsonGitHubTokenRegex().Replace(scrubbed, "\"GitHubToken\": \"[REDACTED]\"");
        scrubbed = KeyValueGitHubTokenRegex().Replace(scrubbed, "GitHubToken=[REDACTED]");

        return scrubbed;
    }

    private static PulseAppSettings CreateRedactedSettings(PulseAppSettings source)
    {
        PulseAppSettings clone = source.Clone();
        clone.GitHubToken = string.IsNullOrWhiteSpace(clone.GitHubToken)
            ? string.Empty
            : RedactedMarker;
        clone.AccentPreset = ScrubSensitiveText(clone.AccentPreset);
        clone.BootstrapDnsProvider = ScrubSensitiveText(clone.BootstrapDnsProvider);
        clone.UiLanguage = ScrubSensitiveText(clone.UiLanguage);
        return clone;
    }

    private static List<DnsQueryTelemetryEvent> SanitizeEvents(IReadOnlyList<DnsQueryTelemetryEvent>? eventsIfOptedIn)
    {
        if (eventsIfOptedIn is null || eventsIfOptedIn.Count == 0)
        {
            return [];
        }

        List<DnsQueryTelemetryEvent> sanitized = new(eventsIfOptedIn.Count);
        foreach (DnsQueryTelemetryEvent item in eventsIfOptedIn)
        {
            sanitized.Add(item with
            {
                UpstreamName = ScrubSensitiveText(item.UpstreamName),
                DecisionNote = ScrubSensitiveText(item.DecisionNote)
            });
        }

        return sanitized;
    }

    private static async Task<List<(string EntryName, string Content)>> ReadAndScrubLogsAsync(
        string? logDirectory,
        CancellationToken ct)
    {
        List<(string EntryName, string Content)> result = [];
        if (string.IsNullOrWhiteSpace(logDirectory) || !Directory.Exists(logDirectory))
        {
            return result;
        }

        DirectoryInfo dir = new(logDirectory);
        List<FileInfo> candidates = [.. dir.EnumerateFiles("*", SearchOption.TopDirectoryOnly)
            .Where(static f => f.Extension.Equals(".log", StringComparison.OrdinalIgnoreCase)
                || f.Extension.Equals(".txt", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(static f => f.LastWriteTimeUtc)
            .Take(MaxLogFiles)];

        foreach (FileInfo file in candidates)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                string rawContent = await ReadBoundedTextAsync(file.FullName, ct).ConfigureAwait(false);
                string scrubbed = ScrubSensitiveText(rawContent);
                result.Add((string.Concat("logs/", file.Name), scrubbed));
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return result;
    }

    private static async Task<string> ReadBoundedTextAsync(string path, CancellationToken ct)
    {
        await using FileStream fs = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 16384,
            FileOptions.Asynchronous);

        if (fs.Length > MaxBytesPerLogFile)
        {
            fs.Seek(fs.Length - MaxBytesPerLogFile, SeekOrigin.Begin);
        }

        using StreamReader reader = new(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        return await reader.ReadToEndAsync(ct).ConfigureAwait(false);
    }

    private static async Task WriteJsonEntryAsync<T>(
        ZipArchive archive,
        string entryName,
        T value,
        CancellationToken ct)
    {
        string json = JsonSerializer.Serialize(value, JsonOptions);
        await WriteTextEntryAsync(archive, entryName, json, ct).ConfigureAwait(false);
    }

    private static async Task WriteTextEntryAsync(
        ZipArchive archive,
        string entryName,
        string content,
        CancellationToken ct)
    {
        ZipArchiveEntry entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        await using Stream entryStream = entry.Open();
        await entryStream.WriteAsync(bytes, ct).ConfigureAwait(false);
    }

    private static void TryDeleteTempFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    [GeneratedRegex(@"([A-Za-z]:\\Users\\)[^\\/:*?""<>|\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WindowsUsersPathRegex();

    [GeneratedRegex(@"([A-Za-z]:\\\\Users\\\\)[^\\/:*?""<>|\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EscapedWindowsUsersPathRegex();

    [GeneratedRegex(@"Bearer\s+[A-Za-z0-9\-._~+/]+=*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BearerTokenRegex();

    [GeneratedRegex(@"Authorization\s*:\s*[^\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationHeaderRegex();

    [GeneratedRegex(@"\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})\b", RegexOptions.CultureInvariant)]
    private static partial Regex GitHubTokenPatternRegex();

    [GeneratedRegex(@"""GitHubToken""\s*:\s*""[^""]*""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsonGitHubTokenRegex();

    [GeneratedRegex(@"GitHubToken\s*=\s*[^\s;,\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex KeyValueGitHubTokenRegex();
}
