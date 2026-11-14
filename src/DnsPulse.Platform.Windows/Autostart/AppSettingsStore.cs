using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security;
using System.Text.Json;
using System.Text.Json.Serialization;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Updates;

namespace DnsPulse.Platform.Windows.Autostart;

/// <summary>
/// Atomic, crash-safe JSON persistence store for <see cref="PulseAppSettings"/> at
/// <c>%APPDATA%\DnsPulse\settings.json</c> with automatic v1.5.3 (<c>%APPDATA%\DNS-Pulse\settings.json</c>) migration.
/// </summary>
public sealed class AppSettingsStore
{
    private const string SettingsFileName = "settings.json";

    private static readonly ConcurrentDictionary<string, SemaphoreSlim> PerPathLocks = new(StringComparer.OrdinalIgnoreCase);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private SemaphoreSlim PathGate => PerPathLocks.GetOrAdd(SettingsFilePath, static _ => new SemaphoreSlim(1, 1));

    /// <summary>
    /// Initializes a new <see cref="AppSettingsStore"/>.
    /// </summary>
    /// <param name="baseDirectory">
    /// Optional explicit directory for <c>settings.json</c>; defaults to <c>%APPDATA%\DnsPulse</c>.
    /// </param>
    /// <param name="legacyBaseDirectory">
    /// Optional legacy v1.5.3 settings directory; defaults to <c>%APPDATA%\DNS-Pulse</c> when <paramref name="baseDirectory"/> is omitted.
    /// </param>
    public AppSettingsStore(string? baseDirectory = null, string? legacyBaseDirectory = null)
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrWhiteSpace(appData))
        {
            appData = Path.GetTempPath();
        }

        string resolvedDir = string.IsNullOrWhiteSpace(baseDirectory)
            ? Path.Combine(appData, "DnsPulse")
            : Path.GetFullPath(baseDirectory.Trim());

        BaseDirectory = resolvedDir;
        SettingsFilePath = Path.Combine(resolvedDir, SettingsFileName);

        if (!string.IsNullOrWhiteSpace(legacyBaseDirectory))
        {
            LegacySettingsFilePath = Path.Combine(Path.GetFullPath(legacyBaseDirectory.Trim()), SettingsFileName);
        }
        else if (string.IsNullOrWhiteSpace(baseDirectory))
        {
            LegacySettingsFilePath = Path.Combine(appData, "DNS-Pulse", SettingsFileName);
        }
    }

    /// <summary>
    /// Gets the primary directory holding <c>settings.json</c>.
    /// </summary>
    public string BaseDirectory { get; }

    /// <summary>
    /// Gets the primary <c>settings.json</c> file path.
    /// </summary>
    public string SettingsFilePath { get; }

    /// <summary>
    /// Gets the optional legacy v1.5.3 <c>settings.json</c> fallback path.
    /// </summary>
    public string? LegacySettingsFilePath { get; }

    /// <summary>
    /// Loads and normalizes <see cref="PulseAppSettings"/> from disk (falling back to legacy v1.5.3
    /// settings if primary does not exist, or safe defaults on missing/corrupted JSON).
    /// </summary>
    public PulseAppSettings Load()
    {
        PathGate.Wait();
        try
        {
            return LoadUnlocked();
        }
        finally
        {
            PathGate.Release();
        }
    }

    /// <summary>
    /// Asynchronously loads and normalizes <see cref="PulseAppSettings"/> from disk.
    /// </summary>
    public async Task<PulseAppSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await PathGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadUnlockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            PathGate.Release();
        }
    }

    /// <summary>
    /// Normalizes and atomically persists <paramref name="settings"/> using a write-through <c>.tmp</c> file.
    /// </summary>
    public void Save(PulseAppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Normalize(settings);

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions);
        string tempPath = string.Concat(SettingsFilePath, ".tmp");
        string backupPath = string.Concat(SettingsFilePath, ".bak");

        PathGate.Wait();
        try
        {
            Directory.CreateDirectory(BaseDirectory);
            using (FileStream stream = new(
                tempPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush();
            }

            CommitTempFile(tempPath, backupPath);
            LogSettingsSaved(settings, bytes.Length);
        }
        catch (Exception ex)
        {
            PlatformDiagnosticLog.Write(string.Create(CultureInfo.InvariantCulture, $"Failed to save settings to '{SettingsFilePath}'."), ex);
            throw;
        }
        finally
        {
            PathGate.Release();
        }
    }

    /// <summary>
    /// Asynchronously normalizes and atomically persists <paramref name="settings"/> using a write-through <c>.tmp</c> file.
    /// </summary>
    public async Task SaveAsync(PulseAppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Normalize(settings);

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions);
        string tempPath = string.Concat(SettingsFilePath, ".tmp");
        string backupPath = string.Concat(SettingsFilePath, ".bak");

        await PathGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(BaseDirectory);
            await using (FileStream stream = new(
                tempPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            CommitTempFile(tempPath, backupPath);
            LogSettingsSaved(settings, bytes.Length);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            PlatformDiagnosticLog.Write(string.Create(CultureInfo.InvariantCulture, $"Failed to save settings asynchronously to '{SettingsFilePath}'."), ex);
            throw;
        }
        finally
        {
            PathGate.Release();
        }
    }

    /// <summary>
    /// Atomically loads, mutates, normalizes, and persists <see cref="PulseAppSettings"/> under the per-path lock.
    /// </summary>
    public async Task<PulseAppSettings> UpdateAsync(
        Action<PulseAppSettings> updateAction,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(updateAction);
        await PathGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PulseAppSettings current = await LoadUnlockedAsync(cancellationToken).ConfigureAwait(false);
            updateAction(current);
            Normalize(current);

            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(current, JsonOptions);
            string tempPath = string.Concat(SettingsFilePath, ".tmp");
            string backupPath = string.Concat(SettingsFilePath, ".bak");

            Directory.CreateDirectory(BaseDirectory);
            await using (FileStream stream = new(
                tempPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            CommitTempFile(tempPath, backupPath);
            LogSettingsSaved(current, bytes.Length);
            return current;
        }
        finally
        {
            PathGate.Release();
        }
    }

    /// <summary>
    /// Clamps numeric ranges and validates enum/string presets on <paramref name="settings"/>.
    /// </summary>
    public static void Normalize(PulseAppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        settings.AccentPreset = settings.AccentPreset switch
        {
            "Azure" or "Violet" or "Amber" or "Rose" => settings.AccentPreset,
            _ => "Emerald"
        };

        settings.BootstrapDnsProvider = settings.BootstrapDnsProvider switch
        {
            "1.1.1.1" or "8.8.8.8" or "9.9.9.9" => settings.BootstrapDnsProvider,
            _ => "Auto"
        };

        settings.ProbeTimeoutMs = Math.Clamp(settings.ProbeTimeoutMs, 1000, 6000);
        settings.BenchmarkConcurrency = Math.Clamp(settings.BenchmarkConcurrency, 2, 16);
        settings.LocalDnsPort = NormalizePort(settings.LocalDnsPort);
        settings.LocalDohPort = NormalizePort(settings.LocalDohPort);
        settings.LocalProxyPort = NormalizePort(settings.LocalProxyPort);
        settings.LocalPacPort = NormalizePort(settings.LocalPacPort);

        settings.GitHubToken = (settings.GitHubToken ?? string.Empty).Trim();
        settings.UiLanguage = string.IsNullOrWhiteSpace(settings.UiLanguage)
            ? "en-US"
            : settings.UiLanguage.Trim();

        if (!Enum.IsDefined(settings.InterceptionMode))
        {
            settings.InterceptionMode = InterceptionMode.AdapterDns;
        }

        if (!Enum.IsDefined(settings.UpdateChannel))
        {
            settings.UpdateChannel = UpdateChannel.Stable;
        }

        if (!Enum.IsDefined(settings.PoolStrategy))
        {
            settings.PoolStrategy = PoolSelectionStrategy.Fastest;
        }

        settings.SelectedQuickServiceId = string.IsNullOrWhiteSpace(settings.SelectedQuickServiceId)
            ? "google_ai_studio"
            : settings.SelectedQuickServiceId.Trim();

        settings.LastVerifiedTargetDomain = string.IsNullOrWhiteSpace(settings.LastVerifiedTargetDomain)
            ? "aistudio.google.com"
            : settings.LastVerifiedTargetDomain.Trim();

        settings.StrategyProfile = string.IsNullOrWhiteSpace(settings.StrategyProfile)
            ? "SmartSplitDnsGeo"
            : settings.StrategyProfile.Trim();

        settings.SelectedTrustedUpstreamId = string.IsNullOrWhiteSpace(settings.SelectedTrustedUpstreamId)
            ? null
            : settings.SelectedTrustedUpstreamId.Trim();

        settings.SelectedGeoUnlockUpstreamId = string.IsNullOrWhiteSpace(settings.SelectedGeoUnlockUpstreamId)
            ? null
            : settings.SelectedGeoUnlockUpstreamId.Trim();

        settings.EnabledRoutingPresetIds = settings.EnabledRoutingPresetIds?
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Select(static id => id.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        settings.CustomGeoUnlockDomains = NormalizeRuleList(settings.CustomGeoUnlockDomains);
        settings.CustomBlockRules = NormalizeRuleList(settings.CustomBlockRules);
        settings.CustomAllowRules = NormalizeRuleList(settings.CustomAllowRules);
    }

    private static int NormalizePort(int port) => port <= 0 ? 0 : Math.Clamp(port, 1, 65535);

    private static string[] NormalizeRuleList(IReadOnlyList<string>? rules)
    {
        if (rules is null || rules.Count == 0)
        {
            return [];
        }

        return
        [
            .. rules
                .Where(static r => !string.IsNullOrWhiteSpace(r))
                .Select(static r => r.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
        ];
    }

    private PulseAppSettings LoadUnlocked()
    {
        if (TryReadSettings(SettingsFilePath, out PulseAppSettings? primary))
        {
            LogSettingsLoaded(SettingsFilePath, primary);
            return primary;
        }

        if (!string.IsNullOrWhiteSpace(LegacySettingsFilePath) &&
            TryReadSettings(LegacySettingsFilePath, out PulseAppSettings? legacy))
        {
            LogSettingsLoaded(LegacySettingsFilePath, legacy);
            return legacy;
        }

        PulseAppSettings defaults = new();
        Normalize(defaults);
        PlatformDiagnosticLog.Write(string.Create(
            CultureInfo.InvariantCulture,
            $"Settings not found at '{SettingsFilePath}'; using defaults (Language={defaults.UiLanguage}, Dark={defaults.IsDarkTheme}, DnsPort={defaults.LocalDnsPort})."));
        return defaults;
    }

    private async Task<PulseAppSettings> LoadUnlockedAsync(CancellationToken cancellationToken)
    {
        string? pathToRead = File.Exists(SettingsFilePath)
            ? SettingsFilePath
            : !string.IsNullOrWhiteSpace(LegacySettingsFilePath) && File.Exists(LegacySettingsFilePath)
                ? LegacySettingsFilePath
                : null;

        if (pathToRead is not null)
        {
            try
            {
                byte[] bytes = await File.ReadAllBytesAsync(pathToRead, cancellationToken).ConfigureAwait(false);
                PulseAppSettings? parsed = JsonSerializer.Deserialize<PulseAppSettings>(bytes, JsonOptions);
                if (parsed is not null)
                {
                    Normalize(parsed);
                    LogSettingsLoaded(pathToRead, parsed);
                    return parsed;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or SecurityException)
            {
                PlatformDiagnosticLog.Write(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Error loading settings from '{pathToRead}'; falling back to defaults."), ex);
            }
        }

        PulseAppSettings defaults = new();
        Normalize(defaults);
        PlatformDiagnosticLog.Write(string.Create(
            CultureInfo.InvariantCulture,
            $"Settings initialized with defaults (File='{SettingsFilePath}', Exists={File.Exists(SettingsFilePath)}, Language={defaults.UiLanguage}, DnsPort={defaults.LocalDnsPort})."));
        return defaults;
    }

    private void CommitTempFile(string tempPath, string backupPath)
    {
        if (File.Exists(SettingsFilePath))
        {
            try
            {
                File.Replace(tempPath, SettingsFilePath, backupPath, ignoreMetadataErrors: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                PlatformDiagnosticLog.Write(string.Create(
                    CultureInfo.InvariantCulture,
                    $"File.Replace failed for '{SettingsFilePath}', falling back to File.Move overwrite."), ex);
            }
        }

        File.Move(tempPath, SettingsFilePath, overwrite: true);
    }

    private static void LogSettingsLoaded(string path, PulseAppSettings settings)
    {
        PlatformDiagnosticLog.Write(string.Create(
            CultureInfo.InvariantCulture,
            $"Loaded settings from '{path}' (Language={settings.UiLanguage}, Dark={settings.IsDarkTheme}, Accent={settings.AccentPreset}, Mode={settings.InterceptionMode}, Ports=[DNS:{settings.LocalDnsPort}, DoH:{settings.LocalDohPort}, Proxy:{settings.LocalProxyPort}, PAC:{settings.LocalPacPort}], Strategy={settings.StrategyProfile})."));
    }

    private void LogSettingsSaved(PulseAppSettings settings, int byteCount)
    {
        PlatformDiagnosticLog.Write(string.Create(
            CultureInfo.InvariantCulture,
            $"Saved settings to '{SettingsFilePath}' ({byteCount} bytes; Language={settings.UiLanguage}, Dark={settings.IsDarkTheme}, Accent={settings.AccentPreset}, Mode={settings.InterceptionMode}, Ports=[DNS:{settings.LocalDnsPort}, DoH:{settings.LocalDohPort}, Proxy:{settings.LocalProxyPort}, PAC:{settings.LocalPacPort}], Strategy={settings.StrategyProfile})."));
    }

    private static bool TryReadSettings(string path, [NotNullWhen(true)] out PulseAppSettings? result)
    {
        result = null;
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            byte[] raw = File.ReadAllBytes(path);
            PulseAppSettings? parsed = JsonSerializer.Deserialize<PulseAppSettings>(raw, JsonOptions);
            if (parsed is null)
            {
                return false;
            }

            Normalize(parsed);
            result = parsed;
            return true;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or SecurityException)
        {
            PlatformDiagnosticLog.Write(string.Create(
                CultureInfo.InvariantCulture,
                $"Error reading settings from '{path}'."), ex);
            return false;
        }
    }
}
