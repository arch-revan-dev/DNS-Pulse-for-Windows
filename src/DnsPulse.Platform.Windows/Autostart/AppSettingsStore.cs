using System.Diagnostics.CodeAnalysis;
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

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly Lock _syncLock = new();

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
        lock (_syncLock)
        {
            if (TryReadSettings(SettingsFilePath, out PulseAppSettings? primary))
            {
                return primary;
            }

            if (!string.IsNullOrWhiteSpace(LegacySettingsFilePath) &&
                TryReadSettings(LegacySettingsFilePath, out PulseAppSettings? legacy))
            {
                return legacy;
            }

            PulseAppSettings defaults = new();
            Normalize(defaults);
            return defaults;
        }
    }

    /// <summary>
    /// Asynchronously loads and normalizes <see cref="PulseAppSettings"/> from disk.
    /// </summary>
    public async Task<PulseAppSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

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
                    return parsed;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (JsonException)
            {
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (SecurityException)
            {
            }
        }

        PulseAppSettings defaults = new();
        Normalize(defaults);
        return defaults;
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

        lock (_syncLock)
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

            if (File.Exists(SettingsFilePath))
            {
                File.Replace(tempPath, SettingsFilePath, backupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, SettingsFilePath, overwrite: true);
            }
        }
    }

    /// <summary>
    /// Asynchronously normalizes and atomically persists <paramref name="settings"/> using a write-through <c>.tmp</c> file.
    /// </summary>
    public async Task SaveAsync(PulseAppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Normalize(settings);

        Directory.CreateDirectory(BaseDirectory);
        string tempPath = string.Concat(SettingsFilePath, ".tmp");
        string backupPath = string.Concat(SettingsFilePath, ".bak");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions);

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

        lock (_syncLock)
        {
            if (File.Exists(SettingsFilePath))
            {
                File.Replace(tempPath, SettingsFilePath, backupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, SettingsFilePath, overwrite: true);
            }
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
        catch (JsonException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (SecurityException)
        {
            return false;
        }
    }
}
