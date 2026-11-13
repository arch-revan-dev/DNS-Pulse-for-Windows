using System.IO;
using System.Text.Json;

namespace DnsPulse.App.Services;

public sealed class AppSettings
{
    public bool IsDarkTheme { get; set; } = true;
    public string AccentPreset { get; set; } = "Emerald";
    public bool CompactMode { get; set; }

    public bool StartWithWindows { get; set; }
    public bool StartMinimizedToTray { get; set; } = true;
    public bool MinimizeToTrayOnClose { get; set; } = true;

    public bool AutoModeEnabled { get; set; }
    public bool AutoFailoverOnDrop { get; set; } = true;

    public bool AutoCheckUpdates { get; set; } = true;
    public bool AutoSyncFeedsOnStartup { get; set; } = true;

    public bool SplitTunnelEnabled { get; set; } = true;
    public bool BlockIpv6OnBypass { get; set; } = true;
    public string BootstrapDnsProvider { get; set; } = "Auto";
    public int ProbeTimeoutMs { get; set; } = 2600;
    public int BenchmarkConcurrency { get; set; } = 6;
}

public sealed class AppSettingsService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true
    };

    private readonly string _settingsPath;

    public AppSettingsService(string? appDataDir = null)
    {
        var dir = string.IsNullOrWhiteSpace(appDataDir)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse")
            : appDataDir;
        Directory.CreateDirectory(dir);
        _settingsPath = Path.Combine(dir, "settings.json");
    }

    public AppSettings Load()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var raw = File.ReadAllText(_settingsPath);
                var parsed = JsonSerializer.Deserialize<AppSettings>(raw);
                if (parsed is not null)
                {
                    Normalize(parsed);
                    return parsed;
                }
            }
        }
        catch
        {
            // Fall back to safe defaults on corrupted JSON
        }

        var defaults = new AppSettings();
        Normalize(defaults);
        return defaults;
    }

    public void Save(AppSettings settings)
    {
        Normalize(settings);
        var dir = Path.GetDirectoryName(_settingsPath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(_settingsPath, JsonSerializer.Serialize(settings, JsonOpts));
    }

    public static void Normalize(AppSettings s)
    {
        s.AccentPreset = s.AccentPreset switch
        {
            "Azure" or "Violet" or "Amber" or "Rose" => s.AccentPreset,
            _ => "Emerald"
        };

        s.BootstrapDnsProvider = s.BootstrapDnsProvider switch
        {
            "1.1.1.1" or "8.8.8.8" or "9.9.9.9" => s.BootstrapDnsProvider,
            _ => "Auto"
        };

        s.ProbeTimeoutMs = Math.Clamp(s.ProbeTimeoutMs, 1000, 6000);
        s.BenchmarkConcurrency = Math.Clamp(s.BenchmarkConcurrency, 2, 16);
    }
}
