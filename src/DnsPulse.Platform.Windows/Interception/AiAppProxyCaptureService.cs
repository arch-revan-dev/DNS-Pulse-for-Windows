using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using DnsPulse.Core.Models;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Runtime discovery snapshot for a desktop or CLI AI application on Windows.
/// </summary>
public sealed record DetectedAiAppStatus(
    AiAppProfile Profile,
    bool IsInstalled,
    string? ExecutablePath,
    bool IsRunning);

/// <summary>
/// Result of attempting to launch an AI desktop or CLI application through DNS Pulse's local loopback proxy.
/// </summary>
public sealed record AiAppLaunchResult(bool Succeeded, string Message);

/// <summary>
/// Crash-safe snapshot of per-user <c>HKCU\Environment</c> proxy variables modified by DNS Pulse.
/// </summary>
public sealed class UserEnvProxyBackupSnapshot
{
    [SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "JSON deserialization DTO for environment backup.")]
    public Dictionary<string, string?> PriorValues { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public int ActiveProxyPort { get; set; }

    public DateTimeOffset CapturedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Captures desktop and CLI AI applications (Antigravity, Claude Code, Cursor, Windsurf, Codex CLI,
/// Gemini CLI, ChatGPT Desktop, VS Code Copilot) into DNS Pulse's local loopback HTTP/SOCKS5 proxy
/// while keeping loopback IPC bypassed via <see cref="AiAppCatalog.LoopbackSafeNoProxy"/>.
/// </summary>
public static class AiAppProxyCaptureService
{
    private const string EnvironmentSubKey = "Environment";

    private static readonly string[] ManagedEnvVarNames =
    [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_USE_ENV_PROXY",
        "GRPC_PROXY_EXP"
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Gets the default backup path for storing prior user environment variables prior to capture.
    /// </summary>
    public static string GetDefaultBackupPath()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        return Path.Combine(appData, "DnsPulse", "ai_env_proxy_backup.json");
    }

    /// <summary>
    /// Scans the local Windows host for installed and currently running AI desktop/CLI applications.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Process and filesystem discovery must stay resilient to inaccessible processes or restricted paths.")]
    public static IReadOnlyList<DetectedAiAppStatus> DetectInstalledAndRunningApps()
    {
        List<DetectedAiAppStatus> results = new(AiAppCatalog.DesktopApps.Count);
        foreach (AiAppProfile profile in AiAppCatalog.DesktopApps)
        {
            string? resolvedPath = ResolveInstalledExecutablePath(profile);
            bool running = IsAnyProcessRunning(profile.ProcessNames);
            results.Add(new DetectedAiAppStatus(
                Profile: profile,
                IsInstalled: resolvedPath is not null,
                ExecutablePath: resolvedPath,
                IsRunning: running));
        }

        return results;
    }

    /// <summary>
    /// Writes loopback-safe <c>HTTP_PROXY</c>/<c>HTTPS_PROXY</c>/<c>ALL_PROXY</c>/<c>NO_PROXY</c>/<c>NODE_USE_ENV_PROXY</c>/<c>GRPC_PROXY_EXP</c>
    /// variables into <c>HKCU\Environment</c> after backing up any prior user values, and broadcasts <c>WM_SETTINGCHANGE</c>.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Best-effort registry and broadcast update must not crash tunnel activation.")]
    public static bool EnableUserEnvironmentProxy(int localProxyPort, string? backupFilePath = null)
    {
        if (localProxyPort is <= 0 or > 65535)
        {
            return false;
        }

        string effectiveBackupPath = string.IsNullOrWhiteSpace(backupFilePath)
            ? GetDefaultBackupPath()
            : backupFilePath;

        try
        {
            using RegistryKey envKey = Registry.CurrentUser.CreateSubKey(EnvironmentSubKey, writable: true);
            if (!File.Exists(effectiveBackupPath))
            {
                UserEnvProxyBackupSnapshot backup = new()
                {
                    ActiveProxyPort = localProxyPort,
                    CapturedAtUtc = DateTimeOffset.UtcNow
                };

                foreach (string name in ManagedEnvVarNames)
                {
                    backup.PriorValues[name] = envKey.GetValue(name) as string;
                }

                string? dir = Path.GetDirectoryName(effectiveBackupPath);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                string json = JsonSerializer.Serialize(backup, JsonOptions);
                File.WriteAllText(effectiveBackupPath, json, Encoding.UTF8);
            }

            string proxyUrl = string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{localProxyPort}");
            envKey.SetValue("HTTP_PROXY", proxyUrl, RegistryValueKind.String);
            envKey.SetValue("HTTPS_PROXY", proxyUrl, RegistryValueKind.String);
            envKey.SetValue("ALL_PROXY", proxyUrl, RegistryValueKind.String);
            envKey.SetValue("NO_PROXY", AiAppCatalog.LoopbackSafeNoProxy, RegistryValueKind.String);
            envKey.SetValue("NODE_USE_ENV_PROXY", "1", RegistryValueKind.String);
            envKey.SetValue("GRPC_PROXY_EXP", proxyUrl, RegistryValueKind.String);

            BroadcastEnvironmentChanged();
            return true;
        }
        catch (Exception ex)
        {
            PlatformDiagnosticLog.Write("Failed to enable user environment proxy capture for AI apps.", ex);
            return false;
        }
    }

    /// <summary>
    /// Restores the user's original <c>HKCU\Environment</c> proxy variables from backup (or removes keys
    /// added by DNS Pulse), deletes the backup file, and broadcasts <c>WM_SETTINGCHANGE</c>.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Environment restore runs during disconnect and emergency recovery and must stay exception-safe.")]
    public static bool RestoreUserEnvironmentProxy(string? backupFilePath = null)
    {
        string effectiveBackupPath = string.IsNullOrWhiteSpace(backupFilePath)
            ? GetDefaultBackupPath()
            : backupFilePath;

        if (!File.Exists(effectiveBackupPath))
        {
            return false;
        }

        try
        {
            string rawJson = File.ReadAllText(effectiveBackupPath, Encoding.UTF8);
            UserEnvProxyBackupSnapshot? snapshot = JsonSerializer.Deserialize<UserEnvProxyBackupSnapshot>(rawJson, JsonOptions);

            using RegistryKey? envKey = Registry.CurrentUser.OpenSubKey(EnvironmentSubKey, writable: true);
            if (envKey is not null && snapshot is not null)
            {
                foreach (string name in ManagedEnvVarNames)
                {
                    if (snapshot.PriorValues.TryGetValue(name, out string? priorValue) && !string.IsNullOrWhiteSpace(priorValue))
                    {
                        envKey.SetValue(name, priorValue, RegistryValueKind.String);
                    }
                    else
                    {
                        envKey.DeleteValue(name, throwOnMissingValue: false);
                    }
                }
            }

            File.Delete(effectiveBackupPath);
            BroadcastEnvironmentChanged();
            return true;
        }
        catch (Exception ex)
        {
            PlatformDiagnosticLog.Write("Failed to restore user environment proxy variables.", ex);
            return false;
        }
    }

    /// <summary>
    /// Launches an AI desktop or CLI application with explicit local loopback proxy environment variables
    /// and Chromium/Electron <c>--proxy-server</c> flags (with loopback IPC excluded).
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "App launch errors are returned as status messages to the UI.")]
    public static AiAppLaunchResult LaunchAppThroughLocalProxy(
        AiAppProfile app,
        string? executablePath,
        int localProxyPort)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (localProxyPort is <= 0 or > 65535)
        {
            return new AiAppLaunchResult(false, "Local AI proxy is not active yet.");
        }

        string proxyUrl = string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{localProxyPort}");
        string? resolvedExe = !string.IsNullOrWhiteSpace(executablePath) && File.Exists(executablePath)
            ? executablePath
            : ResolveInstalledExecutablePath(app);

        try
        {
            ProcessStartInfo startInfo;
            if (!string.IsNullOrWhiteSpace(resolvedExe) && resolvedExe.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase))
            {
                startInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = string.Create(CultureInfo.InvariantCulture, $"/k \"\"{resolvedExe}\" --version & echo DNS Pulse AI proxy active on {proxyUrl}\""),
                    UseShellExecute = false
                };
            }
            else if (!string.IsNullOrWhiteSpace(resolvedExe))
            {
                startInfo = new ProcessStartInfo
                {
                    FileName = resolvedExe,
                    UseShellExecute = false
                };

                if (app.SupportsChromiumProxyFlag)
                {
                    startInfo.ArgumentList.Add(string.Concat("--proxy-server=", proxyUrl));
                    startInfo.ArgumentList.Add(string.Concat("--proxy-bypass-list=", AiAppCatalog.ChromiumProxyBypassList));
                }
            }
            else
            {
                return new AiAppLaunchResult(
                    false,
                    string.Create(CultureInfo.InvariantCulture, $"{app.DisplayName} executable not found on disk."));
            }

            startInfo.Environment["HTTP_PROXY"] = proxyUrl;
            startInfo.Environment["HTTPS_PROXY"] = proxyUrl;
            startInfo.Environment["ALL_PROXY"] = proxyUrl;
            startInfo.Environment["NO_PROXY"] = AiAppCatalog.LoopbackSafeNoProxy;
            startInfo.Environment["NODE_USE_ENV_PROXY"] = "1";
            startInfo.Environment["GRPC_PROXY_EXP"] = proxyUrl;

            using Process? started = Process.Start(startInfo);
            if (started is null)
            {
                return new AiAppLaunchResult(
                    false,
                    string.Create(CultureInfo.InvariantCulture, $"Could not start {app.DisplayName}."));
            }

            return new AiAppLaunchResult(
                true,
                string.Create(CultureInfo.InvariantCulture, $"{app.DisplayName} launched via {proxyUrl}"));
        }
        catch (Exception ex)
        {
            return new AiAppLaunchResult(false, ex.Message);
        }
    }

    /// <summary>
    /// Builds a copy-pasteable PowerShell command that launches the given AI app or CLI through DNS Pulse's local tunnel.
    /// </summary>
    public static string BuildPowerShellLaunchSnippet(AiAppProfile app, int localProxyPort)
    {
        ArgumentNullException.ThrowIfNull(app);
        int port = localProxyPort is > 0 and <= 65535 ? localProxyPort : 18753;
        string proxyUrl = string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{port}");
        StringBuilder sb = new();
        sb.Append(CultureInfo.InvariantCulture, $"$env:HTTP_PROXY='{proxyUrl}'; ");
        sb.Append(CultureInfo.InvariantCulture, $"$env:HTTPS_PROXY='{proxyUrl}'; ");
        sb.Append(CultureInfo.InvariantCulture, $"$env:ALL_PROXY='{proxyUrl}'; ");
        sb.Append(CultureInfo.InvariantCulture, $"$env:NO_PROXY='{AiAppCatalog.LoopbackSafeNoProxy}'; ");
        sb.Append("$env:NODE_USE_ENV_PROXY='1'; ");
        sb.Append(CultureInfo.InvariantCulture, $"$env:GRPC_PROXY_EXP='{proxyUrl}'");

        if (app.SupportsChromiumProxyFlag && app.ExecutableProbePaths.Count > 0)
        {
            string expanded = Environment.ExpandEnvironmentVariables(app.ExecutableProbePaths[0]);
            sb.Append(CultureInfo.InvariantCulture, $"; & '{expanded}' --proxy-server={proxyUrl} --proxy-bypass-list=\"{AiAppCatalog.ChromiumProxyBypassList}\"");
        }
        else if (app.ProcessNames.Count > 0)
        {
            sb.Append(CultureInfo.InvariantCulture, $"; {app.ProcessNames[0]}");
        }

        return sb.ToString();
    }

    private static string? ResolveInstalledExecutablePath(AiAppProfile profile)
    {
        foreach (string rawCandidate in profile.ExecutableProbePaths)
        {
            string expanded = Environment.ExpandEnvironmentVariables(rawCandidate);
            if (!string.IsNullOrWhiteSpace(expanded) && File.Exists(expanded))
            {
                return expanded;
            }
        }

        return null;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Process enumeration can fail on restricted Windows accounts.")]
    private static bool IsAnyProcessRunning(IReadOnlyList<string> processNames)
    {
        foreach (string name in processNames)
        {
            try
            {
                Process[] matches = Process.GetProcessesByName(name);
                bool found = matches.Length > 0;
                foreach (Process proc in matches)
                {
                    proc.Dispose();
                }

                if (found)
                {
                    return true;
                }
            }
            catch (Exception)
            {
            }
        }

        return false;
    }

    private static void BroadcastEnvironmentChanged()
    {
        try
        {
            _ = NativeMethods.SendMessageTimeoutW(
                NativeMethods.HwndBroadcast,
                NativeMethods.WmSettingChange,
                nint.Zero,
                "Environment",
                NativeMethods.SmtoAbortIfHung,
                1500,
                out _);
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
    }

    [SuppressMessage("Interoperability", "SYSLIB1054:Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time", Justification = "AllowUnsafeBlocks is not enabled in the project.")]
    private static class NativeMethods
    {
        internal static readonly nint HwndBroadcast = new(0xffff);
        internal const uint WmSettingChange = 0x001A;
        internal const uint SmtoAbortIfHung = 0x0002;

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern nint SendMessageTimeoutW(
            nint hWnd,
            uint msg,
            nint wParam,
            string lParam,
            uint fuFlags,
            uint uTimeout,
            out nint lpdwResult);
    }
}
