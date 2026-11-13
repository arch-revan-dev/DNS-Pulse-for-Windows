using System.Globalization;
using System.Security;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Autostart;

/// <summary>
/// Manages Windows HKCU Run autostart registration for <c>DnsPulse</c> with
/// <c>dotnet.exe</c> host-path rejection, quoted command building, and mandatory registry readback verification.
/// </summary>
public sealed class WindowsAutostartService
{
    public const string RegistryRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string ValueName = "DnsPulse";

    private readonly string _registryRunPath;
    private readonly string _valueName;
    private readonly Func<string?> _executablePathProvider;

    /// <summary>
    /// Initializes a new <see cref="WindowsAutostartService"/> targeting <c>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</c>.
    /// </summary>
    public WindowsAutostartService()
        : this(RegistryRunPath, ValueName, executablePathProvider: null)
    {
    }

    /// <summary>
    /// Initializes a new <see cref="WindowsAutostartService"/> with an explicit HKCU subkey and executable path provider (for testing).
    /// </summary>
    public WindowsAutostartService(
        string registryRunPath,
        string valueName = ValueName,
        Func<string?>? executablePathProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryRunPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(valueName);

        _registryRunPath = registryRunPath.Trim();
        _valueName = valueName.Trim();
        _executablePathProvider = executablePathProvider ?? (static () => Environment.ProcessPath);
    }

    /// <summary>
    /// Gets the diagnostic detail from the most recent autostart check or modification.
    /// </summary>
    public string LastStatusDetail { get; private set; } = string.Empty;

    /// <summary>
    /// Formats a quoted Windows Run command line for <paramref name="executablePath"/>.
    /// </summary>
    public static string BuildQuotedLaunchCommand(string? executablePath, bool startMinimized)
    {
        string cleanExe = (executablePath ?? string.Empty).Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(cleanExe))
        {
            return string.Empty;
        }

        return startMinimized
            ? string.Create(CultureInfo.InvariantCulture, $"\"{cleanExe}\" --autostart --minimized")
            : string.Create(CultureInfo.InvariantCulture, $"\"{cleanExe}\" --autostart");
    }

    /// <summary>
    /// Extracts the executable path from a Windows Run command line string.
    /// </summary>
    public static string? ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        string trimmed = commandLine.Trim();
        if (trimmed.StartsWith('"'))
        {
            int endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return trimmed[1..endQuote];
            }
        }

        int exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
        {
            return trimmed[..(exeIdx + 4)].Trim('"');
        }

        string[] tokens = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return tokens.Length > 0 ? tokens[0] : null;
    }

    /// <summary>
    /// Checks whether autostart is currently registered, points to an existing non-<c>dotnet.exe</c> executable,
    /// and is readable from HKCU Run.
    /// </summary>
    public bool IsEnabled()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(_registryRunPath, writable: false);
            if (key?.GetValue(_valueName) is not string raw || string.IsNullOrWhiteSpace(raw))
            {
                LastStatusDetail = "Autostart is disabled.";
                return false;
            }

            string? exe = ExtractExecutablePath(raw);
            if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe) || IsDotNetHostPath(exe))
            {
                LastStatusDetail = string.Create(CultureInfo.InvariantCulture, $"Stale or invalid autostart entry: {raw}");
                return false;
            }

            LastStatusDetail = string.Create(CultureInfo.InvariantCulture, $"Enabled: {raw}");
            return true;
        }
        catch (SecurityException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (IOException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Registers autostart in HKCU Run for the current executable (rejecting <c>dotnet.exe</c> hosts)
    /// and performs mandatory readback verification.
    /// </summary>
    public bool Enable(bool startMinimized)
    {
        try
        {
            string? currentExe = _executablePathProvider();
            if (string.IsNullOrWhiteSpace(currentExe) || !File.Exists(currentExe))
            {
                LastStatusDetail = "Executable path could not be resolved on disk.";
                return false;
            }

            if (IsDotNetHostPath(currentExe))
            {
                LastStatusDetail = "Refusing to register dotnet.exe host as autostart target; use compiled DnsPulse.exe.";
                return false;
            }

            string expectedCommand = BuildQuotedLaunchCommand(currentExe, startMinimized);
            if (string.IsNullOrEmpty(expectedCommand))
            {
                LastStatusDetail = "Launch command was empty.";
                return false;
            }

            using RegistryKey? key = Registry.CurrentUser.CreateSubKey(_registryRunPath, writable: true);
            if (key is null)
            {
                LastStatusDetail = "Unable to open HKCU Run registry key.";
                return false;
            }

            key.SetValue(_valueName, expectedCommand, RegistryValueKind.String);
            string? readBack = key.GetValue(_valueName) as string;
            if (!string.Equals(readBack, expectedCommand, StringComparison.OrdinalIgnoreCase))
            {
                LastStatusDetail = "Autostart registry readback verification failed.";
                return false;
            }

            LastStatusDetail = string.Create(CultureInfo.InvariantCulture, $"Verified and enabled: {readBack}");
            return true;
        }
        catch (SecurityException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (IOException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Removes the autostart entry from HKCU Run and verifies removal via readback.
    /// </summary>
    public bool Disable()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(_registryRunPath, writable: true);
            if (key is null)
            {
                LastStatusDetail = "Autostart is disabled.";
                return true;
            }

            key.DeleteValue(_valueName, throwOnMissingValue: false);
            string? check = key.GetValue(_valueName) as string;
            bool removed = string.IsNullOrEmpty(check);
            LastStatusDetail = removed
                ? "Autostart disabled."
                : "Failed to remove autostart registry value.";
            return removed;
        }
        catch (SecurityException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (IOException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// If an autostart entry already exists in HKCU Run, heals stale paths or minimized flags
    /// to point at the current non-<c>dotnet.exe</c> executable.
    /// </summary>
    public bool RepairIfEnabled(bool startMinimized)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(_registryRunPath, writable: false);
            if (key?.GetValue(_valueName) is not string existing || string.IsNullOrWhiteSpace(existing))
            {
                LastStatusDetail = "Autostart not registered; no repair needed.";
                return false;
            }

            string? currentExe = _executablePathProvider();
            if (string.IsNullOrWhiteSpace(currentExe) || !File.Exists(currentExe) || IsDotNetHostPath(currentExe))
            {
                LastStatusDetail = "Skipping autostart repair for invalid or dotnet.exe host path.";
                return false;
            }

            string expectedCommand = BuildQuotedLaunchCommand(currentExe, startMinimized);
            if (string.Equals(existing, expectedCommand, StringComparison.OrdinalIgnoreCase))
            {
                LastStatusDetail = "Autostart entry already matches current executable.";
                return true;
            }

            return Enable(startMinimized);
        }
        catch (SecurityException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
        catch (IOException ex)
        {
            LastStatusDetail = ex.Message;
            return false;
        }
    }

    private static bool IsDotNetHostPath(string executablePath)
    {
        string fileName = Path.GetFileName(executablePath.Trim().Trim('"'));
        return string.Equals(fileName, "dotnet.exe", StringComparison.OrdinalIgnoreCase);
    }
}
