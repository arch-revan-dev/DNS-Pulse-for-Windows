using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace DnsPulse.App.Services;

public static class WindowsAutostartService
{
    public const string RegistryRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string ValueName = "DnsPulse";

    public static string BuildQuotedLaunchCommand(string executablePath, bool startMinimized)
    {
        var cleanExe = (executablePath ?? string.Empty).Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(cleanExe))
            return string.Empty;

        return startMinimized
            ? $"\"{cleanExe}\" --autostart --minimized"
            : $"\"{cleanExe}\" --autostart";
    }

    public static string? ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return null;

        var trimmed = commandLine.Trim();
        if (trimmed.StartsWith('"'))
        {
            int endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1)
                return trimmed[1..endQuote];
        }

        int exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
            return trimmed[..(exeIdx + 4)].Trim('"');

        return trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
    }

    [SupportedOSPlatform("windows")]
    public static (bool IsEnabled, string Detail) GetStatus()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegistryRunPath, writable: false);
            var raw = key?.GetValue(ValueName) as string;
            if (string.IsNullOrWhiteSpace(raw))
                return (false, "Автозапуск отключён");

            var exe = ExtractExecutablePath(raw);
            if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
                return (false, $"Запись устарела (файл не найден): {raw}");

            return (true, $"Активен: {raw}");
        }
        catch (Exception ex)
        {
            return (false, $"Ошибка чтения реестра: {ex.Message}");
        }
    }

    [SupportedOSPlatform("windows")]
    public static (bool Ok, string Detail) SetEnabled(bool enabled, bool startMinimized)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegistryRunPath, writable: true)
                            ?? Registry.CurrentUser.CreateSubKey(RegistryRunPath, writable: true);
            if (key is null)
                return (false, "Не удалось открыть ветку реестра HKCU Run");

            if (!enabled)
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
                var check = key.GetValue(ValueName) as string;
                return string.IsNullOrEmpty(check)
                    ? (true, "Автозапуск отключён")
                    : (false, "Не удалось удалить запись автозапуска из реестра");
            }

            var currentExe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(currentExe) || !File.Exists(currentExe))
                return (false, "Не определён путь к исполняемому файлу DnsPulse.exe");

            if (currentExe.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase))
                return (false, "Запуск через dotnet host: используйте собранный DnsPulse.exe");

            var expectedCmd = BuildQuotedLaunchCommand(currentExe, startMinimized);
            key.SetValue(ValueName, expectedCmd, RegistryValueKind.String);

            // Mandatory readback verification so broken/blocked autostart never fails silently
            var readBack = key.GetValue(ValueName) as string;
            if (!string.Equals(readBack, expectedCmd, StringComparison.OrdinalIgnoreCase))
                return (false, "Запись автозапуска не подтверждена системой (проверьте антивирус)");

            return (true, $"Проверен и включён: {readBack}");
        }
        catch (Exception ex)
        {
            return (false, $"Ошибка настройки автозапуска: {ex.Message}");
        }
    }

    /// <summary>
    /// If autostart is enabled in settings, ensures HKCU Run points to the current executable path
    /// (auto-heals stale paths after moving folder or running an in-app GitHub update).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static void RepairIfEnabled(bool enabled, bool startMinimized)
    {
        if (!enabled) return;
        var currentExe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(currentExe) ||
            currentExe.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        SetEnabled(true, startMinimized);
    }
}
