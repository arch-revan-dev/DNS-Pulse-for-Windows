using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Manages the per-user WinINet <c>AutoConfigURL</c> registry setting and notifies Windows HTTP/browser stacks of changes.
/// </summary>
public static class WinInetProxyManager
{
    private const string InternetSettingsSubKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string AutoConfigUrlValueName = "AutoConfigURL";

    /// <summary>
    /// Reads the current user's WinINet <c>AutoConfigURL</c> value, or <see langword="null"/> when unset.
    /// </summary>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "WinINet AutoConfigURL is stored and returned as a raw registry string.")]
    public static string? GetCurrentAutoConfigUrl()
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: false);
        string? value = key?.GetValue(AutoConfigUrlValueName) as string;
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>
    /// Sets the current user's WinINet <c>AutoConfigURL</c> to <paramref name="pacUrl"/> and returns the prior value.
    /// </summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "WinINet AutoConfigURL is persisted as a registry string.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "Returns the raw prior AutoConfigURL registry string.")]
    public static string? SetAutoConfigUrl(string pacUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pacUrl);

        using RegistryKey key = Registry.CurrentUser.CreateSubKey(InternetSettingsSubKey, writable: true);
        string? prior = key.GetValue(AutoConfigUrlValueName) as string;

        key.SetValue(AutoConfigUrlValueName, pacUrl.Trim(), RegistryValueKind.String);
        NotifyWinInetSettingsChanged();

        return string.IsNullOrWhiteSpace(prior) ? null : prior;
    }

    /// <summary>
    /// Clears the current user's WinINet <c>AutoConfigURL</c> and returns the prior value.
    /// </summary>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "Returns the raw prior AutoConfigURL registry string.")]
    public static string? ClearAutoConfigUrl()
    {
        return RestoreAutoConfigUrl(null);
    }

    /// <summary>
    /// Restores <c>AutoConfigURL</c> to <paramref name="priorAutoConfigUrl"/> (or deletes it when <see langword="null"/> or whitespace) and returns the replaced value.
    /// </summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "WinINet AutoConfigURL is persisted as a registry string.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "Returns the raw replaced AutoConfigURL registry string.")]
    public static string? RestoreAutoConfigUrl(string? priorAutoConfigUrl)
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: true);
        if (key is null)
        {
            return null;
        }

        string? previous = key.GetValue(AutoConfigUrlValueName) as string;

        if (string.IsNullOrWhiteSpace(priorAutoConfigUrl))
        {
            key.DeleteValue(AutoConfigUrlValueName, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(AutoConfigUrlValueName, priorAutoConfigUrl.Trim(), RegistryValueKind.String);
        }

        NotifyWinInetSettingsChanged();
        return string.IsNullOrWhiteSpace(previous) ? null : previous;
    }

    private static void NotifyWinInetSettingsChanged()
    {
        try
        {
            _ = NativeMethods.InternetSetOption(0, NativeMethods.InternetOptionSettingsChanged, 0, 0);
            _ = NativeMethods.InternetSetOption(0, NativeMethods.InternetOptionRefresh, 0, 0);
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
        internal const int InternetOptionSettingsChanged = 39;
        internal const int InternetOptionRefresh = 37;

        [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InternetSetOption(nint hInternet, int dwOption, nint lpBuffer, int dwBufferLength);
    }
}
