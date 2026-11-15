using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
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
    /// When invoked from a <c>LocalSystem</c> Windows Service, also updates loaded interactive user hives under <c>HKEY_USERS</c>.
    /// </summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "WinINet AutoConfigURL is persisted as a registry string.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "Returns the raw prior AutoConfigURL registry string.")]
    public static string? SetAutoConfigUrl(string pacUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pacUrl);

        string trimmedPacUrl = pacUrl.Trim();
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(InternetSettingsSubKey, writable: true);
        string? prior = key.GetValue(AutoConfigUrlValueName) as string;

        key.SetValue(AutoConfigUrlValueName, trimmedPacUrl, RegistryValueKind.String);

        if (IsRunningAsSystem())
        {
            ApplyToLoadedInteractiveUserHives(trimmedPacUrl);
        }

        TrySetWinInetPerConnectionPac(trimmedPacUrl);
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
        string? previous = key?.GetValue(AutoConfigUrlValueName) as string;

        if (key is not null)
        {
            if (string.IsNullOrWhiteSpace(priorAutoConfigUrl))
            {
                key.DeleteValue(AutoConfigUrlValueName, throwOnMissingValue: false);
            }
            else
            {
                key.SetValue(AutoConfigUrlValueName, priorAutoConfigUrl.Trim(), RegistryValueKind.String);
            }
        }

        if (IsRunningAsSystem())
        {
            RestoreLoadedInteractiveUserHives(priorAutoConfigUrl);
        }

        TrySetWinInetPerConnectionPac(string.IsNullOrWhiteSpace(priorAutoConfigUrl) ? null : priorAutoConfigUrl.Trim());
        NotifyWinInetSettingsChanged();
        return string.IsNullOrWhiteSpace(previous) ? null : previous;
    }

    private static bool IsRunningAsSystem()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch (SecurityException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void ApplyToLoadedInteractiveUserHives(string pacUrl)
    {
        foreach (string sid in EnumerateLoadedUserSids())
        {
            try
            {
                string subKeyPath = string.Concat(sid, "\\", InternetSettingsSubKey);
                using RegistryKey userKey = Registry.Users.CreateSubKey(subKeyPath, writable: true);
                userKey.SetValue(AutoConfigUrlValueName, pacUrl, RegistryValueKind.String);
            }
            catch (SecurityException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (IOException)
            {
            }
        }
    }

    private static void RestoreLoadedInteractiveUserHives(string? priorAutoConfigUrl)
    {
        foreach (string sid in EnumerateLoadedUserSids())
        {
            try
            {
                string subKeyPath = string.Concat(sid, "\\", InternetSettingsSubKey);
                using RegistryKey? userKey = Registry.Users.OpenSubKey(subKeyPath, writable: true);
                if (userKey is null)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(priorAutoConfigUrl))
                {
                    userKey.DeleteValue(AutoConfigUrlValueName, throwOnMissingValue: false);
                }
                else
                {
                    userKey.SetValue(AutoConfigUrlValueName, priorAutoConfigUrl.Trim(), RegistryValueKind.String);
                }
            }
            catch (SecurityException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (IOException)
            {
            }
        }
    }

    private static IEnumerable<string> EnumerateLoadedUserSids()
    {
        string[] subKeyNames;
        try
        {
            subKeyNames = Registry.Users.GetSubKeyNames();
        }
        catch (SecurityException)
        {
            yield break;
        }
        catch (UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (string name in subKeyNames)
        {
            if (name.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                && !name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
            {
                yield return name;
            }
        }
    }

    private static void TrySetWinInetPerConnectionPac(string? pacUrl)
    {
        nint pacUrlPtr = nint.Zero;
        nint optionsPtr = nint.Zero;
        nint listPtr = nint.Zero;

        try
        {
            uint currentFlags = QueryCurrentPerConnectionFlags();
            uint nextFlags = string.IsNullOrWhiteSpace(pacUrl)
                ? (currentFlags & ~NativeMethods.ProxyTypeAutoProxyUrl) | NativeMethods.ProxyTypeDirect
                : currentFlags | NativeMethods.ProxyTypeDirect | NativeMethods.ProxyTypeAutoProxyUrl;

            int optionSize = Marshal.SizeOf<NativeMethods.InternetPerConnOption>();
            int optionCount = string.IsNullOrWhiteSpace(pacUrl) ? 1 : 2;
            optionsPtr = Marshal.AllocHGlobal(optionSize * optionCount);

            NativeMethods.InternetPerConnOption flagsOption = new()
            {
                dwOption = NativeMethods.InternetPerConnFlags,
                Value = new NativeMethods.InternetPerConnOptionValue { dwValue = nextFlags }
            };
            Marshal.StructureToPtr(flagsOption, optionsPtr, fDeleteOld: false);

            if (!string.IsNullOrWhiteSpace(pacUrl))
            {
                pacUrlPtr = Marshal.StringToHGlobalUni(pacUrl);
                NativeMethods.InternetPerConnOption pacOption = new()
                {
                    dwOption = NativeMethods.InternetPerConnAutoconfigUrl,
                    Value = new NativeMethods.InternetPerConnOptionValue { pszValue = pacUrlPtr }
                };
                Marshal.StructureToPtr(pacOption, optionsPtr + optionSize, fDeleteOld: false);
            }

            NativeMethods.InternetPerConnOptionList list = new()
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.InternetPerConnOptionList>(),
                pszConnection = nint.Zero,
                dwOptionCount = (uint)optionCount,
                dwOptionError = 0,
                pOptions = optionsPtr
            };

            listPtr = Marshal.AllocHGlobal((int)list.dwSize);
            Marshal.StructureToPtr(list, listPtr, fDeleteOld: false);

            _ = NativeMethods.InternetSetOption(
                0,
                NativeMethods.InternetOptionPerConnectionOption,
                listPtr,
                (int)list.dwSize);
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        finally
        {
            if (listPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(listPtr);
            }

            if (optionsPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(optionsPtr);
            }

            if (pacUrlPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(pacUrlPtr);
            }
        }
    }

    private static uint QueryCurrentPerConnectionFlags()
    {
        nint optionsPtr = nint.Zero;
        nint listPtr = nint.Zero;
        try
        {
            int optionSize = Marshal.SizeOf<NativeMethods.InternetPerConnOption>();
            optionsPtr = Marshal.AllocHGlobal(optionSize);
            NativeMethods.InternetPerConnOption queryOption = new()
            {
                dwOption = NativeMethods.InternetPerConnFlags,
                Value = default
            };
            Marshal.StructureToPtr(queryOption, optionsPtr, fDeleteOld: false);

            NativeMethods.InternetPerConnOptionList list = new()
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.InternetPerConnOptionList>(),
                pszConnection = nint.Zero,
                dwOptionCount = 1,
                dwOptionError = 0,
                pOptions = optionsPtr
            };

            int listSize = (int)list.dwSize;
            listPtr = Marshal.AllocHGlobal(listSize);
            Marshal.StructureToPtr(list, listPtr, fDeleteOld: false);

            if (NativeMethods.InternetQueryOption(0, NativeMethods.InternetOptionPerConnectionOption, listPtr, ref listSize))
            {
                NativeMethods.InternetPerConnOption result = Marshal.PtrToStructure<NativeMethods.InternetPerConnOption>(optionsPtr);
                return result.Value.dwValue;
            }
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        finally
        {
            if (listPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(listPtr);
            }

            if (optionsPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(optionsPtr);
            }
        }

        return NativeMethods.ProxyTypeDirect;
    }

    private static void NotifyWinInetSettingsChanged()
    {
        try
        {
            _ = NativeMethods.InternetSetOption(0, NativeMethods.InternetOptionProxySettingsChanged, 0, 0);
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
        internal const int InternetOptionRefresh = 37;
        internal const int InternetOptionSettingsChanged = 39;
        internal const int InternetOptionPerConnectionOption = 75;
        internal const int InternetOptionProxySettingsChanged = 95;

        internal const uint InternetPerConnFlags = 1;
        internal const uint InternetPerConnAutoconfigUrl = 4;

        internal const uint ProxyTypeDirect = 0x00000001;
        internal const uint ProxyTypeAutoProxyUrl = 0x00000004;

        [StructLayout(LayoutKind.Explicit)]
        internal struct InternetPerConnOptionValue
        {
            [FieldOffset(0)]
            public uint dwValue;

            [FieldOffset(0)]
            public nint pszValue;

            [FieldOffset(0)]
            public long ftValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct InternetPerConnOption
        {
            public uint dwOption;
            public InternetPerConnOptionValue Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct InternetPerConnOptionList
        {
            public uint dwSize;
            public nint pszConnection;
            public uint dwOptionCount;
            public uint dwOptionError;
            public nint pOptions;
        }

        [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InternetSetOption(nint hInternet, int dwOption, nint lpBuffer, int dwBufferLength);

        [DllImport("wininet.dll", EntryPoint = "InternetQueryOptionW", SetLastError = true, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InternetQueryOption(nint hInternet, int dwOption, nint lpBuffer, ref int lpdwBufferLength);
    }
}
