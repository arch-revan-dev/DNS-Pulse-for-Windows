using System.Security;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Manages the Windows Smart Multi-Homed Name Resolution (SMHNR) Group Policy setting.
/// </summary>
public static class SmhnrPolicyManager
{
    private const string DnsClientPolicySubKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string DisableSmartNameResolutionValue = "DisableSmartNameResolution";

    /// <summary>
    /// Returns <see langword="true"/> when Smart Multi-Homed Name Resolution is explicitly disabled via policy.
    /// </summary>
    public static bool IsSmhnrDisabled()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(DnsClientPolicySubKey, writable: false);
            object? raw = key?.GetValue(DisableSmartNameResolutionValue);
            return raw is int intValue && intValue == 1;
        }
        catch (SecurityException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Enables or disables the <c>DisableSmartNameResolution</c> policy in <c>HKLM</c>.
    /// </summary>
    public static void SetSmhnrDisabled(bool disabled)
    {
        if (disabled)
        {
            using RegistryKey key = Registry.LocalMachine.CreateSubKey(DnsClientPolicySubKey, writable: true);
            key.SetValue(DisableSmartNameResolutionValue, 1, RegistryValueKind.DWord);
        }
        else
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(DnsClientPolicySubKey, writable: true);
            key?.DeleteValue(DisableSmartNameResolutionValue, throwOnMissingValue: false);
        }
    }
}
