using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Text.Json;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Detects browser-level DNS-over-HTTPS (DoH) bypass configurations and manages Windows Group Policy overrides for Chrome, Edge, and Firefox.
/// </summary>
public sealed class BrowserDohInspector
{
    private const string ChromePolicySubKey = @"SOFTWARE\Policies\Google\Chrome";
    private const string EdgePolicySubKey = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string FirefoxDohPolicySubKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

    private const string ChromeAppPathSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe";
    private const string EdgeAppPathSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe";
    private const string FirefoxAppPathSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe";

    private const string DnsOverHttpsModeValue = "DnsOverHttpsMode";
    private const string BuiltInDnsClientEnabledValue = "BuiltInDnsClientEnabled";

    private static readonly RegistryKey[] PolicyRoots = [Registry.LocalMachine, Registry.CurrentUser];

    /// <summary>
    /// Inspects Windows policy keys and local browser profiles to identify browsers that may bypass local DNS interception via built-in DoH.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public IReadOnlyList<string> DetectBypassingBrowsers()
    {
        List<string> bypassing = [];

        if (IsChromiumBypassing(
                ChromePolicySubKey,
                ChromeAppPathSubKey,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Local State")))
        {
            bypassing.Add("Chrome");
        }

        if (IsChromiumBypassing(
                EdgePolicySubKey,
                EdgeAppPathSubKey,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Local State")))
        {
            bypassing.Add("Edge");
        }

        if (IsFirefoxBypassing())
        {
            bypassing.Add("Firefox");
        }

        return bypassing;
    }

    /// <summary>
    /// Applies or clears Windows Group Policy entries disabling built-in browser DoH for Chrome, Edge, and Firefox.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public void SetBrowserDohPoliciesDisabled(bool apply)
    {
        SetChromiumPolicy(ChromePolicySubKey, apply);
        SetChromiumPolicy(EdgePolicySubKey, apply);
        SetFirefoxPolicy(apply);
    }

    private static bool IsChromiumBypassing(string policySubKey, string appPathSubKey, string localStatePath)
    {
        (bool hasPolicyOverride, bool policyDisablesDoh, bool policyEnablesDoh) = ReadChromiumPolicy(policySubKey);
        if (hasPolicyOverride)
        {
            if (policyDisablesDoh)
            {
                return false;
            }

            if (policyEnablesDoh)
            {
                return true;
            }
        }

        string? localStateMode = ReadChromiumLocalStateDohMode(localStatePath);
        if (string.Equals(localStateMode, "off", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.Equals(localStateMode, "automatic", StringComparison.OrdinalIgnoreCase)
            || string.Equals(localStateMode, "secure", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        bool installed = IsAppInstalled(appPathSubKey) || File.Exists(localStatePath);
        return installed;
    }

    private static (bool HasOverride, bool DisablesDoh, bool EnablesDoh) ReadChromiumPolicy(string policySubKey)
    {
        foreach (RegistryKey root in PolicyRoots)
        {
            try
            {
                using RegistryKey? key = root.OpenSubKey(policySubKey, writable: false);
                if (key is null)
                {
                    continue;
                }

                string? mode = key.GetValue(DnsOverHttpsModeValue) as string;
                object? builtInObj = key.GetValue(BuiltInDnsClientEnabledValue);

                bool disables = string.Equals(mode, "off", StringComparison.OrdinalIgnoreCase)
                    || (builtInObj is int builtInInt && builtInInt == 0);

                bool enables = string.Equals(mode, "automatic", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(mode, "secure", StringComparison.OrdinalIgnoreCase)
                    || (builtInObj is int builtInEnabled && builtInEnabled == 1);

                if (disables || enables)
                {
                    return (true, disables, enables);
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

        return (false, false, false);
    }

    private static string? ReadChromiumLocalStateDohMode(string localStatePath)
    {
        if (!File.Exists(localStatePath))
        {
            return null;
        }

        try
        {
            using FileStream stream = File.OpenRead(localStatePath);
            using JsonDocument doc = JsonDocument.Parse(stream);

            if (doc.RootElement.TryGetProperty("dns_over_https", out JsonElement dohElement)
                && dohElement.ValueKind == JsonValueKind.Object
                && dohElement.TryGetProperty("mode", out JsonElement modeElement)
                && modeElement.ValueKind == JsonValueKind.String)
            {
                return modeElement.GetString();
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (JsonException)
        {
        }

        return null;
    }

    private static bool IsFirefoxBypassing()
    {
        foreach (RegistryKey root in PolicyRoots)
        {
            try
            {
                using RegistryKey? key = root.OpenSubKey(FirefoxDohPolicySubKey, writable: false);
                if (key?.GetValue("Enabled") is int enabled)
                {
                    return enabled != 0;
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

        string profilesRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla",
            "Firefox",
            "Profiles");

        if (Directory.Exists(profilesRoot))
        {
            try
            {
                foreach (string profileDir in Directory.EnumerateDirectories(profilesRoot))
                {
                    string prefsPath = Path.Combine(profileDir, "prefs.js");
                    if (!File.Exists(prefsPath))
                    {
                        continue;
                    }

                    foreach (string line in File.ReadLines(prefsPath))
                    {
                        if (!line.Contains("network.trr.mode", StringComparison.Ordinal))
                        {
                            continue;
                        }

                        if (line.Contains(", 2)", StringComparison.Ordinal)
                            || line.Contains(", 3)", StringComparison.Ordinal))
                        {
                            return true;
                        }

                        if (line.Contains(", 5)", StringComparison.Ordinal))
                        {
                            return false;
                        }
                    }
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return IsAppInstalled(FirefoxAppPathSubKey);
    }

    private static bool IsAppInstalled(string appPathSubKey)
    {
        foreach (RegistryKey root in PolicyRoots)
        {
            try
            {
                using RegistryKey? key = root.OpenSubKey(appPathSubKey, writable: false);
                if (key is not null)
                {
                    return true;
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

        return false;
    }

    private static void SetChromiumPolicy(string policySubKey, bool apply)
    {
        if (apply)
        {
            using RegistryKey key = Registry.LocalMachine.CreateSubKey(policySubKey, writable: true);
            key.SetValue(DnsOverHttpsModeValue, "off", RegistryValueKind.String);
            key.SetValue(BuiltInDnsClientEnabledValue, 0, RegistryValueKind.DWord);
        }
        else
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(policySubKey, writable: true);
            if (key is not null)
            {
                key.DeleteValue(DnsOverHttpsModeValue, throwOnMissingValue: false);
                key.DeleteValue(BuiltInDnsClientEnabledValue, throwOnMissingValue: false);
            }
        }
    }

    private static void SetFirefoxPolicy(bool apply)
    {
        if (apply)
        {
            using RegistryKey key = Registry.LocalMachine.CreateSubKey(FirefoxDohPolicySubKey, writable: true);
            key.SetValue("Enabled", 0, RegistryValueKind.DWord);
            key.SetValue("Locked", 1, RegistryValueKind.DWord);
        }
        else
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(FirefoxDohPolicySubKey, writable: true);
            if (key is not null)
            {
                key.DeleteValue("Enabled", throwOnMissingValue: false);
                key.DeleteValue("Locked", throwOnMissingValue: false);
            }
        }
    }
}
