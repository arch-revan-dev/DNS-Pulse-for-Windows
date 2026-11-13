using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Manages PulseCore Name Resolution Policy Table (NRPT) split-DNS rules in the Windows Registry.
/// </summary>
public static class NrptPolicyManager
{
    private const string DnsPolicyConfigSubKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    private const string PulseRulePrefix = "PulseCore_";
    private const int NrptVersion = 2;
    private const int GenericDnsServerConfigOption = 0x8;

    /// <summary>
    /// Lists all active PulseCore NRPT rule subkey names currently registered under <c>DnsPolicyConfig</c>.
    /// </summary>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate", Justification = "Reads live Windows Registry subkeys.")]
    public static IReadOnlyList<string> GetPulseNrptRuleNames()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(DnsPolicyConfigSubKey, writable: false);
            if (key is null)
            {
                return [];
            }

            string[] subKeyNames = key.GetSubKeyNames();
            List<string> matches = [];

            foreach (string subKeyName in subKeyNames)
            {
                if (subKeyName.StartsWith(PulseRulePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(subKeyName);
                }
            }

            matches.Sort(StringComparer.OrdinalIgnoreCase);
            return matches;
        }
        catch (SecurityException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (IOException)
        {
            return [];
        }
    }

    /// <summary>
    /// Creates PulseCore NRPT split-DNS rules routing the specified domains to <paramref name="dnsIp"/>.
    /// </summary>
    public static void ApplySplitRules(IPAddress dnsIp, int port, IReadOnlyList<string> domains)
    {
        ArgumentNullException.ThrowIfNull(dnsIp);
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        RemoveAllPulseNrptRules();

        List<string> normalizedDomains = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (string rawDomain in domains)
        {
            if (string.IsNullOrWhiteSpace(rawDomain))
            {
                continue;
            }

            string trimmed = rawDomain.Trim();
            string nrptNamespace = trimmed.StartsWith('.') ? trimmed : string.Create(CultureInfo.InvariantCulture, $".{trimmed}");
            if (seen.Add(nrptNamespace))
            {
                normalizedDomains.Add(nrptNamespace);
            }
        }

        if (normalizedDomains.Count == 0)
        {
            return;
        }

        string genericDnsServers = FormatDnsEndpoint(dnsIp, port);
        using RegistryKey baseKey = Registry.LocalMachine.CreateSubKey(DnsPolicyConfigSubKey, writable: true);

        for (int i = 0; i < normalizedDomains.Count; i++)
        {
            string ruleKeyName = string.Create(CultureInfo.InvariantCulture, $"{PulseRulePrefix}{i + 1:D4}");
            using RegistryKey ruleKey = baseKey.CreateSubKey(ruleKeyName, writable: true);
            ruleKey.SetValue("Name", new string[] { normalizedDomains[i] }, RegistryValueKind.MultiString);
            ruleKey.SetValue("GenericDNSServers", genericDnsServers, RegistryValueKind.String);
            ruleKey.SetValue("ConfigOptions", GenericDnsServerConfigOption, RegistryValueKind.DWord);
            ruleKey.SetValue("Version", NrptVersion, RegistryValueKind.DWord);
        }

        Win32NetworkInterop.FlushDnsResolverCache();
    }

    /// <summary>
    /// Removes all <c>PulseCore_*</c> NRPT rule subkeys from <c>DnsPolicyConfig</c>.
    /// </summary>
    public static void RemoveAllPulseNrptRules()
    {
        using RegistryKey? baseKey = Registry.LocalMachine.OpenSubKey(DnsPolicyConfigSubKey, writable: true);
        if (baseKey is null)
        {
            return;
        }

        string[] subKeyNames = baseKey.GetSubKeyNames();
        bool removedAny = false;

        foreach (string subKeyName in subKeyNames)
        {
            if (subKeyName.StartsWith(PulseRulePrefix, StringComparison.OrdinalIgnoreCase))
            {
                baseKey.DeleteSubKeyTree(subKeyName, throwOnMissingSubKey: false);
                removedAny = true;
            }
        }

        if (removedAny)
        {
            Win32NetworkInterop.FlushDnsResolverCache();
        }
    }

    private static string FormatDnsEndpoint(IPAddress dnsIp, int port)
    {
        if (port == 53)
        {
            return dnsIp.ToString();
        }

        return dnsIp.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Create(CultureInfo.InvariantCulture, $"[{dnsIp}]:{port}")
            : string.Create(CultureInfo.InvariantCulture, $"{dnsIp}:{port}");
    }
}
