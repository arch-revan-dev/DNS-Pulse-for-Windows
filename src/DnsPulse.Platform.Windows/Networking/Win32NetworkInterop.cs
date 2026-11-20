using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using DnsPulse.Platform.Windows.Contracts;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Result of verifying whether Windows active network adapters report the expected DNS server address.
/// </summary>
public sealed record AdapterDnsVerificationResult(
    bool IsApplied,
    IReadOnlyList<string> VerifiedAdapterNames,
    IReadOnlyList<string> ObservedDnsServers);

/// <summary>
/// Windows networking interop and registry DNS configuration helpers.
/// </summary>
public static class Win32NetworkInterop
{
    private const string TcpipInterfacesSubKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    private const string Tcpip6InterfacesSubKey = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
    private const int NetshTimeoutMs = 5000;

    private static readonly string[] VirtualAdapterDescriptionTokens =
    [
        "VirtualBox",
        "KM-TEST Loopback",
        "Loopback Pseudo-Interface",
        "Teredo",
        "6to4",
        "isatap",
        "Kernel Debug",
        "WAN Miniport"
    ];

    private static readonly char[] DnsServerSeparators = [',', ' ', ';'];

    /// <summary>
    /// Flushes the Windows DNS client resolver cache via <c>dnsapi.dll</c>.
    /// </summary>
    public static void FlushDnsResolverCache()
    {
        try
        {
            _ = NativeMethods.DnsFlushResolverCache();
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
    }

    /// <summary>
    /// Enumerates active physical network adapters and reads their IPv4/IPv6 DNS configuration from the Windows Registry.
    /// </summary>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate", Justification = "Performs live OS adapter and registry enumeration.")]
    public static IReadOnlyList<AdapterDnsConfiguration> GetActivePhysicalAdapters()
    {
        NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
        List<AdapterDnsConfiguration> results = [];

        foreach (NetworkInterface adapter in interfaces)
        {
            if (!IsActivePhysicalAdapter(adapter))
            {
                continue;
            }

            string normalizedGuid = NormalizeInterfaceGuid(adapter.Id);
            if (string.IsNullOrWhiteSpace(normalizedGuid))
            {
                continue;
            }

            (IReadOnlyList<string> ipv4Servers, bool wasDhcpIpv4) = ReadInterfaceDnsServers(TcpipInterfacesSubKey, normalizedGuid);
            (IReadOnlyList<string> ipv6Servers, bool wasDhcpIpv6) = ReadInterfaceDnsServers(Tcpip6InterfacesSubKey, normalizedGuid);

            results.Add(new AdapterDnsConfiguration
            {
                InterfaceGuid = normalizedGuid,
                InterfaceName = adapter.Name,
                InterfaceDescription = adapter.Description,
                OriginalIpv4Dns = ipv4Servers,
                OriginalIpv6Dns = ipv6Servers,
                WasDhcpIpv4 = wasDhcpIpv4,
                WasDhcpIpv6 = wasDhcpIpv6,
                IsPhysicalUp = true
            });
        }

        return results;
    }

    /// <summary>
    /// Applies static IPv4 and IPv6 DNS server addresses to the specified adapter interface GUID.
    /// </summary>
    public static void ApplyAdapterDnsServers(
        string interfaceGuid,
        IReadOnlyList<IPAddress> ipv4Servers,
        IReadOnlyList<IPAddress> ipv6Servers)
    {
        ApplyAdapterDnsServers(interfaceGuid, interfaceName: null, ipv4Servers, ipv6Servers);
    }

    /// <summary>
    /// Applies static IPv4 and IPv6 DNS server addresses via both Windows <c>netsh</c> and Registry <c>NameServer</c>,
    /// then notifies DHCP and flushes the OS DNS resolver cache.
    /// </summary>
    public static void ApplyAdapterDnsServers(
        string interfaceGuid,
        string? interfaceName,
        IReadOnlyList<IPAddress> ipv4Servers,
        IReadOnlyList<IPAddress> ipv6Servers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceGuid);
        ArgumentNullException.ThrowIfNull(ipv4Servers);
        ArgumentNullException.ThrowIfNull(ipv6Servers);

        string normalizedGuid = NormalizeInterfaceGuid(interfaceGuid);
        string? resolvedName = !string.IsNullOrWhiteSpace(interfaceName)
            ? interfaceName
            : TryResolveInterfaceName(normalizedGuid);

        List<IPAddress> validIpv4 = [.. ipv4Servers.Where(static ip => ip.AddressFamily == AddressFamily.InterNetwork)];
        List<IPAddress> validIpv6 = [.. ipv6Servers.Where(static ip => ip.AddressFamily == AddressFamily.InterNetworkV6)];

        if (!string.IsNullOrWhiteSpace(resolvedName))
        {
            foreach (string args in BuildNetshSetDnsArguments(resolvedName, AddressFamily.InterNetwork, validIpv4))
            {
                TryRunNetshBestEffort(args);
            }

            foreach (string args in BuildNetshSetDnsArguments(resolvedName, AddressFamily.InterNetworkV6, validIpv6))
            {
                TryRunNetshBestEffort(args);
            }
        }

        string ipv4Value = string.Join(",", validIpv4.Select(static ip => ip.ToString()));
        string ipv6Value = string.Join(",", validIpv6.Select(static ip => ip.ToString()));

        WriteInterfaceNameServer(TcpipInterfacesSubKey, normalizedGuid, ipv4Value);
        WriteInterfaceNameServer(Tcpip6InterfacesSubKey, normalizedGuid, ipv6Value);

        NotifyDhcpConfigChangeBestEffort(normalizedGuid);
        FlushDnsResolverCache();
    }

    /// <summary>
    /// Restores an adapter's DNS configuration from a previously captured <see cref="AdapterDnsConfiguration"/>.
    /// </summary>
    public static void RestoreAdapterDnsServers(AdapterDnsConfiguration original)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentException.ThrowIfNullOrWhiteSpace(original.InterfaceGuid);

        string normalizedGuid = NormalizeInterfaceGuid(original.InterfaceGuid);
        string? resolvedName = !string.IsNullOrWhiteSpace(original.InterfaceName)
            ? original.InterfaceName
            : TryResolveInterfaceName(normalizedGuid);

        if (!string.IsNullOrWhiteSpace(resolvedName))
        {
            foreach (string args in BuildNetshRestoreDnsArguments(resolvedName, AddressFamily.InterNetwork, original.WasDhcpIpv4, original.OriginalIpv4Dns))
            {
                TryRunNetshBestEffort(args);
            }

            foreach (string args in BuildNetshRestoreDnsArguments(resolvedName, AddressFamily.InterNetworkV6, original.WasDhcpIpv6, original.OriginalIpv6Dns))
            {
                TryRunNetshBestEffort(args);
            }
        }

        string ipv4Value = original.WasDhcpIpv4
            ? string.Empty
            : string.Join(",", original.OriginalIpv4Dns);

        string ipv6Value = original.WasDhcpIpv6
            ? string.Empty
            : string.Join(",", original.OriginalIpv6Dns);

        WriteInterfaceNameServer(TcpipInterfacesSubKey, normalizedGuid, ipv4Value);
        WriteInterfaceNameServer(Tcpip6InterfacesSubKey, normalizedGuid, ipv6Value);

        NotifyDhcpConfigChangeBestEffort(normalizedGuid);
        FlushDnsResolverCache();
    }

    /// <summary>
    /// Reads live OS TCP/IP adapter properties to verify whether active physical adapters report <paramref name="expectedIpv4"/> as a configured DNS server.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Live OS adapter verification must stay resilient when adapters transition states.")]
    public static AdapterDnsVerificationResult VerifyAdapterDnsApplied(IPAddress expectedIpv4)
    {
        ArgumentNullException.ThrowIfNull(expectedIpv4);

        List<string> verifiedAdapters = [];
        HashSet<string> observedDns = new(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsActivePhysicalAdapter(adapter))
                {
                    continue;
                }

                IPInterfaceProperties ipProps = adapter.GetIPProperties();
                bool matchedOnAdapter = false;
                foreach (IPAddress dns in ipProps.DnsAddresses)
                {
                    observedDns.Add(dns.ToString());
                    if (dns.Equals(expectedIpv4))
                    {
                        matchedOnAdapter = true;
                    }
                }

                if (matchedOnAdapter && !string.IsNullOrWhiteSpace(adapter.Name))
                {
                    verifiedAdapters.Add(adapter.Name);
                }
            }
        }
        catch (Exception)
        {
        }

        return new AdapterDnsVerificationResult(
            IsApplied: verifiedAdapters.Count > 0,
            VerifiedAdapterNames: verifiedAdapters,
            ObservedDnsServers: [.. observedDns]);
    }

    /// <summary>
    /// Builds deterministic <c>netsh.exe</c> command-line arguments to set static DNS servers on an adapter.
    /// </summary>
    public static IReadOnlyList<string> BuildNetshSetDnsArguments(
        string interfaceName,
        AddressFamily family,
        IReadOnlyList<IPAddress> servers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        ArgumentNullException.ThrowIfNull(servers);

        if (servers.Count == 0)
        {
            return [];
        }

        string protocol = family == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4";
        string escapedName = interfaceName.Replace("\"", string.Empty, StringComparison.Ordinal);
        List<string> commands = new(servers.Count)
        {
            string.Create(
                CultureInfo.InvariantCulture,
                $"interface {protocol} set dnsservers name=\"{escapedName}\" source=static address={servers[0]} register=primary validate=no")
        };

        for (int i = 1; i < servers.Count; i++)
        {
            commands.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"interface {protocol} add dnsservers name=\"{escapedName}\" address={servers[i]} index={i + 1} validate=no"));
        }

        return commands;
    }

    /// <summary>
    /// Builds deterministic <c>netsh.exe</c> command-line arguments to restore an adapter's original DHCP or static DNS servers.
    /// </summary>
    public static IReadOnlyList<string> BuildNetshRestoreDnsArguments(
        string interfaceName,
        AddressFamily family,
        bool wasDhcp,
        IReadOnlyList<string> originalServers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        ArgumentNullException.ThrowIfNull(originalServers);

        string protocol = family == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4";
        string escapedName = interfaceName.Replace("\"", string.Empty, StringComparison.Ordinal);

        if (wasDhcp || originalServers.Count == 0)
        {
            return
            [
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"interface {protocol} set dnsservers name=\"{escapedName}\" source=dhcp")
            ];
        }

        List<IPAddress> parsed = [];
        foreach (string raw in originalServers)
        {
            if (IPAddress.TryParse(raw, out IPAddress? ip) && ip.AddressFamily == family)
            {
                parsed.Add(ip);
            }
        }

        if (parsed.Count == 0)
        {
            return
            [
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"interface {protocol} set dnsservers name=\"{escapedName}\" source=dhcp")
            ];
        }

        return BuildNetshSetDnsArguments(interfaceName, family, parsed);
    }

    internal static string NormalizeInterfaceGuid(string interfaceId)
    {
        string trimmed = interfaceId.Trim();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        if (Guid.TryParse(trimmed, out Guid parsed))
        {
            return parsed.ToString("B", CultureInfo.InvariantCulture).ToUpperInvariant();
        }

        return trimmed.StartsWith('{') && trimmed.EndsWith('}')
            ? trimmed
            : string.Create(CultureInfo.InvariantCulture, $"{{{trimmed}}}");
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Interface name lookup is best-effort for netsh helper execution.")]
    private static string? TryResolveInterfaceName(string normalizedGuid)
    {
        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (string.Equals(NormalizeInterfaceGuid(adapter.Id), normalizedGuid, StringComparison.OrdinalIgnoreCase))
                {
                    return adapter.Name;
                }
            }
        }
        catch (Exception)
        {
        }

        return null;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "netsh execution is defense-in-depth alongside Registry NameServer writes.")]
    private static void TryRunNetshBestEffort(string arguments)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            string netshPath = Path.Combine(Environment.SystemDirectory, "netsh.exe");
            ProcessStartInfo startInfo = new()
            {
                FileName = File.Exists(netshPath) ? netshPath : "netsh.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using Process? process = Process.Start(startInfo);
            if (process is not null)
            {
                _ = process.WaitForExit(NetshTimeoutMs);
            }
        }
        catch (Exception)
        {
        }
    }

    private static bool IsActivePhysicalAdapter(NetworkInterface adapter)
    {
        if (adapter.OperationalStatus != OperationalStatus.Up)
        {
            return false;
        }

        if (adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback
            or NetworkInterfaceType.Tunnel
            or NetworkInterfaceType.Unknown)
        {
            return false;
        }

        string description = adapter.Description ?? string.Empty;
        string name = adapter.Name ?? string.Empty;

        foreach (string token in VirtualAdapterDescriptionTokens)
        {
            if (description.Contains(token, StringComparison.OrdinalIgnoreCase)
                || name.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static (IReadOnlyList<string> Servers, bool WasDhcp) ReadInterfaceDnsServers(
        string baseSubKey,
        string normalizedGuid)
    {
        string subKeyPath = $@"{baseSubKey}\{normalizedGuid}";

        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            if (key is null)
            {
                return ([], true);
            }

            string? staticNameServer = key.GetValue("NameServer") as string;
            if (!string.IsNullOrWhiteSpace(staticNameServer))
            {
                List<string> parsedStatic = ParseDnsServerList(staticNameServer);
                return (parsedStatic, parsedStatic.Count == 0);
            }

            string? dhcpNameServer = key.GetValue("DhcpNameServer") as string;
            return (ParseDnsServerList(dhcpNameServer), true);
        }
        catch (SecurityException)
        {
            return ([], true);
        }
        catch (UnauthorizedAccessException)
        {
            return ([], true);
        }
        catch (IOException)
        {
            return ([], true);
        }
    }

    private static void WriteInterfaceNameServer(
        string baseSubKey,
        string normalizedGuid,
        string nameServerValue)
    {
        string subKeyPath = $@"{baseSubKey}\{normalizedGuid}";
        using RegistryKey key = Registry.LocalMachine.CreateSubKey(subKeyPath, writable: true);
        key.SetValue("NameServer", nameServerValue, RegistryValueKind.String);
    }

    private static List<string> ParseDnsServerList(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return [];
        }

        string[] parts = rawValue.Split(DnsServerSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        List<string> valid = new(parts.Length);

        foreach (string part in parts)
        {
            if (IPAddress.TryParse(part, out IPAddress? parsed))
            {
                valid.Add(parsed.ToString());
            }
        }

        return valid;
    }

    private static void NotifyDhcpConfigChangeBestEffort(string normalizedGuid)
    {
        try
        {
            _ = NativeMethods.DhcpNotifyConfigChange(
                lpwszServerName: null,
                lpwszAdapterName: normalizedGuid,
                bNewIpAddress: false,
                dwIpIndex: 0,
                dwIpAddress: 0,
                dwSubNetMask: 0,
                nDhcpAction: 0);
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
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DnsFlushResolverCache();

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpNotifyConfigChange", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern uint DhcpNotifyConfigChange(
            string? lpwszServerName,
            string lpwszAdapterName,
            [MarshalAs(UnmanagedType.Bool)] bool bNewIpAddress,
            uint dwIpIndex,
            uint dwIpAddress,
            uint dwSubNetMask,
            int nDhcpAction);
    }
}
