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
    /// Detects whether an external DPI-bypass tool such as Zapret (<c>winws</c>) or GoodbyeDPI is currently running,
    /// so PulseCore avoids double-fragmenting TLS ClientHello packets.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Best-effort process scan must remain resilient on restricted environments.")]
    public static bool IsZapretOrDpiToolActive()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        string[] dpiProcessNames = ["winws", "goodbyedpi", "ciadpi", "byedpi", "zapret"];
        try
        {
            foreach (string procName in dpiProcessNames)
            {
                Process[] matches = Process.GetProcessesByName(procName);
                try
                {
                    if (matches.Length > 0)
                    {
                        return true;
                    }
                }
                finally
                {
                    foreach (Process p in matches)
                    {
                        p.Dispose();
                    }
                }
            }
        }
        catch (Exception)
        {
        }

        return false;
    }

    /// <summary>
    /// Applies static IPv4 and IPv6 DNS server addresses via native Windows <c>SetInterfaceDnsSettings</c>,
    /// numeric-index <c>netsh</c> (immune to non-ASCII/Russian adapter names), Registry <c>NameServer</c>,
    /// and PowerShell fallback, then notifies DHCP and flushes the OS DNS resolver cache.
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
        (string? resolvedName, int? ipv4Index, int? ipv6Index) = TryResolveInterfaceInfo(normalizedGuid);
        if (!string.IsNullOrWhiteSpace(interfaceName))
        {
            resolvedName = interfaceName;
        }

        List<IPAddress> validIpv4 = [.. ipv4Servers.Where(static ip => ip.AddressFamily == AddressFamily.InterNetwork)];
        List<IPAddress> validIpv6 = [.. ipv6Servers.Where(static ip => ip.AddressFamily == AddressFamily.InterNetworkV6)];

        string ipv4Value = string.Join(",", validIpv4.Select(static ip => ip.ToString()));
        string ipv6Value = string.Join(",", validIpv6.Select(static ip => ip.ToString()));

        bool appliedIpv4Native = false;
        if (Guid.TryParse(normalizedGuid, out Guid parsedGuid))
        {
            if (validIpv4.Count > 0)
            {
                appliedIpv4Native = TrySetInterfaceDnsSettingsNative(parsedGuid, isIpv6: false, ipv4Value);
            }

            if (validIpv6.Count > 0)
            {
                _ = TrySetInterfaceDnsSettingsNative(parsedGuid, isIpv6: true, ipv6Value);
            }
        }

        bool appliedIpv4Netsh = false;
        if (ipv4Index.HasValue && validIpv4.Count > 0)
        {
            appliedIpv4Netsh = RunNetshCommands(BuildNetshSetDnsArgumentsByIndex(ipv4Index.Value, AddressFamily.InterNetwork, validIpv4));
        }

        if (!appliedIpv4Netsh && !string.IsNullOrWhiteSpace(resolvedName) && validIpv4.Count > 0)
        {
            appliedIpv4Netsh = RunNetshCommands(BuildNetshSetDnsArguments(resolvedName, AddressFamily.InterNetwork, validIpv4));
        }

        if (ipv6Index.HasValue && validIpv6.Count > 0)
        {
            _ = RunNetshCommands(BuildNetshSetDnsArgumentsByIndex(ipv6Index.Value, AddressFamily.InterNetworkV6, validIpv6));
        }
        else if (!string.IsNullOrWhiteSpace(resolvedName) && validIpv6.Count > 0)
        {
            _ = RunNetshCommands(BuildNetshSetDnsArguments(resolvedName, AddressFamily.InterNetworkV6, validIpv6));
        }

        if (!appliedIpv4Native && !appliedIpv4Netsh && ipv4Index.HasValue && validIpv4.Count > 0)
        {
            TrySetDnsViaPowerShellBestEffort(ipv4Index.Value, validIpv4, resetToDhcp: false);
        }

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
        (string? resolvedName, int? ipv4Index, int? ipv6Index) = TryResolveInterfaceInfo(normalizedGuid);
        if (!string.IsNullOrWhiteSpace(original.InterfaceName))
        {
            resolvedName = original.InterfaceName;
        }

        string ipv4Value = original.WasDhcpIpv4
            ? string.Empty
            : string.Join(",", original.OriginalIpv4Dns);

        string ipv6Value = original.WasDhcpIpv6
            ? string.Empty
            : string.Join(",", original.OriginalIpv6Dns);

        if (Guid.TryParse(normalizedGuid, out Guid parsedGuid))
        {
            _ = TrySetInterfaceDnsSettingsNative(parsedGuid, isIpv6: false, ipv4Value);
            _ = TrySetInterfaceDnsSettingsNative(parsedGuid, isIpv6: true, ipv6Value);
        }

        bool restoredIpv4Netsh = false;
        if (ipv4Index.HasValue)
        {
            restoredIpv4Netsh = RunNetshCommands(BuildNetshRestoreDnsArgumentsByIndex(ipv4Index.Value, AddressFamily.InterNetwork, original.WasDhcpIpv4, original.OriginalIpv4Dns));
        }

        if (!restoredIpv4Netsh && !string.IsNullOrWhiteSpace(resolvedName))
        {
            restoredIpv4Netsh = RunNetshCommands(BuildNetshRestoreDnsArguments(resolvedName, AddressFamily.InterNetwork, original.WasDhcpIpv4, original.OriginalIpv4Dns));
        }

        if (ipv6Index.HasValue)
        {
            _ = RunNetshCommands(BuildNetshRestoreDnsArgumentsByIndex(ipv6Index.Value, AddressFamily.InterNetworkV6, original.WasDhcpIpv6, original.OriginalIpv6Dns));
        }
        else if (!string.IsNullOrWhiteSpace(resolvedName))
        {
            _ = RunNetshCommands(BuildNetshRestoreDnsArguments(resolvedName, AddressFamily.InterNetworkV6, original.WasDhcpIpv6, original.OriginalIpv6Dns));
        }

        if (!restoredIpv4Netsh && ipv4Index.HasValue)
        {
            List<IPAddress> origV4 = [];
            foreach (string raw in original.OriginalIpv4Dns)
            {
                if (IPAddress.TryParse(raw, out IPAddress? ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    origV4.Add(ip);
                }
            }

            TrySetDnsViaPowerShellBestEffort(ipv4Index.Value, origV4, resetToDhcp: original.WasDhcpIpv4 || origV4.Count == 0);
        }

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

    /// <summary>
    /// Builds locale-independent <c>netsh.exe</c> command-line arguments using numeric interface index.
    /// </summary>
    public static IReadOnlyList<string> BuildNetshSetDnsArgumentsByIndex(
        int interfaceIndex,
        AddressFamily family,
        IReadOnlyList<IPAddress> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);
        if (servers.Count == 0 || interfaceIndex <= 0)
        {
            return [];
        }

        string protocol = family == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4";
        List<string> commands = new(servers.Count)
        {
            string.Create(
                CultureInfo.InvariantCulture,
                $"interface {protocol} set dnsservers name={interfaceIndex} source=static address={servers[0]} register=primary validate=no")
        };

        for (int i = 1; i < servers.Count; i++)
        {
            commands.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"interface {protocol} add dnsservers name={interfaceIndex} address={servers[i]} index={i + 1} validate=no"));
        }

        return commands;
    }

    /// <summary>
    /// Builds locale-independent <c>netsh.exe</c> restore arguments using numeric interface index.
    /// </summary>
    public static IReadOnlyList<string> BuildNetshRestoreDnsArgumentsByIndex(
        int interfaceIndex,
        AddressFamily family,
        bool wasDhcp,
        IReadOnlyList<string> originalServers)
    {
        ArgumentNullException.ThrowIfNull(originalServers);
        if (interfaceIndex <= 0)
        {
            return [];
        }

        string protocol = family == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4";
        if (wasDhcp || originalServers.Count == 0)
        {
            return
            [
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"interface {protocol} set dnsservers name={interfaceIndex} source=dhcp")
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
                    $"interface {protocol} set dnsservers name={interfaceIndex} source=dhcp")
            ];
        }

        return BuildNetshSetDnsArgumentsByIndex(interfaceIndex, family, parsed);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Interface lookup is best-effort for Windows DNS configuration.")]
    private static (string? Name, int? Ipv4Index, int? Ipv6Index) TryResolveInterfaceInfo(string normalizedGuid)
    {
        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!string.Equals(NormalizeInterfaceGuid(adapter.Id), normalizedGuid, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                int? v4Idx = null;
                int? v6Idx = null;
                try
                {
                    IPInterfaceProperties props = adapter.GetIPProperties();
                    if (adapter.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        v4Idx = props.GetIPv4Properties()?.Index;
                    }

                    if (adapter.Supports(NetworkInterfaceComponent.IPv6))
                    {
                        v6Idx = props.GetIPv6Properties()?.Index;
                    }
                }
                catch (Exception)
                {
                }

                return (adapter.Name, v4Idx, v6Idx);
            }
        }
        catch (Exception)
        {
        }

        return (null, null, null);
    }

    private static bool RunNetshCommands(IReadOnlyList<string> commands)
    {
        if (commands.Count == 0)
        {
            return false;
        }

        bool allOk = true;
        foreach (string args in commands)
        {
            if (!TryRunNetshBestEffort(args))
            {
                allOk = false;
            }
        }

        return allOk;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "netsh execution is defense-in-depth alongside native SetInterfaceDnsSettings and Registry writes.")]
    private static bool TryRunNetshBestEffort(string arguments)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
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
            if (process is null)
            {
                return false;
            }

            Task<string> outTask = process.StandardOutput.ReadToEndAsync();
            Task<string> errTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(NetshTimeoutMs))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception)
                {
                }

                return false;
            }

            _ = outTask.Wait(200);
            _ = errTask.Wait(200);
            return process.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "PowerShell Set-DnsClientServerAddress is a best-effort last-resort fallback.")]
    private static void TrySetDnsViaPowerShellBestEffort(
        int interfaceIndex,
        IReadOnlyList<IPAddress> servers,
        bool resetToDhcp)
    {
        if (!OperatingSystem.IsWindows() || interfaceIndex <= 0)
        {
            return;
        }

        try
        {
            string psCommand = resetToDhcp || servers.Count == 0
                ? string.Create(CultureInfo.InvariantCulture, $"Set-DnsClientServerAddress -InterfaceIndex {interfaceIndex} -ResetServerAddresses")
                : string.Create(CultureInfo.InvariantCulture, $"Set-DnsClientServerAddress -InterfaceIndex {interfaceIndex} -ServerAddresses @({string.Join(",", servers.Select(static s => $"'{s}'"))})");

            ProcessStartInfo startInfo = new()
            {
                FileName = "powershell.exe",
                Arguments = string.Create(CultureInfo.InvariantCulture, $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{psCommand}\""),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using Process? process = Process.Start(startInfo);
            if (process is not null)
            {
                Task<string> outTask = process.StandardOutput.ReadToEndAsync();
                Task<string> errTask = process.StandardError.ReadToEndAsync();
                _ = process.WaitForExit(NetshTimeoutMs);
                _ = outTask.Wait(200);
                _ = errTask.Wait(200);
            }
        }
        catch (Exception)
        {
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Native iphlpapi SetInterfaceDnsSettings is available on Windows 10 2004+ and falls back safely on older builds.")]
    private static bool TrySetInterfaceDnsSettingsNative(Guid interfaceGuid, bool isIpv6, string nameServers)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        nint nameServerPtr = nint.Zero;
        try
        {
            ulong flags = NativeMethods.DnsSettingNameServer | (isIpv6 ? NativeMethods.DnsSettingIpv6 : 0UL);
            nameServerPtr = Marshal.StringToHGlobalUni(nameServers ?? string.Empty);

            NativeMethods.DnsInterfaceSettings settings = new()
            {
                Version = NativeMethods.DnsInterfaceSettingsVersion1,
                Flags = flags,
                Domain = nint.Zero,
                NameServer = nameServerPtr,
                SearchList = nint.Zero,
                RegistrationEnabled = 0,
                RegisterAdapterName = 0,
                EnableLLMNR = 0,
                QueryAdapterName = 0,
                ProfileNameServer = nint.Zero
            };

            uint result = NativeMethods.SetInterfaceDnsSettings(interfaceGuid, ref settings);
            return result == 0;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (nameServerPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(nameServerPtr);
            }
        }
    }

    private static bool IsActivePhysicalAdapter(NetworkInterface adapter)
    {
        if (adapter.OperationalStatus != OperationalStatus.Up)
        {
            return false;
        }

        if (adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
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

        if (adapter.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Unknown)
        {
            // Allow active gateway-bearing adapters (e.g., PPPoE/USB/Ethernet bridges) while excluding idle tunnels.
            try
            {
                return adapter.GetIPProperties().GatewayAddresses.Count > 0;
            }
            catch (NetworkInformationException)
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
        internal const uint DnsInterfaceSettingsVersion1 = 1;
        internal const ulong DnsSettingIpv6 = 0x0001;
        internal const ulong DnsSettingNameServer = 0x0008;

        [StructLayout(LayoutKind.Sequential)]
        internal struct DnsInterfaceSettings
        {
            public uint Version;
            public ulong Flags;
            public nint Domain;
            public nint NameServer;
            public nint SearchList;
            public uint RegistrationEnabled;
            public uint RegisterAdapterName;
            public uint EnableLLMNR;
            public uint QueryAdapterName;
            public nint ProfileNameServer;
        }

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

        [DllImport("iphlpapi.dll", EntryPoint = "SetInterfaceDnsSettings", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern uint SetInterfaceDnsSettings(
            Guid interfaceGuid,
            ref DnsInterfaceSettings settings);
    }
}
