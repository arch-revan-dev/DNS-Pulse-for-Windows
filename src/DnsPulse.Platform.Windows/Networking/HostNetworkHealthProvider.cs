using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Contracts;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Inspects Windows host network health, connectivity, NCSI captive-portal state, port 53 conflicts, SMHNR policy, and browser DoH posture.
/// </summary>
public sealed class HostNetworkHealthProvider : IHostNetworkHealthProvider
{
    private const string NlaInternetSubKey = @"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet";

    private readonly bool _enableOsProbes;
    private readonly Port53ConflictInspector _port53Inspector = new();
    private readonly BrowserDohInspector _browserDohInspector = new();

    /// <summary>
    /// Initializes a new <see cref="HostNetworkHealthProvider"/>.
    /// </summary>
    public HostNetworkHealthProvider(bool enableOsProbes = true)
    {
        _enableOsProbes = enableOsProbes;
    }

    /// <summary>
    /// Captures a point-in-time <see cref="HostNetworkHealthSnapshot"/>.
    /// </summary>
    public Task<HostNetworkHealthSnapshot> InspectAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_enableOsProbes)
        {
            return Task.FromResult(new HostNetworkHealthSnapshot
            {
                CapturedAtUtc = DateTimeOffset.UtcNow
            });
        }

        IReadOnlyList<AdapterDnsConfiguration> adapters = Win32NetworkInterop.GetActivePhysicalAdapters();
        List<string> activeNames = new(adapters.Count);
        HashSet<string> activeGuidSet = new(StringComparer.OrdinalIgnoreCase);

        foreach (AdapterDnsConfiguration adapter in adapters)
        {
            activeNames.Add(adapter.InterfaceName);
            activeGuidSet.Add(adapter.InterfaceGuid);
        }

        (bool hasIpv4, bool hasIpv6) = InspectAddressFamilyConnectivity(activeGuidSet);
        bool captivePortalDetected = DetectNcsiCaptivePortal(hasIpv4 || hasIpv6);
        (string? occupantName, int? occupantPid) = _port53Inspector.InspectPort53Conflict();
        bool isSmhnrDisabled = SmhnrPolicyManager.IsSmhnrDisabled();
        IReadOnlyList<string> bypassingBrowsers = _browserDohInspector.DetectBypassingBrowsers();

        HostNetworkHealthSnapshot snapshot = new()
        {
            CapturedAtUtc = DateTimeOffset.UtcNow,
            ActiveInterfaceNames = activeNames,
            HasIpv4Connectivity = hasIpv4,
            HasIpv6Connectivity = hasIpv6,
            IsCaptivePortalDetected = captivePortalDetected,
            Port53OccupantName = occupantName,
            Port53OccupantProcessId = occupantPid,
            IsSmhnrDisabled = isSmhnrDisabled,
            DetectedBrowserDohBypassBrowsers = bypassingBrowsers
        };

        return Task.FromResult(snapshot);
    }

    private static (bool HasIpv4, bool HasIpv6) InspectAddressFamilyConnectivity(HashSet<string> activeGuidSet)
    {
        bool hasIpv4 = false;
        bool hasIpv6 = false;

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            if (activeGuidSet.Count > 0)
            {
                string normalizedGuid = Win32NetworkInterop.NormalizeInterfaceGuid(nic.Id);
                if (!activeGuidSet.Contains(normalizedGuid))
                {
                    continue;
                }
            }
            else if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            IPInterfaceProperties ipProps = nic.GetIPProperties();
            foreach (UnicastIPAddressInformation unicast in ipProps.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    byte[] bytes = unicast.Address.GetAddressBytes();
                    bool isApipa = bytes[0] == 169 && bytes[1] == 254;
                    if (!isApipa)
                    {
                        hasIpv4 = true;
                    }
                }
                else if (unicast.Address.AddressFamily == AddressFamily.InterNetworkV6 && !unicast.Address.IsIPv6LinkLocal)
                {
                    hasIpv6 = true;
                }
            }
        }

        return (hasIpv4, hasIpv6);
    }

    private static bool DetectNcsiCaptivePortal(bool hasIpAddress)
    {
        try
        {
            using RegistryKey? nlaKey = Registry.LocalMachine.OpenSubKey(NlaInternetSubKey, writable: false);
            if (nlaKey is not null)
            {
                if (nlaKey.GetValue("CaptivePortalTimer") is int timer && timer > 0)
                {
                    return true;
                }

                if (nlaKey.GetValue("EnableActiveProbing") is int activeProbing
                    && activeProbing == 1
                    && hasIpAddress
                    && !NetworkInterface.GetIsNetworkAvailable())
                {
                    return true;
                }
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

        return false;
    }
}
