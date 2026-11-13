using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Networking;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Intercepts host DNS traffic by pointing active physical adapters' DNS settings to the local PulseCore endpoint.
/// </summary>
public sealed class AdapterDnsInterceptor : IDnsInterceptor
{
    private readonly bool _blockIpv6OnBypass;
    private readonly bool _disableSmhnr;

    private IReadOnlyList<AdapterDnsConfiguration> _capturedAdapters = [];
    private bool _priorSmhnrDisabled;
    private bool _isActive;

    /// <summary>
    /// Initializes a new <see cref="AdapterDnsInterceptor"/>.
    /// </summary>
    public AdapterDnsInterceptor(bool blockIpv6OnBypass = true, bool disableSmhnr = true)
    {
        _blockIpv6OnBypass = blockIpv6OnBypass;
        _disableSmhnr = disableSmhnr;
    }

    /// <inheritdoc />
    public InterceptionMode Mode => InterceptionMode.AdapterDns;

    /// <summary>
    /// Gets the adapter configurations captured on the most recent activation.
    /// </summary>
    public IReadOnlyList<AdapterDnsConfiguration> CapturedAdapters => _capturedAdapters;

    /// <summary>
    /// Gets whether SMHNR was already disabled before activation.
    /// </summary>
    public bool PriorSmhnrDisabled => _priorSmhnrDisabled;

    /// <inheritdoc />
    public Task ActivateAsync(
        IPAddress localDnsIp,
        int dnsPort,
        IReadOnlyList<string> splitDomains,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(localDnsIp);
        ArgumentNullException.ThrowIfNull(splitDomains);
        ct.ThrowIfCancellationRequested();

        if (dnsPort != 53)
        {
            throw new NotSupportedException(
                string.Create(CultureInfo.InvariantCulture, $"AdapterDns interception requires DNS port 53, but received port {dnsPort}."));
        }

        _priorSmhnrDisabled = SmhnrPolicyManager.IsSmhnrDisabled();
        IReadOnlyList<AdapterDnsConfiguration> adapters = Win32NetworkInterop.GetActivePhysicalAdapters();
        _capturedAdapters = adapters;

        IReadOnlyList<IPAddress> ipv4Servers = localDnsIp.AddressFamily == AddressFamily.InterNetwork
            ? [localDnsIp]
            : [];

        IReadOnlyList<IPAddress> ipv6Servers = localDnsIp.AddressFamily == AddressFamily.InterNetworkV6
            ? [localDnsIp]
            : (_blockIpv6OnBypass ? [IPAddress.IPv6Loopback] : []);

        List<AdapterDnsConfiguration> modifiedAdapters = new(adapters.Count);

        try
        {
            if (_disableSmhnr)
            {
                SmhnrPolicyManager.SetSmhnrDisabled(true);
            }

            foreach (AdapterDnsConfiguration adapter in adapters)
            {
                ct.ThrowIfCancellationRequested();
                Win32NetworkInterop.ApplyAdapterDnsServers(adapter.InterfaceGuid, ipv4Servers, ipv6Servers);
                modifiedAdapters.Add(adapter);
            }

            _isActive = true;
        }
        catch
        {
            for (int i = modifiedAdapters.Count - 1; i >= 0; i--)
            {
                Win32NetworkInterop.RestoreAdapterDnsServers(modifiedAdapters[i]);
            }

            if (_disableSmhnr)
            {
                SmhnrPolicyManager.SetSmhnrDisabled(_priorSmhnrDisabled);
            }

            _capturedAdapters = [];
            _isActive = false;
            throw;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeactivateAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!_isActive && _capturedAdapters.Count == 0)
        {
            return Task.CompletedTask;
        }

        foreach (AdapterDnsConfiguration adapter in _capturedAdapters)
        {
            Win32NetworkInterop.RestoreAdapterDnsServers(adapter);
        }

        if (_disableSmhnr)
        {
            SmhnrPolicyManager.SetSmhnrDisabled(_priorSmhnrDisabled);
        }

        _capturedAdapters = [];
        _isActive = false;
        return Task.CompletedTask;
    }
}
