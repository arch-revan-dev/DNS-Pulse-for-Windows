using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Networking;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Intercepts host DNS traffic by pointing active physical adapters' DNS settings to the local PulseCore endpoint,
/// reinforced by hybrid Windows NRPT split-DNS rules and live OS adapter verification.
/// </summary>
public sealed class AdapterDnsInterceptor : IDnsInterceptor
{
    private static readonly IPAddress Ipv6DiscardSinkhole = IPAddress.Parse("100::1");

    private readonly bool _blockIpv6OnBypass;
    private readonly bool _disableSmhnr;
    private readonly Func<int, bool> _isIpv6LoopbackPortFree;

    private IReadOnlyList<AdapterDnsConfiguration> _capturedAdapters = [];
    private IReadOnlyList<string> _verifiedAdapterNames = [];
    private bool _priorSmhnrDisabled;
    private bool _appliedHybridNrpt;
    private bool _isActive;

    /// <summary>
    /// Initializes a new <see cref="AdapterDnsInterceptor"/>.
    /// </summary>
    public AdapterDnsInterceptor(bool blockIpv6OnBypass = true, bool disableSmhnr = true)
        : this(blockIpv6OnBypass, disableSmhnr, isIpv6LoopbackPortFree: null)
    {
    }

    internal AdapterDnsInterceptor(
        bool blockIpv6OnBypass,
        bool disableSmhnr,
        Func<int, bool>? isIpv6LoopbackPortFree)
    {
        _blockIpv6OnBypass = blockIpv6OnBypass;
        _disableSmhnr = disableSmhnr;
        _isIpv6LoopbackPortFree = isIpv6LoopbackPortFree ?? IsIpv6LoopbackPortFree;
    }

    /// <inheritdoc />
    public InterceptionMode Mode => InterceptionMode.AdapterDns;

    /// <summary>
    /// Gets the adapter configurations captured on the most recent activation.
    /// </summary>
    public IReadOnlyList<AdapterDnsConfiguration> CapturedAdapters => _capturedAdapters;

    /// <summary>
    /// Gets the active adapter names verified by live OS TCP/IP stack readback.
    /// </summary>
    public IReadOnlyList<string> VerifiedAdapterNames => _verifiedAdapterNames;

    /// <summary>
    /// Gets whether SMHNR was already disabled before activation.
    /// </summary>
    public bool PriorSmhnrDisabled => _priorSmhnrDisabled;

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Defense-in-depth NRPT registration must not block adapter DNS activation if GPO restricts NRPT.")]
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

        // When PulseCore binds an IPv4 fallback (e.g. 127.0.53.1) because another resolver (such as ag_dns)
        // occupies [::1]:53 or [::]:53, pointing adapter IPv6 DNS at ::1 would leak AAAA queries to that
        // conflicting listener. Route IPv6 bypass to RFC 6666 discard-only 100::1 instead when [::1]:53 is busy.
        IReadOnlyList<IPAddress> ipv6Servers = ResolveEffectiveIpv6BypassServers(
            localDnsIp,
            _blockIpv6OnBypass,
            _isIpv6LoopbackPortFree);

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
                Win32NetworkInterop.ApplyAdapterDnsServers(
                    adapter.InterfaceGuid,
                    adapter.InterfaceName,
                    ipv4Servers,
                    ipv6Servers);
                modifiedAdapters.Add(adapter);
            }

            if (splitDomains.Count > 0)
            {
                try
                {
                    NrptPolicyManager.ApplySplitRules(localDnsIp, dnsPort, splitDomains);
                    _appliedHybridNrpt = true;
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
                catch (Exception)
                {
                }
            }

            if (localDnsIp.AddressFamily == AddressFamily.InterNetwork)
            {
                AdapterDnsVerificationResult verification = Win32NetworkInterop.VerifyAdapterDnsApplied(localDnsIp);
                _verifiedAdapterNames = verification.VerifiedAdapterNames;
            }
            else
            {
                _verifiedAdapterNames = [];
            }

            _isActive = true;
        }
        catch
        {
            if (_appliedHybridNrpt)
            {
                try
                {
                    NrptPolicyManager.RemoveAllPulseNrptRules();
                }
                catch (Exception)
                {
                }

                _appliedHybridNrpt = false;
            }

            for (int i = modifiedAdapters.Count - 1; i >= 0; i--)
            {
                Win32NetworkInterop.RestoreAdapterDnsServers(modifiedAdapters[i]);
            }

            if (_disableSmhnr)
            {
                SmhnrPolicyManager.SetSmhnrDisabled(_priorSmhnrDisabled);
            }

            _capturedAdapters = [];
            _verifiedAdapterNames = [];
            _isActive = false;
            throw;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "NRPT cleanup during deactivate must stay exception-safe so adapter restore always runs.")]
    public Task DeactivateAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!_isActive && _capturedAdapters.Count == 0 && !_appliedHybridNrpt)
        {
            return Task.CompletedTask;
        }

        if (_appliedHybridNrpt)
        {
            try
            {
                NrptPolicyManager.RemoveAllPulseNrptRules();
            }
            catch (Exception)
            {
            }

            _appliedHybridNrpt = false;
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
        _verifiedAdapterNames = [];
        _isActive = false;
        return Task.CompletedTask;
    }

    internal static IReadOnlyList<IPAddress> ResolveEffectiveIpv6BypassServers(
        IPAddress localDnsIp,
        bool blockIpv6OnBypass,
        Func<int, bool>? isIpv6LoopbackPortFree = null)
    {
        ArgumentNullException.ThrowIfNull(localDnsIp);

        if (localDnsIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return [localDnsIp];
        }

        if (!blockIpv6OnBypass)
        {
            return [];
        }

        Func<int, bool> probe = isIpv6LoopbackPortFree ?? IsIpv6LoopbackPortFree;
        return probe(53) ? [IPAddress.IPv6Loopback] : [Ipv6DiscardSinkhole];
    }

    internal static bool IsIpv6LoopbackPortFree(int port)
    {
        if (!Socket.OSSupportsIPv6)
        {
            return true;
        }

        try
        {
            using Socket udpSocket = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.ExclusiveAddressUse = true;
            udpSocket.Bind(new IPEndPoint(IPAddress.IPv6Loopback, port));

            using Socket tcpSocket = new(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            tcpSocket.ExclusiveAddressUse = true;
            tcpSocket.Bind(new IPEndPoint(IPAddress.IPv6Loopback, port));

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
