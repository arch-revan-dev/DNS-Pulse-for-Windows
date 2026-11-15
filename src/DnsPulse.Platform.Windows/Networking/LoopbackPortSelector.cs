using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Selects an available Windows loopback IPv4 endpoint by performing live UDP and TCP bind probes.
/// </summary>
public sealed class LoopbackPortSelector
{
    private const int FallbackSubnetCount = 10;

    /// <summary>
    /// Returns the ordered list of Windows loopback candidate addresses probed by <see cref="SelectAvailableDnsEndpoint(int)"/>.
    /// </summary>
    public static IReadOnlyList<IPAddress> GetCandidateEndpoints()
    {
        List<IPAddress> candidates = new(1 + FallbackSubnetCount)
        {
            IPAddress.Loopback
        };

        for (int i = 1; i <= FallbackSubnetCount; i++)
        {
            candidates.Add(IPAddress.Parse(string.Create(CultureInfo.InvariantCulture, $"127.0.53.{i}")));
        }

        return candidates;
    }

    /// <summary>
    /// Probes <c>127.0.0.1</c> and then <c>127.0.53.1</c> through <c>127.0.53.10</c> for simultaneous UDP and TCP availability on <paramref name="port"/>.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract for dependency injection and mocking.")]
    public IPAddress SelectAvailableDnsEndpoint(int port = 53)
    {
        if (TrySelectAvailableDnsEndpoint(port, preferredAddress: null, out IPAddress? selected) && selected is not null)
        {
            return selected;
        }

        throw new InvalidOperationException(
            string.Create(CultureInfo.InvariantCulture, $"No available loopback DNS endpoint found on port {port}."));
    }

    /// <summary>
    /// Attempts to select an available loopback IPv4 endpoint for simultaneous UDP and TCP binding on <paramref name="port"/>,
    /// checking <paramref name="preferredAddress"/> first when provided.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract for dependency injection and mocking.")]
    public bool TrySelectAvailableDnsEndpoint(int port, [NotNullWhen(true)] out IPAddress? selectedAddress)
    {
        return TrySelectAvailableDnsEndpoint(port, preferredAddress: null, out selectedAddress);
    }

    /// <summary>
    /// Attempts to select an available loopback IPv4 endpoint for simultaneous UDP and TCP binding on <paramref name="port"/>,
    /// checking <paramref name="preferredAddress"/> first when provided.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract for dependency injection and mocking.")]
    public bool TrySelectAvailableDnsEndpoint(
        int port,
        IPAddress? preferredAddress,
        [NotNullWhen(true)] out IPAddress? selectedAddress)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        if (preferredAddress is not null
            && preferredAddress.AddressFamily == AddressFamily.InterNetwork
            && IPAddress.IsLoopback(preferredAddress)
            && TryBindDualProtocol(preferredAddress, port))
        {
            selectedAddress = preferredAddress;
            return true;
        }

        foreach (IPAddress candidate in GetCandidateEndpoints())
        {
            if (preferredAddress is not null && candidate.Equals(preferredAddress))
            {
                continue;
            }

            if (TryBindDualProtocol(candidate, port))
            {
                selectedAddress = candidate;
                return true;
            }
        }

        selectedAddress = null;
        return false;
    }

    private static bool TryBindDualProtocol(IPAddress address, int port)
    {
        IPEndPoint endpoint = new(address, port);

        try
        {
            using Socket udpSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.ExclusiveAddressUse = true;
            udpSocket.Bind(endpoint);

            using Socket tcpSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcpSocket.ExclusiveAddressUse = true;
            tcpSocket.Bind(endpoint);

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
