using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace DnsPulse.Engine.Sidecar;

/// <summary>
/// Describes the endpoints and scannable PAC QR matrix exposed to mobile/console devices
/// when DNS Pulse operates in LAN Gateway Mode.
/// </summary>
/// <param name="DnsEndpoint">LAN DNS endpoint (<c>ip:port</c>).</param>
/// <param name="PacUrl">HTTP URL of the <c>/proxy.pac</c> endpoint served to LAN clients.</param>
/// <param name="ProxyEndpoint">LAN HTTP/SOCKS5 fragmentation proxy endpoint (<c>ip:port</c>).</param>
/// <param name="PacQrMatrix">Square QR code matrix encoding <paramref name="PacUrl"/>.</param>
[SuppressMessage("Performance", "CA1814:Prefer jagged arrays over multidimensional", Justification = "Matches LanGatewayDescriptor contract exposing a 2D QR matrix.")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Matches LanGatewayDescriptor contract exposing PacQrMatrix.")]
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "Stores formatted PAC URL string for LAN gateway QR and UI display.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Stores formatted PAC URL string for LAN gateway QR and UI display.")]
public sealed record LanGatewayDescriptor(
    string DnsEndpoint,
    string PacUrl,
    string ProxyEndpoint,
    bool[,] PacQrMatrix)
{
    /// <summary>
    /// Creates a <see cref="LanGatewayDescriptor"/> and encodes its <c>/proxy.pac</c> URL into a QR matrix.
    /// </summary>
    public static LanGatewayDescriptor Create(
        IPAddress lanAddress,
        int dnsPort,
        int pacPort,
        int proxyPort,
        QrEccLevel eccLevel = QrEccLevel.Medium)
    {
        ArgumentNullException.ThrowIfNull(lanAddress);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(dnsPort, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(dnsPort, 65535);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(pacPort, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(pacPort, 65535);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(proxyPort, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(proxyPort, 65535);

        string authorityHost = lanAddress.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Concat("[", lanAddress.ToString(), "]")
            : lanAddress.ToString();

        string dnsEndpoint = string.Create(CultureInfo.InvariantCulture, $"{authorityHost}:{dnsPort}");
        string pacUrl = string.Create(CultureInfo.InvariantCulture, $"http://{authorityHost}:{pacPort}/proxy.pac");
        string proxyEndpoint = string.Create(CultureInfo.InvariantCulture, $"{authorityHost}:{proxyPort}");
        bool[,] qrMatrix = QrMatrixGenerator.Generate(pacUrl, eccLevel);

        return new LanGatewayDescriptor(dnsEndpoint, pacUrl, proxyEndpoint, qrMatrix);
    }
}
