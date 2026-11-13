using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

internal static class EndpointResolutionHelper
{
    public static bool TryGetParsedStamp(DnsServerEntry upstream, out DnsStamp? stamp)
    {
        if (!string.IsNullOrWhiteSpace(upstream.DnsStampUri)
            && DnsStampCodec.TryParse(upstream.DnsStampUri.Trim(), out stamp))
        {
            return true;
        }

        stamp = null;
        return false;
    }

    public static async Task<IReadOnlyList<IPAddress>> ResolveTargetAddressesAsync(
        DnsServerEntry upstream,
        string? fallbackHost,
        IBootstrapResolver? bootstrapResolver,
        CancellationToken cancellationToken)
    {
        List<IPAddress> addresses = [];

        void AddIfValidIp(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }

            if (TryParseEndpointIp(raw, out IPAddress? parsed, out _))
            {
                if (!addresses.Contains(parsed))
                {
                    addresses.Add(parsed);
                }
            }
        }

        AddIfValidIp(upstream.PrimaryIp);
        AddIfValidIp(upstream.SecondaryIp);

        foreach (string ip in upstream.BootstrapIps)
        {
            AddIfValidIp(ip);
        }

        if (TryGetParsedStamp(upstream, out DnsStamp? stamp) && stamp is not null)
        {
            AddIfValidIp(stamp.ServerAddress);
            foreach (string ip in stamp.BootstrapIps)
            {
                AddIfValidIp(ip);
            }
        }

        if (addresses.Count > 0)
        {
            return addresses;
        }

        string? hostToResolve = !string.IsNullOrWhiteSpace(fallbackHost)
            ? fallbackHost
            : upstream.DotHost;

        if (!string.IsNullOrWhiteSpace(hostToResolve))
        {
            if (IPAddress.TryParse(hostToResolve.Trim(), out IPAddress? literal))
            {
                return [literal];
            }

            if (bootstrapResolver is not null)
            {
                IReadOnlyList<IPAddress> bootstrapped = await bootstrapResolver
                    .ResolveHostAsync(hostToResolve, cancellationToken)
                    .ConfigureAwait(false);
                if (bootstrapped.Count > 0)
                {
                    return bootstrapped;
                }
            }
        }

        return addresses;
    }

    public static bool TryParseEndpointIp(string raw, out IPAddress address, out int? port)
    {
        string trimmed = raw.Trim();
        port = null;

        if (trimmed.StartsWith('['))
        {
            int close = trimmed.IndexOf(']', StringComparison.Ordinal);
            if (close > 1)
            {
                string v6 = trimmed[1..close];
                if (IPAddress.TryParse(v6, out IPAddress? parsedV6))
                {
                    address = parsedV6;
                    if (close + 1 < trimmed.Length && trimmed[close + 1] == ':'
                        && int.TryParse(trimmed.AsSpan(close + 2), NumberStyles.None, CultureInfo.InvariantCulture, out int parsedPort)
                        && parsedPort is >= 1 and <= 65535)
                    {
                        port = parsedPort;
                    }

                    return true;
                }
            }
        }

        if (IPAddress.TryParse(trimmed, out IPAddress? direct))
        {
            address = direct;
            return true;
        }

        int colon = trimmed.LastIndexOf(':');
        if (colon > 0 && colon < trimmed.Length - 1)
        {
            string hostPart = trimmed[..colon];
            if (IPAddress.TryParse(hostPart, out IPAddress? v4WithPort)
                && v4WithPort.AddressFamily == AddressFamily.InterNetwork
                && int.TryParse(trimmed.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out int parsedPort)
                && parsedPort is >= 1 and <= 65535)
            {
                address = v4WithPort;
                port = parsedPort;
                return true;
            }
        }

        address = IPAddress.None;
        return false;
    }

    public static string FormatEndpoint(IPAddress address, int port)
    {
        return address.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Create(CultureInfo.InvariantCulture, $"[{address}]:{port}")
            : string.Create(CultureInfo.InvariantCulture, $"{address}:{port}");
    }

    public static bool HasTlsFragmentationTag(DnsServerEntry upstream)
    {
        foreach (string tag in upstream.Tags)
        {
            if (string.Equals(tag, "tls-frag", StringComparison.OrdinalIgnoreCase)
                || string.Equals(tag, "fragment-tls", StringComparison.OrdinalIgnoreCase)
                || string.Equals(tag, "dpi-bypass", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
