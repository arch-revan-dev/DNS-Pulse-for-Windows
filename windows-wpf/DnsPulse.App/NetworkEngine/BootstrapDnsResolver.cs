using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace DnsPulse.App.NetworkEngine;

/// <summary>
/// Resolves DoH, feed, and CDN hostnames directly over public UDP DNS (1.1.1.1 / 8.8.8.8 / 9.9.9.9),
/// preventing self-referential loops when 127.0.0.1 is set on Windows adapters and avoiding broken IPv6 routes.
/// </summary>
public static class BootstrapDnsResolver
{
    private static readonly string[] BootstrapServers = { "1.1.1.1", "8.8.8.8", "9.9.9.9" };
    private static readonly string[] BootstrapDohIps = { "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query" };
    public static volatile string PreferredBootstrapProvider = "Auto";

    public static string[] GetOrderedBootstrapServers()
    {
        var pref = PreferredBootstrapProvider;
        if (pref is "1.1.1.1" or "8.8.8.8" or "9.9.9.9")
        {
            return new[] { pref }
                .Concat(BootstrapServers.Where(s => !string.Equals(s, pref, StringComparison.Ordinal)))
                .ToArray();
        }
        return BootstrapServers;
    }
    private static readonly HttpClient BootstrapDohClient = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromMilliseconds(2000)
    })
    {
        Timeout = TimeSpan.FromMilliseconds(2500)
    };
    private static readonly ConcurrentDictionary<string, (IPAddress[] Addresses, long ExpiresAtMs)> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    public static void ClearCache() => Cache.Clear();

    public static async Task<IPAddress[]> ResolveHostAddressesAsync(
        string host,
        string? preferredIp = null,
        CancellationToken ct = default)
    {
        var clean = (host ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(clean))
            return Array.Empty<IPAddress>();

        if (IPAddress.TryParse(clean, out var literal))
            return new[] { literal };

        if (!string.IsNullOrWhiteSpace(preferredIp) &&
            IPAddress.TryParse(preferredIp.Trim(), out var hintIp) &&
            !IPAddress.IsLoopback(hintIp))
        {
            return new[] { hintIp };
        }

        var now = Environment.TickCount64;
        if (Cache.TryGetValue(clean, out var cached) && cached.ExpiresAtMs > now && cached.Addresses.Length > 0)
            return cached.Addresses;

        var resolved = new List<IPAddress>();
        var query = DnsPacketCodec.EncodeQuery(clean, qtype: 1);

        foreach (var dnsIp in GetOrderedBootstrapServers())
        {
            try
            {
                var raw = await ForwardRawUdpAsync(dnsIp, query, 1100, ct).ConfigureAwait(false);
                if (raw is { Length: >= 12 })
                {
                    var decoded = DnsPacketCodec.DecodeResponse(raw);
                    foreach (var ipStr in decoded.Ips)
                    {
                        if (IPAddress.TryParse(ipStr, out var addr) &&
                            !IPAddress.IsLoopback(addr) &&
                            AntiDirectIpFilter.IsValidNonBogonIp(ipStr))
                        {
                            resolved.Add(addr);
                        }
                    }
                    if (resolved.Count > 0)
                        break;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Try next bootstrap server
            }
        }

        if (resolved.Count == 0)
        {
            foreach (var dohIpUrl in BootstrapDohIps)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Post, dohIpUrl);
                    req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-message"));
                    req.Content = new ByteArrayContent(query);
                    req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/dns-message");
                    using var resp = await BootstrapDohClient.SendAsync(req, ct).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode)
                    {
                        var wire = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                        var decoded = DnsPacketCodec.DecodeResponse(wire);
                        foreach (var ipStr in decoded.Ips)
                        {
                            if (IPAddress.TryParse(ipStr, out var addr) &&
                                !IPAddress.IsLoopback(addr) &&
                                AntiDirectIpFilter.IsValidNonBogonIp(ipStr))
                            {
                                resolved.Add(addr);
                            }
                        }
                        if (resolved.Count > 0)
                            break;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // Try next IP-based DoH bootstrap resolver
                }
            }
        }

        if (resolved.Count == 0)
        {
            try
            {
                var systemAddrs = await Dns.GetHostAddressesAsync(clean, ct).ConfigureAwait(false);
                var ipv4 = systemAddrs
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                    .ToArray();
                if (ipv4.Length > 0)
                {
                    resolved.AddRange(ipv4);
                }
                else
                {
                    resolved.AddRange(systemAddrs.Where(a => !IPAddress.IsLoopback(a)));
                }
            }
            catch
            {
                // Host unreachable
            }
        }

        if (resolved.Count > 0)
        {
            var distinct = resolved.Distinct().ToArray();
            Cache[clean] = (distinct, now + 600_000L);
            return distinct;
        }

        return Array.Empty<IPAddress>();
    }

    public static async Task<Stream> ConnectTcpWithBootstrapAsync(
        string host,
        int port,
        string? explicitConnectIp,
        TimeSpan connectTimeout,
        CancellationToken ct)
    {
        var addresses = !string.IsNullOrWhiteSpace(explicitConnectIp) && IPAddress.TryParse(explicitConnectIp.Trim(), out var forced)
            ? new[] { forced }
            : await ResolveHostAddressesAsync(host, null, ct).ConfigureAwait(false);

        if (addresses.Length == 0)
            throw new SocketException((int)SocketError.HostNotFound);

        Exception? lastErr = null;
        foreach (var addr in addresses.Take(3))
        {
            var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };
            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(connectTimeout);
                await socket.ConnectAsync(new IPEndPoint(addr, port), timeoutCts.Token).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex)
            {
                lastErr = ex;
                socket.Dispose();
                if (ct.IsCancellationRequested)
                    throw;
            }
        }

        throw lastErr ?? new SocketException((int)SocketError.TimedOut);
    }

    public static HttpClient CreateBootstrapHttpClient(
        TimeSpan totalTimeout,
        bool allowAutoRedirect = false,
        Func<string, string?>? ipOverrideForHost = null)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectTimeout = TimeSpan.FromMilliseconds(2600),
            ConnectCallback = async (context, token) =>
            {
                var host = context.DnsEndPoint.Host;
                var overrideIp = ipOverrideForHost?.Invoke(host);
                return await ConnectTcpWithBootstrapAsync(
                    host,
                    context.DnsEndPoint.Port,
                    overrideIp,
                    TimeSpan.FromMilliseconds(2500),
                    token).ConfigureAwait(false);
            }
        };

        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = totalTimeout
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DNS-Pulse-Windows/1.1");
        return client;
    }

    public static async Task<byte[]?> ForwardRawUdpAsync(
        string serverIp,
        byte[] queryPacket,
        int timeoutMs,
        CancellationToken ct)
    {
        if (!IPAddress.TryParse(serverIp.Trim(), out var targetIp))
            return null;

        using var udp = new UdpClient(targetIp.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        await udp.SendAsync(queryPacket, new IPEndPoint(targetIp, 53), cts.Token).ConfigureAwait(false);
        var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
        return result.Buffer;
    }

    public static async Task<byte[]?> ForwardRawTcpAsync(
        string serverIp,
        byte[] queryPacket,
        int timeoutMs,
        CancellationToken ct)
    {
        if (!IPAddress.TryParse(serverIp.Trim(), out var targetIp))
            return null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        using var tcp = new TcpClient(targetIp.AddressFamily) { NoDelay = true };
        await tcp.ConnectAsync(targetIp, 53, cts.Token).ConfigureAwait(false);
        await using var stream = tcp.GetStream();

        var lenPrefix = new[] { (byte)((queryPacket.Length >> 8) & 0xFF), (byte)(queryPacket.Length & 0xFF) };
        await stream.WriteAsync(lenPrefix, cts.Token).ConfigureAwait(false);
        await stream.WriteAsync(queryPacket, cts.Token).ConfigureAwait(false);
        await stream.FlushAsync(cts.Token).ConfigureAwait(false);

        return await ReadLengthPrefixedDnsAsync(stream, cts.Token).ConfigureAwait(false);
    }

    public static async Task<byte[]?> ForwardRawDotAsync(
        string dotHost,
        string? serverIp,
        byte[] queryPacket,
        int timeoutMs,
        CancellationToken ct)
    {
        var sniHost = !string.IsNullOrWhiteSpace(dotHost) ? dotHost.Trim() : (serverIp ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(sniHost))
            return null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        await using var rawStream = await ConnectTcpWithBootstrapAsync(
            sniHost,
            853,
            serverIp,
            TimeSpan.FromMilliseconds(Math.Min(timeoutMs, 2400)),
            cts.Token).ConfigureAwait(false);

        using var ssl = new SslStream(
            rawStream,
            leaveInnerStreamOpen: false,
            static (_, _, _, _) => true);

        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = sniHost
        }, cts.Token).ConfigureAwait(false);

        var lenPrefix = new[] { (byte)((queryPacket.Length >> 8) & 0xFF), (byte)(queryPacket.Length & 0xFF) };
        await ssl.WriteAsync(lenPrefix, cts.Token).ConfigureAwait(false);
        await ssl.WriteAsync(queryPacket, cts.Token).ConfigureAwait(false);
        await ssl.FlushAsync(cts.Token).ConfigureAwait(false);

        return await ReadLengthPrefixedDnsAsync(ssl, cts.Token).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadLengthPrefixedDnsAsync(Stream stream, CancellationToken ct)
    {
        var hdr = new byte[2];
        var readHdr = await ReadExactAsync(stream, hdr, 0, 2, ct).ConfigureAwait(false);
        if (readHdr < 2)
            return null;

        int msgLen = (hdr[0] << 8) | hdr[1];
        if (msgLen < 12 || msgLen > 8192)
            return null;

        var buf = new byte[msgLen];
        var readBody = await ReadExactAsync(stream, buf, 0, msgLen, ct).ConfigureAwait(false);
        return readBody == msgLen ? buf : null;
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(offset + total, count - total), ct).ConfigureAwait(false);
            if (n <= 0)
                break;
            total += n;
        }
        return total;
    }

    public static bool TryParseQuestion(byte[] packet, out string domain, out ushort qtype)
    {
        domain = string.Empty;
        qtype = 1;
        if (packet is null || packet.Length < 17)
            return false;

        int offset = 12;
        var sb = new StringBuilder();
        while (offset < packet.Length)
        {
            byte len = packet[offset++];
            if (len == 0)
                break;
            if ((len & 0xC0) != 0)
                return false;
            if (offset + len > packet.Length)
                return false;
            if (sb.Length > 0)
                sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(packet, offset, len));
            offset += len;
        }

        if (offset + 4 > packet.Length)
            return false;

        qtype = (ushort)((packet[offset] << 8) | packet[offset + 1]);
        domain = sb.ToString().Trim().TrimEnd('.').ToLowerInvariant();
        return domain.Length > 0;
    }
}
