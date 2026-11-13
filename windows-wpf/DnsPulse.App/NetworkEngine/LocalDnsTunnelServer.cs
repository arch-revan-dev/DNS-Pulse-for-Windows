using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public sealed class LocalDnsTunnelServer : IAsyncDisposable
{
    private readonly HttpClient _httpClient = BootstrapDnsResolver.CreateBootstrapHttpClient(
        TimeSpan.FromMilliseconds(2600),
        allowAutoRedirect: false);

    private readonly ConcurrentDictionary<string, (byte[] Packet, long ExpiresAtMs)> _responseCache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, byte> _activeTargetDomains =
        new(StringComparer.OrdinalIgnoreCase);

    private UdpClient? _udpListener;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;
    private volatile DnsServerEntry? _activeServer;
    private volatile string _lastLearnedSmartProxyIp = string.Empty;
    private long _queriesHandled;
    private long _cacheHits;

    public bool IsRunning => _cts is not null && !_cts.IsCancellationRequested && _udpListener is not null;
    public DnsServerEntry? ActiveServer => _activeServer;
    public long QueriesHandled => Interlocked.Read(ref _queriesHandled);
    public long CacheHits => Interlocked.Read(ref _cacheHits);
    public string ListenEndpoint { get; private set; } = "127.0.0.1:53";
    public string? LastErrorMessage { get; private set; }

    /// <summary>
    /// When true (default, matching Android), only AI/streaming/gaming/custom target domains route through Smart-DNS/Smart-Proxy;
    /// all other domains resolve rapidly via 1.1.1.1 / 8.8.8.8 so normal internet is never blocked or slowed.
    /// </summary>
    public bool SplitTunnelBypassOnly { get; set; } = true;

    /// <summary>
    /// When true (default), suppresses AAAA (IPv6) and HTTPS/SVCB queries on bypass domains so Windows browsers
    /// don't bypass the Smart-DNS/SNI-443 IPv4 proxy over direct IPv6 routes.
    /// </summary>
    public bool BlockIpv6OnBypass { get; set; } = true;

    public void UpdateBypassDomains(IEnumerable<string> domains)
    {
        if (domains is null) return;
        DynamicBypassRegistry.ClassifyAndAddDomains(domains);
    }

    public void SetActiveTargetDomain(string? targetDomain)
    {
        _activeTargetDomains.Clear();
        if (string.IsNullOrWhiteSpace(targetDomain))
            return;

        var clean = targetDomain.Trim().TrimEnd('.').ToLowerInvariant();
        if (DynamicBypassRegistry.IsValidDomainName(clean))
        {
            _activeTargetDomains[clean] = 0;
            foreach (var comp in AntiDirectIpFilter.GetCompanionDomains(clean))
            {
                _activeTargetDomains[comp.ToLowerInvariant()] = 0;
            }
        }
    }

    public Task StartAsync(DnsServerEntry server, string listenIp = "127.0.0.1")
    {
        Stop();
        LastErrorMessage = null;
        _activeServer = server;
        _responseCache.Clear();
        _lastLearnedSmartProxyIp = string.Empty;
        Interlocked.Exchange(ref _queriesHandled, 0);
        Interlocked.Exchange(ref _cacheHits, 0);

        if (!IPAddress.TryParse(listenIp, out var bindAddr))
            bindAddr = IPAddress.Loopback;

        try
        {
            var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(bindAddr, 53));
            _udpListener = udp;
        }
        catch (SocketException ex)
        {
            LastErrorMessage = $"Порт {listenIp}:53 занят или требует прав администратора ({ex.SocketErrorCode}).";
            throw new InvalidOperationException(LastErrorMessage, ex);
        }

        ListenEndpoint = $"{bindAddr}:53";
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _listenTask = Task.Run(() => ListenLoopAsync(_udpListener, token), token);
        return Task.CompletedTask;
    }

    public void SwitchServer(DnsServerEntry nextServer)
    {
        _activeServer = nextServer;
        _responseCache.Clear();
        _lastLearnedSmartProxyIp = string.Empty;
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try { _udpListener?.Dispose(); } catch { /* ignore */ }
        _udpListener = null;
        _cts?.Dispose();
        _cts = null;
        _listenTask = null;
        _activeServer = null;
        _responseCache.Clear();
        _lastLearnedSmartProxyIp = string.Empty;
    }

    private async Task ListenLoopAsync(UdpClient listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult packet;
            try
            {
                packet = await listener.ReceiveAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch
            {
                continue;
            }

            _ = HandlePacketAsync(listener, packet, ct);
        }
    }

    private async Task HandlePacketAsync(UdpClient listener, UdpReceiveResult packet, CancellationToken ct)
    {
        try
        {
            var response = await ForwardDnsQueryAsync(packet.Buffer, ct).ConfigureAwait(false);
            if (response is { Length: >= 12 })
            {
                await listener.SendAsync(response, packet.RemoteEndPoint, ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // Never crash listener loop on malformed/timed-out packets
        }
    }

    private async Task<byte[]?> ForwardDnsQueryAsync(byte[] queryBytes, CancellationToken ct)
    {
        if (queryBytes.Length < 12)
            return null;

        Interlocked.Increment(ref _queriesHandled);

        BootstrapDnsResolver.TryParseQuestion(queryBytes, out var qDomain, out var qType);
        var server = _activeServer;
        var now = Environment.TickCount64;

        // 0. Check whether query targets a bypass service or our own upstream endpoint
        bool isUpstreamSelfHost = IsUpstreamEndpointHost(server, qDomain);
        bool isLocalOrInternal = string.IsNullOrEmpty(qDomain)
            || qDomain == "localhost"
            || qDomain.EndsWith(".local", StringComparison.Ordinal)
            || qDomain.EndsWith(".lan", StringComparison.Ordinal)
            || qDomain.EndsWith(".internal", StringComparison.Ordinal);

        bool isBypassTarget = !isUpstreamSelfHost && !isLocalOrInternal && IsBypassDomain(qDomain);

        // 1. In-memory DNS cache (keyed by domain + qtype so A and AAAA never collide)
        string cacheKey = $"{qDomain}|{qType}";
        if (_responseCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresAtMs > now)
        {
            Interlocked.Increment(ref _cacheHits);
            return StampTransactionId(cached.Packet, queryBytes);
        }

        // 2. Prevent IPv6/HTTPS(SVCB) leak for Smart-Proxy nodes and protected AI/Streaming/Gaming domains
        bool isSmartProxyNode = server is not null &&
            (server.Protocol == DnsProtocol.SNI443 ||
             (!string.IsNullOrWhiteSpace(server.DohUrl) && server.DohUrl.StartsWith("smartproxy://", StringComparison.OrdinalIgnoreCase)));

        if (BlockIpv6OnBypass &&
            (isSmartProxyNode || isBypassTarget || !SplitTunnelBypassOnly) &&
            isBypassTarget &&
            qType is 28 or 65) // AAAA (28) or HTTPS/SVCB (65)
        {
            return BuildEmptyNoErrorResponse(queryBytes);
        }

        // 3. Smart-Proxy SNI443 node: synthesize proxy IP for bypass targets on QTYPE A (1)
        if (isSmartProxyNode && server is not null && isBypassTarget)
        {
            var proxyIp = !string.IsNullOrWhiteSpace(server.DohUrl) && server.DohUrl.StartsWith("smartproxy://", StringComparison.OrdinalIgnoreCase)
                ? server.DohUrl["smartproxy://".Length..].Trim()
                : !string.IsNullOrWhiteSpace(server.SmartProxyIp)
                    ? server.SmartProxyIp.Trim()
                    : server.PrimaryIp.Trim();

            if (qType == 1 && AntiDirectIpFilter.IsValidNonBogonIp(proxyIp))
            {
                var synthesized = BuildResponsePacket(queryBytes, new[] { proxyIp }, 60);
                _responseCache[cacheKey] = (synthesized, now + 45_000L);
                return synthesized;
            }
        }

        // 4. Bypass non-tunnel domains -> rapid direct public UDP 1.1.1.1 / 8.8.8.8 (prevents internet blackout!)
        if (server is null || isUpstreamSelfHost || (SplitTunnelBypassOnly && !isBypassTarget) || isSmartProxyNode)
        {
            var fastDirect = await QueryFallbackPublicAsync(queryBytes, ct).ConfigureAwait(false);
            if (fastDirect is { Length: >= 12 })
            {
                _responseCache[cacheKey] = (fastDirect, now + 45_000L);
                return fastDirect;
            }
            return BuildServFailResponse(queryBytes);
        }

        // 5. Route bypass target (or full tunnel when !SplitTunnelBypassOnly) through selected upstream server
        byte[]? upstreamReply = await QueryConfiguredUpstreamAsync(server, queryBytes, ct).ConfigureAwait(false);

        if (upstreamReply is { Length: >= 12 })
        {
            if (isBypassTarget && qType == 1)
            {
                var decoded = DnsPacketCodec.DecodeResponse(upstreamReply);
                var validIp = decoded.Ips.FirstOrDefault(AntiDirectIpFilter.IsValidNonBogonIp);
                if (!string.IsNullOrEmpty(validIp))
                {
                    if (AntiDirectIpFilter.IsDirectServiceIp(validIp, qDomain))
                    {
                        // Guard against direct IP leak if we already learned a working Smart-Proxy IP from this upstream
                        if (!string.IsNullOrEmpty(_lastLearnedSmartProxyIp))
                        {
                            var guarded = BuildResponsePacket(queryBytes, new[] { _lastLearnedSmartProxyIp }, 45);
                            _responseCache[cacheKey] = (guarded, now + 45_000L);
                            return guarded;
                        }
                    }
                    else
                    {
                        _lastLearnedSmartProxyIp = validIp;
                    }
                }
            }

            _responseCache[cacheKey] = (upstreamReply, now + 45_000L);
            return upstreamReply;
        }

        // 6. Safety fallback so an upstream timeout never drops internet connectivity
        if (isBypassTarget && qType == 1 && !string.IsNullOrEmpty(_lastLearnedSmartProxyIp))
        {
            return BuildResponsePacket(queryBytes, new[] { _lastLearnedSmartProxyIp }, 30);
        }

        var fallback = await QueryFallbackPublicAsync(queryBytes, ct).ConfigureAwait(false);
        return fallback ?? BuildServFailResponse(queryBytes);
    }

    private bool IsBypassDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;

        if (DynamicBypassRegistry.IsBypassTargetDomain(domain))
            return true;

        foreach (var custom in _activeTargetDomains.Keys)
        {
            if (domain.Equals(custom, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + custom, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsUpstreamEndpointHost(DnsServerEntry? server, string qDomain)
    {
        if (server is null || string.IsNullOrWhiteSpace(qDomain))
            return false;

        if (!string.IsNullOrWhiteSpace(server.DohUrl) &&
            Uri.TryCreate(server.DohUrl, UriKind.Absolute, out var dohUri) &&
            !string.IsNullOrWhiteSpace(dohUri.Host))
        {
            if (qDomain.Equals(dohUri.Host, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (!string.IsNullOrWhiteSpace(server.DotHost) &&
            qDomain.Equals(server.DotHost.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private async Task<byte[]?> QueryConfiguredUpstreamAsync(DnsServerEntry server, byte[] queryBytes, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(server.DohUrl) &&
            !server.DohUrl.StartsWith("smartproxy://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, server.DohUrl);
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
                req.Content = new ByteArrayContent(queryBytes);
                req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

                using var resp = await _httpClient.SendAsync(req, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    var wire = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                    if (wire.Length >= 12)
                        return StampTransactionId(wire, queryBytes);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Fall back to GET / DoT / UDP 53
            }

            try
            {
                var sep = server.DohUrl.Contains('?') ? "&" : "?";
                var url = $"{server.DohUrl}{sep}dns={DnsPacketCodec.ToBase64Url(queryBytes)}";
                using var getReq = new HttpRequestMessage(HttpMethod.Get, url);
                getReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

                using var getResp = await _httpClient.SendAsync(getReq, ct).ConfigureAwait(false);
                if (getResp.IsSuccessStatusCode)
                {
                    var wire = await getResp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                    if (wire.Length >= 12)
                        return StampTransactionId(wire, queryBytes);
                }
            }
            catch
            {
                // Continue fallback chain
            }
        }

        if (server.Protocol == DnsProtocol.DoT || !string.IsNullOrWhiteSpace(server.DotHost))
        {
            var dotHost = !string.IsNullOrWhiteSpace(server.DotHost) ? server.DotHost! : server.PrimaryIp;
            var dotWire = await BootstrapDnsResolver.ForwardRawDotAsync(dotHost, server.PrimaryIp, queryBytes, 2200, ct).ConfigureAwait(false);
            if (dotWire is { Length: >= 12 })
                return StampTransactionId(dotWire, queryBytes);
        }

        if (!string.IsNullOrWhiteSpace(server.PrimaryIp))
        {
            var udp1 = await BootstrapDnsResolver.ForwardRawUdpAsync(server.PrimaryIp, queryBytes, 1500, ct).ConfigureAwait(false);
            if (udp1 is { Length: >= 12 })
                return StampTransactionId(udp1, queryBytes);
        }

        if (!string.IsNullOrWhiteSpace(server.SecondaryIp))
        {
            var udp2 = await BootstrapDnsResolver.ForwardRawUdpAsync(server.SecondaryIp, queryBytes, 1500, ct).ConfigureAwait(false);
            if (udp2 is { Length: >= 12 })
                return StampTransactionId(udp2, queryBytes);
        }

        if (!string.IsNullOrWhiteSpace(server.PrimaryIp))
        {
            var tcp = await BootstrapDnsResolver.ForwardRawTcpAsync(server.PrimaryIp, queryBytes, 1800, ct).ConfigureAwait(false);
            if (tcp is { Length: >= 12 })
                return StampTransactionId(tcp, queryBytes);
        }

        return null;
    }

    private static async Task<byte[]?> QueryFallbackPublicAsync(byte[] queryBytes, CancellationToken ct)
    {
        var cf = await BootstrapDnsResolver.ForwardRawUdpAsync("1.1.1.1", queryBytes, 1300, ct).ConfigureAwait(false);
        if (cf is { Length: >= 12 })
            return StampTransactionId(cf, queryBytes);

        var gg = await BootstrapDnsResolver.ForwardRawUdpAsync("8.8.8.8", queryBytes, 1300, ct).ConfigureAwait(false);
        return gg is { Length: >= 12 } ? StampTransactionId(gg, queryBytes) : null;
    }

    private static byte[] StampTransactionId(byte[] response, byte[] originalQuery)
    {
        if (response.Length < 2 || originalQuery.Length < 2)
            return response;
        var clone = (byte[])response.Clone();
        clone[0] = originalQuery[0];
        clone[1] = originalQuery[1];
        return clone;
    }

    private static int FindQuestionEndOffset(byte[] query)
    {
        int offset = 12;
        while (offset < query.Length)
        {
            byte len = query[offset++];
            if (len == 0) break;
            if ((len & 0xC0) != 0)
            {
                offset++;
                break;
            }
            offset += len;
        }
        return Math.Min(query.Length, offset + 4);
    }

    public static byte[] BuildEmptyNoErrorResponse(byte[] query)
    {
        if (query is null || query.Length < 12)
            return Array.Empty<byte>();

        int qEnd = FindQuestionEndOffset(query);
        using var ms = new MemoryStream();
        ms.Write(query, 0, Math.Min(2, query.Length));
        byte rdFlag = (byte)(query.Length > 2 ? (query[2] & 0x01) : 0x01);
        ms.WriteByte((byte)(0x80 | rdFlag)); // QR=1, RD preserved
        ms.WriteByte(0x80); // RA=1, RCODE=0 (NOERROR)
        ms.WriteByte(0x00); ms.WriteByte(0x01); // QDCOUNT = 1
        ms.WriteByte(0x00); ms.WriteByte(0x00); // ANCOUNT = 0
        ms.WriteByte(0x00); ms.WriteByte(0x00); // NSCOUNT = 0
        ms.WriteByte(0x00); ms.WriteByte(0x00); // ARCOUNT = 0
        if (qEnd > 12)
            ms.Write(query, 12, qEnd - 12);
        return ms.ToArray();
    }

    public static byte[] BuildServFailResponse(byte[] query)
    {
        if (query is null || query.Length < 12)
            return Array.Empty<byte>();

        int qEnd = FindQuestionEndOffset(query);
        using var ms = new MemoryStream();
        ms.Write(query, 0, Math.Min(2, query.Length));
        byte rdFlag = (byte)(query.Length > 2 ? (query[2] & 0x01) : 0x01);
        ms.WriteByte((byte)(0x80 | rdFlag));
        ms.WriteByte(0x82); // RA=1, RCODE=2 (SERVFAIL)
        ms.WriteByte(0x00); ms.WriteByte(0x01);
        ms.WriteByte(0x00); ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x00);
        if (qEnd > 12)
            ms.Write(query, 12, qEnd - 12);
        return ms.ToArray();
    }

    public static byte[] BuildResponsePacket(byte[] query, IReadOnlyList<string> ips, uint ttlSeconds = 60)
    {
        if (query is null || query.Length < 12)
            return Array.Empty<byte>();

        var validIpv4 = new List<byte[]>();
        foreach (var ip in ips)
        {
            if (IPAddress.TryParse(ip?.Trim(), out var addr) && addr.AddressFamily == AddressFamily.InterNetwork)
                validIpv4.Add(addr.GetAddressBytes());
        }

        if (validIpv4.Count == 0)
            return BuildEmptyNoErrorResponse(query);

        int qEnd = FindQuestionEndOffset(query);
        using var ms = new MemoryStream();
        ms.Write(query, 0, Math.Min(2, query.Length));
        byte rdFlag = (byte)(query.Length > 2 ? (query[2] & 0x01) : 0x01);
        ms.WriteByte((byte)(0x80 | rdFlag));
        ms.WriteByte(0x80); // RA=1, RCODE=0
        ms.WriteByte(0x00); ms.WriteByte(0x01); // QDCOUNT = 1
        ms.WriteByte((byte)((validIpv4.Count >> 8) & 0xFF));
        ms.WriteByte((byte)(validIpv4.Count & 0xFF)); // ANCOUNT
        ms.WriteByte(0x00); ms.WriteByte(0x00); // NSCOUNT
        ms.WriteByte(0x00); ms.WriteByte(0x00); // ARCOUNT

        if (qEnd > 12)
            ms.Write(query, 12, qEnd - 12);

        foreach (var addrBytes in validIpv4)
        {
            ms.WriteByte(0xC0); ms.WriteByte(0x0C); // Name pointer to QNAME at offset 12
            ms.WriteByte(0x00); ms.WriteByte(0x01); // TYPE = A
            ms.WriteByte(0x00); ms.WriteByte(0x01); // CLASS = IN
            ms.WriteByte((byte)((ttlSeconds >> 24) & 0xFF));
            ms.WriteByte((byte)((ttlSeconds >> 16) & 0xFF));
            ms.WriteByte((byte)((ttlSeconds >> 8) & 0xFF));
            ms.WriteByte((byte)(ttlSeconds & 0xFF));
            ms.WriteByte(0x00); ms.WriteByte(0x04); // RDLENGTH = 4
            ms.Write(addrBytes, 0, 4);
        }

        return ms.ToArray();
    }

    public ValueTask DisposeAsync()
    {
        Stop();
        _httpClient.Dispose();
        return ValueTask.CompletedTask;
    }
}
