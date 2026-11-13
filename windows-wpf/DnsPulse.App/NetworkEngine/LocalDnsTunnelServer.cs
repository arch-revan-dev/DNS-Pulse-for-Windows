using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public sealed class LocalDnsTunnelServer : IAsyncDisposable
{
    private readonly FourStageProber _prober = new();
    private readonly ConcurrentDictionary<string, (byte[] Packet, DateTimeOffset Expires)> _cache = new();
    private readonly HashSet<string> _bypassDomains = new(StringComparer.OrdinalIgnoreCase);

    private UdpClient? _udpListener;
    private CancellationTokenSource? _cts;
    private DnsServerEntry? _activeServer;
    private long _queriesHandled;
    private long _cacheHits;

    public bool IsRunning => _cts is not null && !_cts.IsCancellationRequested;
    public long QueriesHandled => Interlocked.Read(ref _queriesHandled);
    public long CacheHits => Interlocked.Read(ref _cacheHits);
    public DnsServerEntry? ActiveServer => _activeServer;
    public string ListenEndpoint { get; private set; } = "127.0.0.1:53";

    public void UpdateBypassDomains(IEnumerable<string> domains)
    {
        lock (_bypassDomains)
        {
            _bypassDomains.Clear();
            foreach (var d in domains)
            {
                var clean = d.Trim().ToLowerInvariant();
                if (!string.IsNullOrEmpty(clean)) _bypassDomains.Add(clean);
            }
        }
    }

    public Task StartAsync(DnsServerEntry server, string listenIp = "127.0.0.1")
    {
        Stop();
        _activeServer = server;
        _cache.Clear();
        Interlocked.Exchange(ref _queriesHandled, 0);
        Interlocked.Exchange(ref _cacheHits, 0);
        ListenEndpoint = $"{listenIp}:53";
        _cts = new CancellationTokenSource();
        _udpListener = new UdpClient(new IPEndPoint(IPAddress.Parse(listenIp), 53));
        _ = AcceptLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    public void SwitchServer(DnsServerEntry nextServer)
    {
        _activeServer = nextServer;
        _cache.Clear();
    }

    public void Stop()
    {
        _cts?.Cancel();
        _udpListener?.Dispose();
        _udpListener = null;
        _cts = null;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _udpListener is not null)
        {
            try
            {
                var received = await _udpListener.ReceiveAsync(ct);
                _ = Task.Run(() => HandleQueryAsync(received.Buffer, received.RemoteEndPoint, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Keep tunnel alive on transient socket errors
            }
        }
    }

    private async Task HandleQueryAsync(byte[] requestPacket, IPEndPoint client, CancellationToken ct)
    {
        if (requestPacket.Length < 12 || _activeServer is null || _udpListener is null) return;
        Interlocked.Increment(ref _queriesHandled);

        string qname = ExtractQname(requestPacket);
        bool useBypass = IsBypassDomain(qname);
        var upstream = useBypass
            ? _activeServer
            : new DnsServerEntry { Id = "direct_cf", Name = "Cloudflare", Protocol = DnsProtocol.UDP, PrimaryIp = "1.1.1.1" };

        try
        {
            byte[] responseBytes;
            string cacheKey = $"{upstream.Id}:{qname}";
            if (_cache.TryGetValue(cacheKey, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
            {
                Interlocked.Increment(ref _cacheHits);
                responseBytes = (byte[])cached.Packet.Clone();
                responseBytes[0] = requestPacket[0];
                responseBytes[1] = requestPacket[1];
            }
            else
            {
                var (ips, _) = await _prober.ResolveAsync(upstream, qname, ct);
                responseBytes = BuildResponsePacket(requestPacket, ips);
                _cache[cacheKey] = (responseBytes, DateTimeOffset.UtcNow.AddSeconds(60));
            }
            await _udpListener.SendAsync(responseBytes, client, ct);
        }
        catch
        {
            var fail = BuildServfailPacket(requestPacket);
            await _udpListener.SendAsync(fail, client, ct);
        }
    }

    private bool IsBypassDomain(string qname)
    {
        if (string.IsNullOrWhiteSpace(qname)) return false;
        lock (_bypassDomains)
        {
            if (_bypassDomains.Count == 0) return true;
            if (_bypassDomains.Contains(qname)) return true;
            return _bypassDomains.Any(d => qname.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        }
    }

    private static string ExtractQname(byte[] packet)
    {
        var labels = new List<string>();
        int idx = 12;
        while (idx < packet.Length)
        {
            byte len = packet[idx++];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0 || idx + len > packet.Length) break;
            labels.Add(System.Text.Encoding.UTF8.GetString(packet, idx, len));
            idx += len;
        }
        return string.Join('.', labels);
    }

    /// <summary>
    /// Extracts the end offset of the Question section so trailing EDNS0 OPT records are cleanly stripped.
    /// </summary>
    internal static int FindQuestionSectionEnd(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 12) return packet.Length;
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        int offset = 12;
        for (int q = 0; q < qdCount && offset < packet.Length; q++)
        {
            while (offset < packet.Length)
            {
                byte len = packet[offset];
                if (len == 0)
                {
                    offset++;
                    break;
                }
                if ((len & 0xC0) == 0xC0)
                {
                    offset += 2;
                    break;
                }
                offset += 1 + len;
            }
            offset += 4; // QTYPE (2) + QCLASS (2)
        }
        return Math.Min(offset, packet.Length);
    }

    public static byte[] BuildResponsePacket(byte[] query, IReadOnlyList<string> ips, uint ttlSeconds = 60)
    {
        int questionEnd = FindQuestionSectionEnd(query);
        var ipv4List = new List<byte[]>();
        foreach (var raw in ips)
        {
            if (IPAddress.TryParse(raw, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                ipv4List.Add(ip.GetAddressBytes());
        }

        using var ms = new MemoryStream(questionEnd + ipv4List.Count * 16);
        ms.Write(query, 0, questionEnd);

        var header = ms.GetBuffer();
        header[2] = 0x81; // QR=1, RD=1
        header[3] = 0x80; // RA=1, RCODE=0
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), (ushort)ipv4List.Count);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(8, 2), 0);  // NSCOUNT=0
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(10, 2), 0); // ARCOUNT=0 (strip EDNS0)

        Span<byte> ttlBuf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(ttlBuf, ttlSeconds);

        foreach (var addrBytes in ipv4List)
        {
            ms.Write([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
            ms.Write(ttlBuf);
            ms.Write([0x00, 0x04]);
            ms.Write(addrBytes);
        }

        return ms.ToArray();
    }

    private static byte[] BuildServfailPacket(byte[] query)
    {
        int questionEnd = FindQuestionSectionEnd(query);
        var fail = new byte[Math.Max(12, questionEnd)];
        Buffer.BlockCopy(query, 0, fail, 0, Math.Min(query.Length, fail.Length));
        fail[2] = 0x81;
        fail[3] = 0x82; // SERVFAIL
        BinaryPrimitives.WriteUInt16BigEndian(fail.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(fail.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(fail.AsSpan(10, 2), 0);
        return fail;
    }

    public ValueTask DisposeAsync()
    {
        Stop();
        return ValueTask.CompletedTask;
    }
}
