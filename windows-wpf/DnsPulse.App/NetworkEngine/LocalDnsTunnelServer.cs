using System.Collections.Concurrent;
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

    public bool IsRunning => _cts is not null && !_cts.IsCancellationRequested;
    public long QueriesHandled => Interlocked.Read(ref _queriesHandled);
    public string ListenEndpoint { get; private set; } = "127.0.0.1:53";

    public void UpdateBypassDomains(IEnumerable<string> domains)
    {
        lock (_bypassDomains)
        {
            _bypassDomains.Clear();
            foreach (var d in domains) _bypassDomains.Add(d.Trim().ToLowerInvariant());
        }
    }

    public Task StartAsync(DnsServerEntry server, string listenIp = "127.0.0.1")
    {
        Stop();
        _activeServer = server;
        _cache.Clear();
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
            // SERVFAIL fallback
            var fail = (byte[])requestPacket.Clone();
            if (fail.Length >= 4) { fail[2] = 0x81; fail[3] = 0x82; }
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
            if (idx + len > packet.Length) break;
            labels.Add(System.Text.Encoding.UTF8.GetString(packet, idx, len));
            idx += len;
        }
        return string.Join('.', labels);
    }

    private static byte[] BuildResponsePacket(byte[] query, List<string> ips)
    {
        if (ips.Count == 0 || !IPAddress.TryParse(ips[0], out var ip))
        {
            var empty = (byte[])query.Clone();
            empty[2] = 0x81; empty[3] = 0x80;
            return empty;
        }
        var addrBytes = ip.GetAddressBytes();
        using var ms = new MemoryStream(query.Length + 16);
        ms.Write(query);
        var buf = ms.GetBuffer();
        buf[2] = 0x81; buf[3] = 0x80;
        buf[6] = 0x00; buf[7] = 0x01; // ANCOUNT=1
        ms.Write([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        ms.Write(addrBytes);
        return ms.ToArray();
    }

    public ValueTask DisposeAsync()
    {
        Stop();
        return ValueTask.CompletedTask;
    }
}
