using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public sealed class FourStageProber
{
    private const string BrowserUa =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

    private readonly HttpClient _httpClient = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromMilliseconds(3200)
    };

    public async Task<(List<string> Ips, double LatencyMs)> ResolveAsync(
        DnsServerEntry server,
        string domain,
        CancellationToken ct)
    {
        if (server.Protocol == DnsProtocol.DoH && !string.IsNullOrWhiteSpace(server.DohUrl))
            return await QueryDoHAsync(server.DohUrl, domain, ct);

        if (server.Protocol == DnsProtocol.DoT && !string.IsNullOrWhiteSpace(server.DotHost))
            return await QueryDoTAsync(server.DotHost, server.PrimaryIp, domain, ct);

        if (server.Protocol == DnsProtocol.SNI443)
        {
            var ip = server.SmartProxyIp ?? server.PrimaryIp;
            var sw = Stopwatch.StartNew();
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(ip, 443, ct);
            return ([ip], Math.Max(1, sw.Elapsed.TotalMilliseconds));
        }

        return await QueryUdp53Async(server.PrimaryIp, domain, ct);
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryDoHAsync(string dohUrl, string domain, CancellationToken ct)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var sw = Stopwatch.StartNew();

        using var postReq = new HttpRequestMessage(HttpMethod.Post, dohUrl);
        postReq.Headers.UserAgent.ParseAdd(BrowserUa);
        postReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        postReq.Content = new ByteArrayContent(query);
        postReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

        HttpResponseMessage? resp = null;
        try
        {
            resp = await _httpClient.SendAsync(postReq, ct);
            if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"DoH POST {(int)resp.StatusCode}");
        }
        catch
        {
            // Fallback to RFC 8484 HTTP GET (?dns=base64url)
            var sep = dohUrl.Contains('?') ? '&' : '?';
            var getUrl = $"{dohUrl}{sep}dns={DnsPacketCodec.ToBase64Url(query)}";
            using var getReq = new HttpRequestMessage(HttpMethod.Get, getUrl);
            getReq.Headers.UserAgent.ParseAdd(BrowserUa);
            getReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            resp = await _httpClient.SendAsync(getReq, ct);
            resp.EnsureSuccessStatusCode();
        }

        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        var decoded = DnsPacketCodec.DecodeResponse(bytes);
        return (decoded.Ips, Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryUdp53Async(string serverIp, string domain, CancellationToken ct)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var sw = Stopwatch.StartNew();
        using var udp = new UdpClient();
        await udp.SendAsync(query, new IPEndPoint(IPAddress.Parse(serverIp), 53), ct);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(2600);
        var result = await udp.ReceiveAsync(timeoutCts.Token);
        var decoded = DnsPacketCodec.DecodeResponse(result.Buffer);
        return (decoded.Ips, Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryDoTAsync(string dotHost, string fallbackIp, string domain, CancellationToken ct)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var frame = new byte[2 + query.Length];
        frame[0] = (byte)(query.Length >> 8);
        frame[1] = (byte)(query.Length & 0xFF);
        Buffer.BlockCopy(query, 0, frame, 2, query.Length);

        var sw = Stopwatch.StartNew();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(string.IsNullOrWhiteSpace(dotHost) ? fallbackIp : dotHost, 853, ct);
        await using var ssl = new SslStream(tcp.GetStream(), false);
        await ssl.AuthenticateAsClientAsync(dotHost, null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        await ssl.WriteAsync(frame, ct);
        await ssl.FlushAsync(ct);

        var lenBuf = new byte[2];
        await ssl.ReadExactlyAsync(lenBuf, ct);
        int msgLen = (lenBuf[0] << 8) | lenBuf[1];
        var msgBuf = new byte[msgLen];
        await ssl.ReadExactlyAsync(msgBuf, ct);
        var decoded = DnsPacketCodec.DecodeResponse(msgBuf);
        return (decoded.Ips, Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(bool Port443Ok, int? HttpStatus, string? RedirectLocation)> ProbeSniPort443Async(
        string targetIp,
        string sniDomain,
        CancellationToken ct)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(3200);
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(targetIp, 443, timeoutCts.Token);
            await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sniDomain
            }, timeoutCts.Token);

            var reqText = $"HEAD / HTTP/1.1\r\nHost: {sniDomain}\r\nUser-Agent: {BrowserUa}\r\nConnection: close\r\n\r\n";
            await ssl.WriteAsync(Encoding.ASCII.GetBytes(reqText), timeoutCts.Token);
            await ssl.FlushAsync(timeoutCts.Token);

            var buf = new byte[4096];
            int read = await ssl.ReadAsync(buf, timeoutCts.Token);
            var raw = Encoding.UTF8.GetString(buf, 0, read);
            int? status = null;
            string? location = null;

            foreach (var line in raw.Split("\r\n"))
            {
                if (status is null && line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(' ');
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int code)) status = code;
                }
                else if (line.StartsWith("Location:", StringComparison.OrdinalIgnoreCase))
                {
                    location = line["Location:".Length..].Trim();
                }
            }
            return (true, status, location);
        }
        catch
        {
            return (false, null, null);
        }
    }

    public async Task<ProbeResult> ProbeFourStagesAsync(DnsServerEntry server, string targetDomain, bool requiresBypass, CancellationToken ct)
    {
        try
        {
            var r1 = await ResolveAsync(server, targetDomain, ct);
            var r2 = await ResolveAsync(server, targetDomain, ct);
            var burstSw = Stopwatch.StartNew();
            var burst = await Task.WhenAll(
                ResolveAsync(server, targetDomain, ct),
                ResolveAsync(server, targetDomain, ct));
            double burstSec = Math.Max(0.015, burstSw.Elapsed.TotalSeconds);

            var lats = new[] { r1.LatencyMs, r2.LatencyMs, burst[0].LatencyMs, burst[1].LatencyMs };
            double avg = Math.Round(lats.Average(), 1);
            double jitter = Math.Round(lats.Max(x => Math.Abs(x - avg)), 1);
            double tps = Math.Round(2.0 / burstSec, 1);

            var ips = r1.Ips.Count > 0 ? r1.Ips : r2.Ips;
            var validIps = ips.Where(ip => !AntiDirectIpFilter.IsBogonOrLoopback(ip)).ToList();
            bool allDirect = requiresBypass && validIps.Count > 0 && validIps.All(ip => AntiDirectIpFilter.IsDirectServiceIp(ip, targetDomain));

            bool? companionPassed = null;
            if (requiresBypass && validIps.Count > 0 && !allDirect)
            {
                var companions = AntiDirectIpFilter.GetCompanionDomains(targetDomain);
                if (companions.Length > 0)
                {
                    companionPassed = true;
                    foreach (var comp in companions)
                    {
                        var compRes = await ResolveAsync(server, comp, ct);
                        if (compRes.Ips.Count == 0 || compRes.Ips.All(ip => AntiDirectIpFilter.IsDirectServiceIp(ip, comp)))
                            companionPassed = false;
                    }
                }
            }

            bool? port443Ok = null;
            int? httpStatus = null;
            string? redirectLoc = null;
            if (validIps.Count > 0 && !allDirect)
            {
                (port443Ok, httpStatus, redirectLoc) = await ProbeSniPort443Async(validIps[0], targetDomain, ct);
            }

            var (verdict, reason) = AntiDirectIpFilter.Classify(
                requiresBypass, ips, companionPassed, port443Ok, httpStatus, redirectLoc, targetDomain, false);

            return new ProbeResult
            {
                ServerId = server.Id,
                TargetDomain = targetDomain,
                RequiresBypass = requiresBypass,
                LatencyMs = Math.Round(lats[^1]),
                MinLatencyMs = Math.Round(lats.Min()),
                AvgLatencyMs = avg,
                JitterMs = jitter,
                Tps = tps,
                ResolvedIps = ips,
                Verdict = verdict,
                VerdictReason = reason,
                CompanionPassed = companionPassed,
                Port443Ok = port443Ok,
                HttpStatus = httpStatus,
                RedirectLocation = redirectLoc,
                CheckedAt = DateTimeOffset.UtcNow
            };
        }
        catch
        {
            var (verdict, reason) = AntiDirectIpFilter.Classify(
                requiresBypass, [], null, null, null, null, targetDomain, true);
            return new ProbeResult
            {
                ServerId = server.Id,
                TargetDomain = targetDomain,
                RequiresBypass = requiresBypass,
                Verdict = verdict,
                VerdictReason = reason,
                Tps = 0
            };
        }
    }
}
