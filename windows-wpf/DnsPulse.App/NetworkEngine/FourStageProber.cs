using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public sealed class FourStageProber
{
    private const string BrowserUa =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

    // Uses direct public UDP bootstrap DNS (1.1.1.1 / 8.8.8.8) instead of Windows system DNS
    // so probing works even if 127.0.0.1 local tunnel is active or ISP DNS blocks DoH hostnames.
    private readonly HttpClient _httpClient = BootstrapDnsResolver.CreateBootstrapHttpClient(
        TimeSpan.FromMilliseconds(3800),
        allowAutoRedirect: false);

    public int ProbeTimeoutMs { get; set; } = 2600;

    public async Task<(List<string> Ips, double LatencyMs)> ResolveAsync(
        DnsServerEntry server, string domain, CancellationToken ct)
    {
        var (ips, latencyMs, _) = await ResolveWithProtocolAsync(server, domain, ct).ConfigureAwait(false);
        return (ips, latencyMs);
    }

    public async Task<(bool Ok, double LatencyMs)> ProbeTcp443LatencyAsync(
        string hostIp, int timeoutMs, CancellationToken ct)
    {
        if (!IPAddress.TryParse((hostIp ?? string.Empty).Trim(), out var targetIp))
            return (false, 0);

        var sw = Stopwatch.StartNew();
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(Math.Clamp(timeoutMs, 400, 6000));
            using var tcp = new TcpClient(targetIp.AddressFamily) { NoDelay = true };
            await tcp.ConnectAsync(targetIp, 443, timeoutCts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, Math.Max(1, Math.Round(sw.Elapsed.TotalMilliseconds)));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return (false, 0);
        }
    }

    public async Task<(List<string> Ips, double LatencyMs, string ProtocolUsed)> ResolveWithProtocolAsync(
        DnsServerEntry server, string domain, CancellationToken ct)
    {
        // Smart-Proxy SNI443 node: smartproxy://<IP>
        if (server.Protocol == DnsProtocol.SNI443 ||
            (!string.IsNullOrWhiteSpace(server.DohUrl) && server.DohUrl.StartsWith("smartproxy://", StringComparison.OrdinalIgnoreCase)))
        {
            var proxyIp = !string.IsNullOrWhiteSpace(server.DohUrl) && server.DohUrl.StartsWith("smartproxy://", StringComparison.OrdinalIgnoreCase)
                ? server.DohUrl["smartproxy://".Length..].Trim()
                : !string.IsNullOrWhiteSpace(server.SmartProxyIp)
                    ? server.SmartProxyIp.Trim()
                    : server.PrimaryIp.Trim();

            if (!AntiDirectIpFilter.IsValidNonBogonIp(proxyIp))
                return (new List<string>(), 0, "Smart-VPN 443");

            var (tcpOk, tcpMs) = await ProbeTcp443LatencyAsync(proxyIp, Math.Min(ProbeTimeoutMs, 2200), ct).ConfigureAwait(false);
            return tcpOk
                ? (new List<string> { proxyIp }, tcpMs, "Smart-VPN 443")
                : (new List<string>(), 0, "Smart-VPN 443");
        }

        // 1. DoH (RFC 8484 POST -> GET), with UDP 53 fallback if PrimaryIp exists
        if (!string.IsNullOrWhiteSpace(server.DohUrl))
        {
            try
            {
                var res = await QueryDoHAsync(server.DohUrl, domain, ct).ConfigureAwait(false);
                if (res.Ips.Count > 0)
                    return (res.Ips, res.LatencyMs, "DoH");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Fall back to DoT / UDP 53 / TCP 53 if PrimaryIp is known
            }
        }

        // 2. DoT (DNS over TLS port 853)
        if (server.Protocol == DnsProtocol.DoT || !string.IsNullOrWhiteSpace(server.DotHost))
        {
            var dotTarget = !string.IsNullOrWhiteSpace(server.DotHost) ? server.DotHost! : server.PrimaryIp;
            if (!string.IsNullOrWhiteSpace(dotTarget))
            {
                try
                {
                    var res = await QueryDoTAsync(dotTarget, server.PrimaryIp, domain, ct).ConfigureAwait(false);
                    if (res.Ips.Count > 0)
                        return (res.Ips, res.LatencyMs, "DoT");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // Fall back to UDP 53
                }
            }
        }

        // 3. UDP 53 Primary -> UDP 53 Secondary -> TCP 53 Primary
        if (!string.IsNullOrWhiteSpace(server.PrimaryIp) && IPAddress.TryParse(server.PrimaryIp.Trim(), out _))
        {
            try
            {
                var res = await QueryUdp53Async(server.PrimaryIp.Trim(), domain, ct).ConfigureAwait(false);
                if (res.Ips.Count > 0)
                    return (res.Ips, res.LatencyMs, "UDP 53");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Try secondary UDP 53 or TCP 53
            }

            if (!string.IsNullOrWhiteSpace(server.SecondaryIp) && IPAddress.TryParse(server.SecondaryIp.Trim(), out _))
            {
                try
                {
                    var res2 = await QueryUdp53Async(server.SecondaryIp.Trim(), domain, ct).ConfigureAwait(false);
                    if (res2.Ips.Count > 0)
                        return (res2.Ips, res2.LatencyMs, "UDP 53 (2)");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // Try TCP 53
                }
            }

            try
            {
                var tcpRes = await QueryTcp53Async(server.PrimaryIp.Trim(), domain, ct).ConfigureAwait(false);
                if (tcpRes.Ips.Count > 0)
                    return (tcpRes.Ips, tcpRes.LatencyMs, "TCP 53");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // All transports timed out
            }
        }

        return (new List<string>(), 0, server.ProtocolBadge);
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryDoHAsync(string dohUrl, string domain, CancellationToken ct)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var sw = Stopwatch.StartNew();

        // Attempt 1: RFC 8484 POST
        try
        {
            using var postTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            postTimeoutCts.CancelAfter(2600);

            using var req = new HttpRequestMessage(HttpMethod.Post, dohUrl);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            req.Content = new ByteArrayContent(query);
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

            using var resp = await _httpClient.SendAsync(req, postTimeoutCts.Token).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                var wire = await resp.Content.ReadAsByteArrayAsync(postTimeoutCts.Token).ConfigureAwait(false);
                sw.Stop();
                var ips = FilterValidIps(DnsPacketCodec.DecodeResponse(wire).Ips);
                if (ips.Count > 0)
                    return (ips, Math.Max(1, sw.Elapsed.TotalMilliseconds));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Retry via GET if server does not accept POST (some community endpoints only accept GET ?dns=)
        }

        ct.ThrowIfCancellationRequested();

        // Attempt 2: RFC 8484 GET ?dns=...
        using var getTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        getTimeoutCts.CancelAfter(2400);

        var sep = dohUrl.Contains('?') ? "&" : "?";
        var getUrl = $"{dohUrl}{sep}dns={DnsPacketCodec.ToBase64Url(query)}";
        using var getReq = new HttpRequestMessage(HttpMethod.Get, getUrl);
        getReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

        sw.Restart();
        using var getResp = await _httpClient.SendAsync(getReq, getTimeoutCts.Token).ConfigureAwait(false);
        getResp.EnsureSuccessStatusCode();
        var getWire = await getResp.Content.ReadAsByteArrayAsync(getTimeoutCts.Token).ConfigureAwait(false);
        sw.Stop();

        return (FilterValidIps(DnsPacketCodec.DecodeResponse(getWire).Ips), Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryUdp53Async(
        string serverIp, string domain, CancellationToken ct, int? timeoutMs = null)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var sw = Stopwatch.StartNew();
        int effectiveTimeout = Math.Clamp(timeoutMs ?? ProbeTimeoutMs, 500, 6000);
        var raw = await BootstrapDnsResolver.ForwardRawUdpAsync(serverIp, query, effectiveTimeout, ct).ConfigureAwait(false);
        sw.Stop();
        if (raw is not { Length: >= 12 })
            return (new List<string>(), 0);

        return (FilterValidIps(DnsPacketCodec.DecodeResponse(raw).Ips), Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryTcp53Async(string serverIp, string domain, CancellationToken ct)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var sw = Stopwatch.StartNew();
        var raw = await BootstrapDnsResolver.ForwardRawTcpAsync(serverIp, query, Math.Clamp(ProbeTimeoutMs, 800, 6000), ct).ConfigureAwait(false);
        sw.Stop();
        if (raw is not { Length: >= 12 })
            return (new List<string>(), 0);

        return (FilterValidIps(DnsPacketCodec.DecodeResponse(raw).Ips), Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(List<string> Ips, double LatencyMs)> QueryDoTAsync(string dotHost, string fallbackIp, string domain, CancellationToken ct)
    {
        var query = DnsPacketCodec.EncodeQuery(domain);
        var sw = Stopwatch.StartNew();
        var raw = await BootstrapDnsResolver.ForwardRawDotAsync(dotHost, fallbackIp, query, Math.Clamp(ProbeTimeoutMs, 1000, 6000), ct).ConfigureAwait(false);
        sw.Stop();
        if (raw is not { Length: >= 12 })
            return (new List<string>(), 0);

        return (FilterValidIps(DnsPacketCodec.DecodeResponse(raw).Ips), Math.Max(1, sw.Elapsed.TotalMilliseconds));
    }

    public async Task<(bool Port443Ok, int? HttpStatus, string? RedirectLocation)> ProbeSniPort443Async(
        string proxyIp, string targetHost, CancellationToken ct)
    {
        var detailed = await ProbeSniPort443DetailedAsync(proxyIp, targetHost, null, ct).ConfigureAwait(false);
        return (detailed.Port443Ok, detailed.HttpStatus, detailed.RedirectLocation);
    }

    public async Task<(bool Port443Ok, int? HttpStatus, string? RedirectLocation, bool GeoBlockedBody, string? DetailReason, double HandshakeMs)>
        ProbeSniPort443DetailedAsync(string proxyIp, string targetHost, string? apiProxyIp, CancellationToken ct)
    {
        if (!IPAddress.TryParse(proxyIp.Trim(), out var targetIp))
            return (false, null, null, false, "Некорректный IP для проверки порта 443", 0);

        // Stage 3A: Raw TCP 443 connect check
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcpTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            tcpTimeoutCts.CancelAfter(1800);
            using var tcp = new TcpClient(targetIp.AddressFamily) { NoDelay = true };
            await tcp.ConnectAsync(targetIp, 443, tcpTimeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            sw.Stop();
            return (false, null, null, false, $"Порт 443 закрыт на {proxyIp}", sw.Elapsed.TotalMilliseconds);
        }

        // Stage 3B: Real HTTPS probe through proxyIp using SocketsHttpHandler ConnectCallback (SNI = targetHost)
        var cleanHost = (targetHost ?? string.Empty).Trim().Replace("https://", "").Replace("http://", "").Split('/')[0];
        if (string.IsNullOrEmpty(cleanHost))
            cleanHost = "gemini.google.com";

        using var sniClient = BootstrapDnsResolver.CreateBootstrapHttpClient(
            TimeSpan.FromMilliseconds(2600),
            allowAutoRedirect: false,
            host =>
            {
                if (!string.IsNullOrWhiteSpace(apiProxyIp) &&
                    (host.Contains("alkalimakersuite", StringComparison.OrdinalIgnoreCase) ||
                     host.Contains("alkalicore", StringComparison.OrdinalIgnoreCase) ||
                     host.Contains("clients6", StringComparison.OrdinalIgnoreCase)))
                {
                    return apiProxyIp;
                }
                return proxyIp;
            });

        try
        {
            if (DynamicBypassRegistry.IsStrictGoogleAiDomain(cleanHost))
            {
                // Probe 1: AI Studio /welcome (explicitly catches /docs/available-regions redirects and ISP hijacks)
                var (ok1, code1, loc1, bodyGeo1, reason1) = await ExecuteSingleHttpsProbeAsync(
                    sniClient,
                    "https://aistudio.google.com/welcome",
                    proxyIp,
                    requireGoogleSignature: true,
                    ct).ConfigureAwait(false);

                if (!ok1 || bodyGeo1 || AntiDirectIpFilter.IsGeoBlockedRedirect(code1, loc1))
                {
                    sw.Stop();
                    return (ok1, code1, loc1, bodyGeo1, reason1, sw.Elapsed.TotalMilliseconds);
                }

                // Probe 2: AI Studio RPC backend (alkalimakersuite-pa.clients6.google.com)
                var (ok2, code2, loc2, bodyGeo2, reason2) = await ExecuteSingleHttpsProbeAsync(
                    sniClient,
                    "https://alkalimakersuite-pa.clients6.google.com/",
                    proxyIp,
                    requireGoogleSignature: false,
                    ct).ConfigureAwait(false);

                if (!ok2 || bodyGeo2 || AntiDirectIpFilter.IsGeoBlockedRedirect(code2, loc2))
                {
                    sw.Stop();
                    return (ok2, code2, loc2, bodyGeo2, reason2, sw.Elapsed.TotalMilliseconds);
                }

                // Probe 3: Gemini Web (/app)
                var (ok3, code3, loc3, bodyGeo3, reason3) = await ExecuteSingleHttpsProbeAsync(
                    sniClient,
                    "https://gemini.google.com/app",
                    proxyIp,
                    requireGoogleSignature: false,
                    ct).ConfigureAwait(false);

                sw.Stop();
                return (ok3, code3 ?? code1, loc3 ?? loc1, bodyGeo3, reason3, sw.Elapsed.TotalMilliseconds);
            }

            // Generic domain HTTPS probe through proxyIp
            var (ok, code, loc, bodyGeo, reason) = await ExecuteSingleHttpsProbeAsync(
                sniClient,
                $"https://{cleanHost}/",
                proxyIp,
                requireGoogleSignature: false,
                ct).ConfigureAwait(false);

            sw.Stop();
            return (ok, code, loc, bodyGeo, reason, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, null, null, false, $"TLS/HTTPS ошибка на {proxyIp}: {ex.Message}", sw.Elapsed.TotalMilliseconds);
        }
    }

    private static async Task<(bool Ok, int? Status, string? Location, bool BodyGeoBlocked, string? DetailReason)>
        ExecuteSingleHttpsProbeAsync(
            HttpClient client,
            string url,
            string proxyIp,
            bool requireGoogleSignature,
            CancellationToken ct)
    {
        try
        {
            using var reqTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqTimeoutCts.CancelAfter(2400);

            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.TryAddWithoutValidation("User-Agent", BrowserUa);
            req.Headers.TryAddWithoutValidation("Accept-Language", "en-US,en;q=0.9");
            req.Headers.TryAddWithoutValidation("Connection", "close");

            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, reqTimeoutCts.Token).ConfigureAwait(false);
            int code = (int)resp.StatusCode;
            var location = resp.Headers.Location?.ToString();

            if (code is 502 or 503 or 504 or 521 or 522 or 524)
            {
                return (false, code, location, false, $"Прокси {proxyIp} вернул ошибку шлюза (HTTP {code})");
            }

            string bodySnippet = string.Empty;
            try
            {
                await using var bodyStream = await resp.Content.ReadAsStreamAsync(reqTimeoutCts.Token).ConfigureAwait(false);
                var buf = new byte[8192];
                int read = await bodyStream.ReadAsync(buf, reqTimeoutCts.Token).ConfigureAwait(false);
                if (read > 0)
                    bodySnippet = System.Text.Encoding.UTF8.GetString(buf, 0, read);
            }
            catch
            {
                // Partial body is fine
            }

            bool bodyGeo = AntiDirectIpFilter.IsGeoBlockedBody(bodySnippet);
            if (AntiDirectIpFilter.IsGeoBlockedRedirect(code, location) || bodyGeo)
            {
                return (true, code, location, true, $"Редирект/блок региона (HTTP {code} {location ?? ""})".Trim());
            }

            if (requireGoogleSignature)
            {
                var lowerBody = bodySnippet.ToLowerInvariant();
                var lowerLoc = (location ?? string.Empty).ToLowerInvariant();
                bool hasSig = lowerLoc.Contains("accounts.google.com")
                    || lowerBody.Contains("aistudio")
                    || lowerBody.Contains("makersuite")
                    || lowerBody.Contains("gstatic")
                    || lowerBody.Contains("google")
                    || lowerBody.Contains("gemini");

                if (code >= 400 || (!hasSig && !string.IsNullOrWhiteSpace(lowerBody)))
                {
                    return (false, code, location, false, $"Ложный узел {proxyIp} (HTTP {code}, не Google AI Studio)");
                }
            }

            return (true, code, location, false, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return (false, null, null, false, $"HTTPS-запрос через {proxyIp}:443 оборван/таймаут");
        }
    }

    public async Task<ProbeResult> ProbeFourStagesAsync(
        DnsServerEntry server, string targetDomain, bool requiresBypass, CancellationToken ct)
    {
        var primaryCheckDomain = requiresBypass &&
                                 string.Equals(targetDomain?.Trim(), "google.com", StringComparison.OrdinalIgnoreCase)
            ? "aistudio.google.com"
            : (targetDomain ?? "aistudio.google.com").Trim().TrimEnd('.').ToLowerInvariant();

        var result = new ProbeResult
        {
            ServerId = server.Id,
            TargetDomain = primaryCheckDomain,
            RequiresBypass = requiresBypass
        };

        var latencies = new List<double>();
        var resolvedIps = new List<string>();
        int attempts = 0;

        // Stage 1: 2 sequential attempts + 1 stability probe (isolated try/catch so a flaky 2nd packet never discards a working 1st!)
        for (int i = 0; i < 3; i++)
        {
            if (ct.IsCancellationRequested) break;
            attempts++;
            try
            {
                var probe = await ResolveWithProtocolAsync(server, primaryCheckDomain, ct).ConfigureAwait(false);
                if (probe.Ips.Count > 0)
                {
                    latencies.Add(probe.LatencyMs);
                    if (resolvedIps.Count == 0)
                        resolvedIps.AddRange(probe.Ips);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Individual probe failure logged in successRate, don't abort entire server benchmark!
            }
        }

        if (latencies.Count == 0 || resolvedIps.Count == 0)
        {
            var (failVerdict, failReason) = AntiDirectIpFilter.Classify(
                requiresBypass, Array.Empty<string>(), null, null, null, null, primaryCheckDomain, timedOut: true);
            result.Verdict = failVerdict;
            result.VerdictReason = failReason;
            result.SuccessRatePercent = 0;
            return result;
        }

        result.ResolvedIps = resolvedIps.Distinct().ToList();
        result.MinLatencyMs = latencies.Min();
        result.AvgLatencyMs = latencies.Average();
        result.LatencyMs = result.AvgLatencyMs;
        result.JitterMs = ComputeJitter(latencies);
        result.SuccessRatePercent = (int)Math.Round(latencies.Count * 100.0 / Math.Max(1, attempts));
        result.Tps = Math.Max(1, Math.Round((1000.0 / Math.Max(1.0, result.LatencyMs ?? 1.0)) * (result.SuccessRatePercent.Value / 100.0), 1));

        var primaryIp = result.ResolvedIps[0];

        // If universal / clean ping mode (!requiresBypass), skip strict anti-direct & AI Studio redirect gates!
        if (!requiresBypass)
        {
            var (okVerdict, okReason) = AntiDirectIpFilter.Classify(
                false, result.ResolvedIps, true, null, null, null, primaryCheckDomain, timedOut: false);
            result.Verdict = okVerdict;
            result.VerdictReason = okReason;
            return result;
        }

        // Fast fail if primary resolved directly to Google / OpenAI / Cloudflare CDN IP
        if (AntiDirectIpFilter.IsDirectServiceIp(primaryIp, primaryCheckDomain))
        {
            var (directVerdict, directReason) = AntiDirectIpFilter.Classify(
                true, result.ResolvedIps, false, null, null, null, primaryCheckDomain, timedOut: false);
            result.Verdict = directVerdict;
            result.VerdictReason = directReason;
            result.CompanionPassed = false;
            return result;
        }

        // Stage 2: Companion RPC / API domains (verify they aren't leaking direct provider IPs)
        string? apiProxyIp = null;
        var companions = AntiDirectIpFilter.GetCompanionDomains(primaryCheckDomain);
        if (companions.Length > 0)
        {
            bool anyCompanionDirect = false;
            foreach (var comp in companions)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var compRes = await ResolveWithProtocolAsync(server, comp, ct).ConfigureAwait(false);
                    if (compRes.Ips.Count > 0)
                    {
                        if (AntiDirectIpFilter.IsDirectServiceIp(compRes.Ips[0], comp))
                        {
                            anyCompanionDirect = true;
                        }
                        else if (apiProxyIp is null &&
                                 (comp.Contains("alkalimakersuite", StringComparison.OrdinalIgnoreCase) ||
                                  comp.Contains("generativelanguage", StringComparison.OrdinalIgnoreCase)))
                        {
                            apiProxyIp = compRes.Ips[0];
                        }
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // Companion timeout alone doesn't fail if main proxy port 443 works
                }
            }
            result.CompanionPassed = !anyCompanionDirect;
        }

        // Stage 3 & 4: TCP/TLS Port 443 + HTTP /welcome + /app + /docs/available-regions check
        var (port443Ok, httpStatus, redirectLoc, geoBody, detailReason, _) =
            await ProbeSniPort443DetailedAsync(primaryIp, primaryCheckDomain, apiProxyIp, ct).ConfigureAwait(false);

        result.Port443Ok = port443Ok;
        result.HttpStatus = httpStatus;
        result.RedirectLocation = redirectLoc;

        var (verdict, reason) = AntiDirectIpFilter.Classify(
            true,
            result.ResolvedIps,
            result.CompanionPassed,
            port443Ok,
            httpStatus,
            redirectLoc,
            primaryCheckDomain,
            timedOut: false,
            isGeoBlockedBody: geoBody,
            customFailureDetail: detailReason);

        result.Verdict = verdict;
        result.VerdictReason = reason;
        return result;
    }

    private static List<string> FilterValidIps(IEnumerable<string> rawIps) =>
        rawIps.Where(AntiDirectIpFilter.IsValidNonBogonIp).Distinct().ToList();

    private static double ComputeJitter(List<double> values)
    {
        if (values.Count < 2) return 0;
        double avg = values.Average();
        return Math.Sqrt(values.Sum(v => Math.Pow(v - avg, 2)) / values.Count);
    }
}
