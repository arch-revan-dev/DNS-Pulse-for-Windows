using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Security;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Diagnostics;

/// <summary>
/// Executes deterministic 6-layer diagnostics across host health, transport latency, DNS integrity,
/// X.509 TLS authenticity, application/companion geo-probes, and 1-click remediation classification.
/// </summary>
public sealed class SixLayerDiagnosticEngine
{
    private const int MaxBodyInspectBytes = 8192;

    private readonly IBootstrapResolver _bootstrapResolver;
    private readonly Func<DnsProtocol, IDnsUpstreamClient> _clientFactory;
    private readonly IHostNetworkHealthProvider? _hostHealthProvider;

    public SixLayerDiagnosticEngine(
        IBootstrapResolver bootstrapResolver,
        IDnsUpstreamClient upstreamClient,
        IHostNetworkHealthProvider? hostHealthProvider = null)
        : this(
            bootstrapResolver,
            CreateSingleClientFactory(upstreamClient),
            hostHealthProvider)
    {
    }

    public SixLayerDiagnosticEngine(
        IBootstrapResolver bootstrapResolver,
        Func<DnsProtocol, IDnsUpstreamClient> clientFactory,
        IHostNetworkHealthProvider? hostHealthProvider = null)
    {
        ArgumentNullException.ThrowIfNull(bootstrapResolver);
        ArgumentNullException.ThrowIfNull(clientFactory);

        _bootstrapResolver = bootstrapResolver;
        _clientFactory = clientFactory;
        _hostHealthProvider = hostHealthProvider;
    }

    /// <summary>
    /// Runs all six diagnostic layers for <paramref name="targetDomain"/> through <paramref name="upstream"/>.
    /// </summary>
    public async Task<DiagnosticReport> DiagnoseAsync(
        string targetDomain,
        DnsServerEntry upstream,
        DiagnosticProbeOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDomain);
        ArgumentNullException.ThrowIfNull(upstream);

        string normalizedDomain = DnsQuestion.Create(targetDomain, DnsRecordType.A).Name;
        DiagnosticProbeOptions effectiveOptions = options ?? new DiagnosticProbeOptions();
        DateTimeOffset startedAtUtc = DateTimeOffset.UtcNow;
        Stopwatch totalStopwatch = Stopwatch.StartNew();

        List<DiagnosticLayerResult> layers = new(6);

        // Layer 1: Host & Windows Network Health
        Layer1Outcome layer1 = await ExecuteLayer1Async(effectiveOptions.ProbeTimeout, cancellationToken).ConfigureAwait(false);
        layers.Add(layer1.Result);

        // Layer 2: Transport Reachability & Latency
        Layer2Outcome layer2 = await ExecuteLayer2Async(normalizedDomain, upstream, effectiveOptions, cancellationToken).ConfigureAwait(false);
        layers.Add(layer2.Result);

        // Layer 3: DNS Integrity & Poisoning Check
        Layer3Outcome layer3 = await ExecuteLayer3Async(
            normalizedDomain,
            upstream,
            layer2.SampleResponse,
            effectiveOptions,
            cancellationToken).ConfigureAwait(false);
        layers.Add(layer3.Result);

        // Layer 4: TLS Handshake & Cryptographic Authenticity
        Layer4Outcome layer4 = effectiveOptions.IncludeTlsAndApplicationProbes
            ? await ExecuteLayer4Async(
                normalizedDomain,
                upstream,
                layer3.ResolvedAddresses,
                layer3.BaselineAddresses,
                effectiveOptions,
                cancellationToken).ConfigureAwait(false)
            : new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Skipped,
                    TimeSpan.Zero,
                    "TLS probe skipped by benchmark options."),
                Endpoint: null,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: false,
                TcpConnectBlocked: false,
                NegotiatedAlpn: null);
        layers.Add(layer4.Result);

        // Layer 5: Application & Companion API Geo-Probe
        Layer5Outcome layer5 = effectiveOptions.IncludeTlsAndApplicationProbes
            ? await ExecuteLayer5Async(
                normalizedDomain,
                upstream,
                layer4,
                effectiveOptions,
                cancellationToken).ConfigureAwait(false)
            : new Layer5Outcome(
                new DiagnosticLayerResult(
                    5,
                    "Application & Companion API Geo-Probe",
                    DiagnosticLayerStatus.Skipped,
                    TimeSpan.Zero,
                    "Application geo-probe skipped by benchmark options."),
                HttpStatusCode: null,
                IsGeoBlocked: false,
                CompanionPassed: null,
                GeoReason: null,
                TlsMitmOnCompanion: false);
        layers.Add(layer5.Result);

        // Layer 6: Root-Cause Classification & 1-Click Fix
        Layer6Outcome layer6 = ExecuteLayer6(
            normalizedDomain,
            upstream,
            layer1,
            layer2,
            layer3,
            layer4,
            layer5);
        layers.Add(layer6.Result);

        totalStopwatch.Stop();

        return new DiagnosticReport
        {
            TargetDomain = normalizedDomain,
            Upstream = upstream,
            StartedAtUtc = startedAtUtc,
            TotalDuration = totalStopwatch.Elapsed,
            Verdict = layer6.Verdict,
            Reason = layer6.Reason,
            Remediation = layer6.Remediation,
            Layers = layers,
            LatencyP50Ms = layer2.P50Ms,
            LatencyP95Ms = layer2.P95Ms,
            JitterMs = layer2.JitterMs,
            PacketLossPercent = layer2.PacketLossPercent,
            ResolvedAddresses = layer3.ResolvedAddresses,
            TlsHandshakeSucceeded = layer4.Succeeded,
            NegotiatedAlpn = layer4.NegotiatedAlpn,
            EchAdvertised = layer3.EchAdvertised,
            HttpStatusCode = layer5.HttpStatusCode,
            CompanionPassed = layer5.CompanionPassed,
            HostHealth = layer1.Snapshot
        };
    }

    private static Func<DnsProtocol, IDnsUpstreamClient> CreateSingleClientFactory(IDnsUpstreamClient upstreamClient)
    {
        ArgumentNullException.ThrowIfNull(upstreamClient);
        return _ => upstreamClient;
    }

    private async Task<Layer1Outcome> ExecuteLayer1Async(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        Stopwatch sw = Stopwatch.StartNew();
        if (_hostHealthProvider is null)
        {
            sw.Stop();
            return new Layer1Outcome(
                new DiagnosticLayerResult(
                    1,
                    "Host & Network Health",
                    DiagnosticLayerStatus.Skipped,
                    sw.Elapsed,
                    "Host network health provider not configured."),
                Snapshot: null,
                HasPort53Conflict: false,
                HasBrowserDohBypass: false);
        }

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            HostNetworkHealthSnapshot snapshot = await _hostHealthProvider.InspectAsync(timeoutCts.Token).ConfigureAwait(false);
            sw.Stop();

            bool port53Conflict = !string.IsNullOrWhiteSpace(snapshot.Port53OccupantName);
            bool browserBypass = snapshot.DetectedBrowserDohBypassBrowsers.Count > 0;
            bool noConnectivity = !snapshot.HasIpv4Connectivity && !snapshot.HasIpv6Connectivity;

            Dictionary<string, string> metrics = new(StringComparer.Ordinal)
            {
                ["ipv4"] = snapshot.HasIpv4Connectivity ? "true" : "false",
                ["ipv6"] = snapshot.HasIpv6Connectivity ? "true" : "false",
                ["captivePortal"] = snapshot.IsCaptivePortalDetected ? "true" : "false"
            };

            if (port53Conflict)
            {
                metrics["port53Occupant"] = snapshot.Port53OccupantName!;
            }

            if (browserBypass)
            {
                metrics["browserDohBypass"] = string.Join(", ", snapshot.DetectedBrowserDohBypassBrowsers);
            }

            DiagnosticLayerStatus status = port53Conflict || browserBypass || snapshot.IsCaptivePortalDetected || noConnectivity
                ? DiagnosticLayerStatus.Warning
                : DiagnosticLayerStatus.Passed;

            StringBuilder summary = new();
            if (port53Conflict)
            {
                summary.Append(CultureInfo.InvariantCulture, $"Port 53 occupied by {snapshot.Port53OccupantName}");
                if (snapshot.Port53OccupantProcessId is int pid)
                {
                    summary.Append(CultureInfo.InvariantCulture, $" (PID {pid})");
                }

                summary.Append(". ");
            }

            if (browserBypass)
            {
                summary.Append(CultureInfo.InvariantCulture, $"Browser DoH override active: {string.Join(", ", snapshot.DetectedBrowserDohBypassBrowsers)}. ");
            }

            if (snapshot.IsCaptivePortalDetected)
            {
                summary.Append("Captive portal detected. ");
            }

            if (summary.Length == 0)
            {
                summary.Append("Host networking posture is clean.");
            }

            return new Layer1Outcome(
                new DiagnosticLayerResult(1, "Host & Network Health", status, sw.Elapsed, summary.ToString().TrimEnd(), metrics),
                snapshot,
                port53Conflict,
                browserBypass);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException ex)
        {
            sw.Stop();
            return new Layer1Outcome(
                new DiagnosticLayerResult(1, "Host & Network Health", DiagnosticLayerStatus.Warning, sw.Elapsed, ex.Message),
                null,
                false,
                false);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new Layer1Outcome(
                new DiagnosticLayerResult(1, "Host & Network Health", DiagnosticLayerStatus.Warning, sw.Elapsed, "Host health inspection timed out."),
                null,
                false,
                false);
        }
    }

    private async Task<Layer2Outcome> ExecuteLayer2Async(
        string domain,
        DnsServerEntry upstream,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        Stopwatch layerSw = Stopwatch.StartNew();
        int sampleCount = Math.Clamp(options.TransportProbeSamples, 1, 16);
        IDnsUpstreamClient client = _clientFactory(upstream.Protocol);

        List<double> rttsMs = new(sampleCount);
        DnsMessage? sampleResponse = null;
        int failureCount = 0;
        bool sawTlsAuthFailure = false;
        bool sawTransportResetOrTimeout = false;
        string? lastError = null;

        for (int index = 0; index < sampleCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            ushort queryId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue + 1);
            DnsMessage query = DnsMessage.CreateQuery(queryId, domain, DnsRecordType.A);

            using CancellationTokenSource sampleCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sampleCts.CancelAfter(options.ProbeTimeout);

            Stopwatch sampleSw = Stopwatch.StartNew();
            try
            {
                UpstreamQueryResult queryResult = await client.QueryAsync(query, upstream, sampleCts.Token).ConfigureAwait(false);
                sampleSw.Stop();

                double rttMs = queryResult.Latency > TimeSpan.Zero
                    ? queryResult.Latency.TotalMilliseconds
                    : sampleSw.Elapsed.TotalMilliseconds;

                rttsMs.Add(Math.Max(0.01, rttMs));
                sampleResponse ??= queryResult.Response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (AuthenticationException ex)
            {
                sampleSw.Stop();
                failureCount++;
                sawTlsAuthFailure = true;
                lastError = ex.Message;
            }
            catch (SocketException ex)
            {
                sampleSw.Stop();
                failureCount++;
                sawTransportResetOrTimeout = true;
                lastError = ex.Message;
            }
            catch (HttpRequestException ex)
            {
                sampleSw.Stop();
                failureCount++;
                if (ex.InnerException is AuthenticationException)
                {
                    sawTlsAuthFailure = true;
                }
                else
                {
                    sawTransportResetOrTimeout = true;
                }

                lastError = ex.Message;
            }
            catch (IOException ex)
            {
                sampleSw.Stop();
                failureCount++;
                sawTransportResetOrTimeout = true;
                lastError = ex.Message;
            }
            catch (TimeoutException ex)
            {
                sampleSw.Stop();
                failureCount++;
                sawTransportResetOrTimeout = true;
                lastError = ex.Message;
            }
            catch (OperationCanceledException)
            {
                sampleSw.Stop();
                failureCount++;
                sawTransportResetOrTimeout = true;
                lastError = "Upstream DNS probe timed out.";
            }
        }

        layerSw.Stop();
        double packetLossPercent = (failureCount * 100.0) / sampleCount;

        if (rttsMs.Count == 0)
        {
            Dictionary<string, string> failMetrics = new(StringComparer.Ordinal)
            {
                ["samples"] = sampleCount.ToString(CultureInfo.InvariantCulture),
                ["packetLossPercent"] = packetLossPercent.ToString("F1", CultureInfo.InvariantCulture),
                ["protocol"] = upstream.Protocol.ToString()
            };

            return new Layer2Outcome(
                new DiagnosticLayerResult(
                    2,
                    "Transport Reachability & Latency",
                    DiagnosticLayerStatus.Failed,
                    layerSw.Elapsed,
                    lastError ?? "All upstream transport probe samples failed.",
                    failMetrics),
                SampleResponse: null,
                P50Ms: null,
                P95Ms: null,
                JitterMs: null,
                PacketLossPercent: packetLossPercent,
                SawTlsAuthFailure: sawTlsAuthFailure,
                SawTransportResetOrTimeout: sawTransportResetOrTimeout);
        }

        double p50 = ComputePercentile(rttsMs, 0.50);
        double p95 = ComputePercentile(rttsMs, 0.95);
        double jitter = ComputeJitter(rttsMs);

        Dictionary<string, string> metrics = new(StringComparer.Ordinal)
        {
            ["samples"] = sampleCount.ToString(CultureInfo.InvariantCulture),
            ["p50Ms"] = p50.ToString("F2", CultureInfo.InvariantCulture),
            ["p95Ms"] = p95.ToString("F2", CultureInfo.InvariantCulture),
            ["jitterMs"] = jitter.ToString("F2", CultureInfo.InvariantCulture),
            ["packetLossPercent"] = packetLossPercent.ToString("F1", CultureInfo.InvariantCulture)
        };

        DiagnosticLayerStatus status = failureCount > 0
            ? DiagnosticLayerStatus.Warning
            : DiagnosticLayerStatus.Passed;

        string summary = string.Create(
            CultureInfo.InvariantCulture,
            $"p50={p50:F1}ms, p95={p95:F1}ms, jitter={jitter:F1}ms, loss={packetLossPercent:F0}%");

        return new Layer2Outcome(
            new DiagnosticLayerResult(2, "Transport Reachability & Latency", status, layerSw.Elapsed, summary, metrics),
            sampleResponse,
            p50,
            p95,
            jitter,
            packetLossPercent,
            sawTlsAuthFailure,
            sawTransportResetOrTimeout);
    }

    private async Task<Layer3Outcome> ExecuteLayer3Async(
        string domain,
        DnsServerEntry upstream,
        DnsMessage? upstreamResponse,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        Stopwatch sw = Stopwatch.StartNew();

        if (upstreamResponse is null)
        {
            sw.Stop();
            return new Layer3Outcome(
                new DiagnosticLayerResult(
                    3,
                    "DNS Integrity & Poisoning Check",
                    DiagnosticLayerStatus.Skipped,
                    sw.Elapsed,
                    "Skipped because Layer 2 produced no DNS response."),
                ResolvedAddresses: [],
                BaselineAddresses: [],
                IsDnsPoisoned: false,
                DirectIpOnBypassUpstream: false,
                EchAdvertised: false);
        }

        List<IPAddress> upstreamIps = ExtractIpAddresses(upstreamResponse);
        List<IPAddress> baselineIps = [];
        DnsResponseCode? baselineRcode = null;
        bool echAdvertised = HasEchSvcParam(upstreamResponse);

        using CancellationTokenSource baselineCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        baselineCts.CancelAfter(options.ProbeTimeout);

        try
        {
            DnsMessage baselineResponse = await _bootstrapResolver.QueryBaselineAsync(domain, DnsRecordType.A, baselineCts.Token).ConfigureAwait(false);
            baselineRcode = baselineResponse.EffectiveResponseCode;
            baselineIps = ExtractIpAddresses(baselineResponse);
            if (!echAdvertised)
            {
                echAdvertised = HasEchSvcParam(baselineResponse);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            // Baseline query failed; continue with local bogon/sinkhole checks.
        }
        catch (HttpRequestException)
        {
        }
        catch (IOException)
        {
        }
        catch (TimeoutException)
        {
        }
        catch (OperationCanceledException)
        {
        }

        if (!echAdvertised && options.CheckEchViaBaseline)
        {
            using CancellationTokenSource httpsCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            httpsCts.CancelAfter(options.ProbeTimeout);

            try
            {
                DnsMessage httpsRecord = await _bootstrapResolver.QueryBaselineAsync(domain, DnsRecordType.HTTPS, httpsCts.Token).ConfigureAwait(false);
                echAdvertised = HasEchSvcParam(httpsRecord);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (SocketException)
            {
            }
            catch (HttpRequestException)
            {
            }
            catch (IOException)
            {
            }
            catch (TimeoutException)
            {
            }
            catch (OperationCanceledException)
            {
            }
        }

        bool allowCarrierException = IsNamedCarrierAnycastUpstream(upstream);
        DnsRebindingValidationResult validation = DnsRebindingValidator.ValidateAnswer(
            RouteZone.Zone4EncryptedTrusted,
            upstreamIps,
            allowCarrierAnycastExceptions: allowCarrierException,
            namedCarrierEndpointId: upstream.Id);

        bool hasBogonOrSinkhole = !validation.IsSafe;
        bool poisonedNxDomain = upstreamResponse.EffectiveResponseCode == DnsResponseCode.NxDomain
            && baselineRcode == DnsResponseCode.NoError
            && baselineIps.Count > 0;

        bool isDnsPoisoned = hasBogonOrSinkhole || poisonedNxDomain;

        bool directIpOnBypass = false;
        if (upstream.SupportsBypass && !isDnsPoisoned)
        {
            foreach (IPAddress ip in validation.AcceptedAddresses)
            {
                if (AntiDirectAndGeoSignatures.IsDirectServiceIp(ip, domain))
                {
                    directIpOnBypass = true;
                    break;
                }
            }
        }

        sw.Stop();

        Dictionary<string, string> metrics = new(StringComparer.Ordinal)
        {
            ["rcode"] = upstreamResponse.EffectiveResponseCode.ToString(),
            ["answerCount"] = upstreamIps.Count.ToString(CultureInfo.InvariantCulture),
            ["echAdvertised"] = echAdvertised ? "true" : "false",
            ["poisoned"] = isDnsPoisoned ? "true" : "false"
        };

        if (isDnsPoisoned)
        {
            string reason = hasBogonOrSinkhole
                ? "DNS response contains bogon/sinkhole IP address(es)."
                : "Upstream returned NXDOMAIN while encrypted baseline resolved valid public record(s).";

            return new Layer3Outcome(
                new DiagnosticLayerResult(3, "DNS Integrity & Poisoning Check", DiagnosticLayerStatus.Failed, sw.Elapsed, reason, metrics),
                validation.AcceptedAddresses,
                baselineIps,
                IsDnsPoisoned: true,
                DirectIpOnBypassUpstream: directIpOnBypass,
                EchAdvertised: echAdvertised);
        }

        DiagnosticLayerStatus status = directIpOnBypass ? DiagnosticLayerStatus.Warning : DiagnosticLayerStatus.Passed;
        string summary = directIpOnBypass
            ? "Valid public IP returned, but it matches direct unproxied CDN prefix on a bypass upstream."
            : string.Create(CultureInfo.InvariantCulture, $"Verified {validation.AcceptedAddresses.Count} public address(es); ECH={(echAdvertised ? "advertised" : "absent")}.");

        return new Layer3Outcome(
            new DiagnosticLayerResult(3, "DNS Integrity & Poisoning Check", status, sw.Elapsed, summary, metrics),
            validation.AcceptedAddresses,
            baselineIps,
            IsDnsPoisoned: false,
            DirectIpOnBypassUpstream: directIpOnBypass,
            EchAdvertised: echAdvertised);
    }

    private static async Task<Layer4Outcome> ExecuteLayer4Async(
        string domain,
        DnsServerEntry upstream,
        IReadOnlyList<IPAddress> resolvedAddresses,
        IReadOnlyList<IPAddress> baselineAddresses,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        Stopwatch sw = Stopwatch.StartNew();
        IPEndPoint? targetEndpoint = ResolveTlsEndpoint(upstream, resolvedAddresses, baselineAddresses, options);

        if (targetEndpoint is null)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Skipped,
                    sw.Elapsed,
                    "No routable target IP address available for TLS verification."),
                Endpoint: null,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: false,
                TcpConnectBlocked: false,
                NegotiatedAlpn: null);
        }

        using CancellationTokenSource tlsCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        tlsCts.CancelAfter(options.ProbeTimeout);

        using Socket socket = new(targetEndpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.NoDelay = true;

        try
        {
            await socket.ConnectAsync(targetEndpoint, tlsCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException ex)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    string.Create(CultureInfo.InvariantCulture, $"TCP connect failed: {ex.Message}")),
                targetEndpoint,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: false,
                TcpConnectBlocked: true,
                NegotiatedAlpn: null);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    "TCP connection to TLS endpoint timed out."),
                targetEndpoint,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: false,
                TcpConnectBlocked: true,
                NegotiatedAlpn: null);
        }

        using NetworkStream networkStream = new(socket, ownsSocket: false);
        using SslStream sslStream = new(networkStream, leaveInnerStreamOpen: true);

        SslClientAuthenticationOptions sslOptions = CreateSslClientAuthenticationOptions(domain, options);

        try
        {
            await sslStream.AuthenticateAsClientAsync(sslOptions, tlsCts.Token).ConfigureAwait(false);
            sw.Stop();

            string? alpn = sslStream.NegotiatedApplicationProtocol.Protocol.IsEmpty
                ? null
                : Encoding.ASCII.GetString(sslStream.NegotiatedApplicationProtocol.Protocol.Span);

            Dictionary<string, string> metrics = new(StringComparer.Ordinal)
            {
                ["tlsProtocol"] = sslStream.SslProtocol.ToString(),
                ["alpn"] = alpn ?? "none",
                ["targetHost"] = domain
            };

            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Passed,
                    sw.Elapsed,
                    string.Create(CultureInfo.InvariantCulture, $"TLS {sslStream.SslProtocol} verified for '{domain}' (ALPN={alpn ?? "none"})."),
                    metrics),
                targetEndpoint,
                Succeeded: true,
                TlsMitmRejected: false,
                TlsSniDpiReset: false,
                TcpConnectBlocked: false,
                NegotiatedAlpn: alpn);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AuthenticationException ex)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    string.Create(CultureInfo.InvariantCulture, $"X.509 certificate / SAN validation failed: {ex.Message}")),
                targetEndpoint,
                Succeeded: false,
                TlsMitmRejected: true,
                TlsSniDpiReset: false,
                TcpConnectBlocked: false,
                NegotiatedAlpn: null);
        }
        catch (IOException ex)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    string.Create(CultureInfo.InvariantCulture, $"TLS handshake reset/aborted (possible SNI DPI): {ex.Message}")),
                targetEndpoint,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: true,
                TcpConnectBlocked: false,
                NegotiatedAlpn: null);
        }
        catch (SocketException ex)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    string.Create(CultureInfo.InvariantCulture, $"TLS socket reset during handshake: {ex.Message}")),
                targetEndpoint,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: true,
                TcpConnectBlocked: false,
                NegotiatedAlpn: null);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new Layer4Outcome(
                new DiagnosticLayerResult(
                    4,
                    "TLS Handshake & Cryptographic Authenticity",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    "TLS handshake timed out (possible SNI DPI drop)."),
                targetEndpoint,
                Succeeded: false,
                TlsMitmRejected: false,
                TlsSniDpiReset: true,
                TcpConnectBlocked: false,
                NegotiatedAlpn: null);
        }
    }

    private async Task<Layer5Outcome> ExecuteLayer5Async(
        string domain,
        DnsServerEntry upstream,
        Layer4Outcome layer4,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        Stopwatch sw = Stopwatch.StartNew();
        if (!layer4.Succeeded || layer4.Endpoint is null)
        {
            sw.Stop();
            return new Layer5Outcome(
                new DiagnosticLayerResult(
                    5,
                    "Application & Companion API Geo-Probe",
                    DiagnosticLayerStatus.Skipped,
                    sw.Elapsed,
                    "Skipped because Layer 4 TLS verification did not succeed."),
                HttpStatusCode: null,
                IsGeoBlocked: false,
                CompanionPassed: null,
                GeoReason: null,
                TlsMitmOnCompanion: false);
        }

        string probePath = options.HttpProbePath ?? GetDefaultProbePath(domain);
        HttpProbeOutcome primaryProbe = await ProbeHttpsEndpointAsync(
            domain,
            probePath,
            layer4.Endpoint,
            options,
            cancellationToken).ConfigureAwait(false);

        if (primaryProbe.TlsMitmRejected)
        {
            sw.Stop();
            return new Layer5Outcome(
                new DiagnosticLayerResult(
                    5,
                    "Application & Companion API Geo-Probe",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    primaryProbe.Detail),
                primaryProbe.StatusCode,
                IsGeoBlocked: false,
                CompanionPassed: null,
                GeoReason: primaryProbe.Detail,
                TlsMitmOnCompanion: true);
        }

        bool isGeoBlocked = primaryProbe.IsGeoBlocked;
        string? geoReason = isGeoBlocked ? primaryProbe.Detail : null;

        bool? companionPassed = null;
        bool companionMitm = false;

        if (options.ProbeCompanionDomains)
        {
            IReadOnlyList<string> companions = AntiDirectAndGeoSignatures.GetCompanionDomains(domain);
            if (companions.Count > 0)
            {
                bool allCompanionsOk = true;
                foreach (string companion in companions)
                {
                    IPEndPoint? companionEndpoint = await ResolveCompanionEndpointAsync(
                        companion,
                        upstream,
                        options,
                        cancellationToken).ConfigureAwait(false);

                    if (companionEndpoint is null)
                    {
                        continue;
                    }

                    HttpProbeOutcome compProbe = await ProbeHttpsEndpointAsync(
                        companion,
                        "/",
                        companionEndpoint,
                        options,
                        cancellationToken).ConfigureAwait(false);

                    if (compProbe.TlsMitmRejected)
                    {
                        allCompanionsOk = false;
                        companionMitm = true;
                        geoReason = string.Create(CultureInfo.InvariantCulture, $"Companion '{companion}' failed TLS verification: {compProbe.Detail}");
                        break;
                    }

                    if (compProbe.IsGeoBlocked || compProbe.IsGatewayFailure)
                    {
                        allCompanionsOk = false;
                        if (compProbe.IsGeoBlocked)
                        {
                            isGeoBlocked = true;
                            geoReason ??= string.Create(CultureInfo.InvariantCulture, $"Companion '{companion}' geo-blocked: {compProbe.Detail}");
                        }
                    }
                }

                companionPassed = allCompanionsOk;
            }
        }

        sw.Stop();

        Dictionary<string, string> metrics = new(StringComparer.Ordinal)
        {
            ["path"] = probePath,
            ["geoBlocked"] = isGeoBlocked ? "true" : "false"
        };

        if (primaryProbe.StatusCode is int code)
        {
            metrics["httpStatus"] = code.ToString(CultureInfo.InvariantCulture);
        }

        if (companionPassed is bool comp)
        {
            metrics["companionPassed"] = comp ? "true" : "false";
        }

        if (companionMitm)
        {
            return new Layer5Outcome(
                new DiagnosticLayerResult(
                    5,
                    "Application & Companion API Geo-Probe",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    geoReason ?? "Companion domain failed X.509 certificate validation.",
                    metrics),
                primaryProbe.StatusCode,
                isGeoBlocked,
                companionPassed,
                geoReason,
                TlsMitmOnCompanion: true);
        }

        if (isGeoBlocked)
        {
            return new Layer5Outcome(
                new DiagnosticLayerResult(
                    5,
                    "Application & Companion API Geo-Probe",
                    DiagnosticLayerStatus.Failed,
                    sw.Elapsed,
                    geoReason ?? "Regional geo-block signature detected.",
                    metrics),
                primaryProbe.StatusCode,
                IsGeoBlocked: true,
                companionPassed,
                geoReason,
                TlsMitmOnCompanion: false);
        }

        DiagnosticLayerStatus status = primaryProbe.IsGatewayFailure || primaryProbe.IsTransportFailure || companionPassed == false
            ? DiagnosticLayerStatus.Warning
            : DiagnosticLayerStatus.Passed;

        return new Layer5Outcome(
            new DiagnosticLayerResult(
                5,
                "Application & Companion API Geo-Probe",
                status,
                sw.Elapsed,
                primaryProbe.Detail,
                metrics),
            primaryProbe.StatusCode,
            IsGeoBlocked: false,
            companionPassed,
            GeoReason: null,
            TlsMitmOnCompanion: false);
    }

    private static Layer6Outcome ExecuteLayer6(
        string domain,
        DnsServerEntry upstream,
        Layer1Outcome layer1,
        Layer2Outcome layer2,
        Layer3Outcome layer3,
        Layer4Outcome layer4,
        Layer5Outcome layer5)
    {
        Stopwatch sw = Stopwatch.StartNew();

        DiagnosticVerdict verdict;
        string reason;
        RecommendedRemediation remediation;

        if (layer3.IsDnsPoisoned)
        {
            verdict = DiagnosticVerdict.DnsPoisoned;
            reason = layer3.Result.Summary;
            remediation = new RecommendedRemediation(
                RemediationActionKind.SwitchToDoQOrFragmentedDoh,
                "Switch to Encrypted DoQ or Fragmented DoH",
                "DNS response was poisoned or sinkholed. Route queries through an encrypted DoQ/DoH resolver.",
                domain);
        }
        else if (layer4.TlsMitmRejected || layer2.SawTlsAuthFailure || layer5.TlsMitmOnCompanion)
        {
            verdict = DiagnosticVerdict.TlsMitmRejected;
            reason = layer4.TlsMitmRejected
                ? layer4.Result.Summary
                : (layer5.TlsMitmOnCompanion ? (layer5.GeoReason ?? "Companion TLS MITM rejected.") : "Upstream TLS certificate validation failed.");
            remediation = new RecommendedRemediation(
                RemediationActionKind.DeploySelfHostedVps,
                "Deploy Private Authenticated VPS Tunnel",
                "TLS MITM or untrusted certificate interception detected. Do not bypass certificate checks; route via an authenticated private endpoint.",
                domain);
        }
        else if (layer1.HasPort53Conflict)
        {
            verdict = DiagnosticVerdict.LocalPort53Conflict;
            reason = layer1.Result.Summary;
            remediation = new RecommendedRemediation(
                RemediationActionKind.FixLocalPort53Conflict,
                "Resolve Local Port 53 Conflict",
                "Another service is occupying UDP/TCP port 53 on this host. Stop or reconfigure the conflicting listener.",
                domain);
        }
        else if (layer2.P50Ms is null)
        {
            if (upstream.IsEncrypted && (layer2.SawTransportResetOrTimeout || layer2.SawTlsAuthFailure))
            {
                verdict = DiagnosticVerdict.EncryptedDnsDpiBlocked;
                reason = layer2.Result.Summary;
                remediation = new RecommendedRemediation(
                    RemediationActionKind.SwitchToDoQOrFragmentedDoh,
                    "Switch to DoQ or TLS-Fragmented DoH",
                    "Encrypted DNS upstream is blocked or reset in transit. Try DoQ (QUIC) or TLS ClientHello fragmentation.",
                    domain);
            }
            else
            {
                verdict = DiagnosticVerdict.IpBlockedByIsp;
                reason = layer2.Result.Summary;
                remediation = new RecommendedRemediation(
                    RemediationActionKind.DeploySelfHostedVps,
                    "Deploy Self-Hosted VPS Relay",
                    "Upstream resolver IP appears unreachable or blocked by ISP.",
                    domain);
            }
        }
        else if (layer4.TlsSniDpiReset)
        {
            verdict = DiagnosticVerdict.TlsSniDpiReset;
            reason = layer4.Result.Summary;
            remediation = new RecommendedRemediation(
                RemediationActionKind.EnableTlsSplitPacForDomain,
                "Enable TLS Fragmentation / Split PAC",
                "TCP connection was reset during TLS ClientHello, indicating SNI-based DPI filtering.",
                domain);
        }
        else if (layer4.TcpConnectBlocked)
        {
            verdict = DiagnosticVerdict.IpBlockedByIsp;
            reason = layer4.Result.Summary;
            remediation = new RecommendedRemediation(
                RemediationActionKind.DeploySelfHostedVps,
                "Deploy Self-Hosted VPS Relay",
                "TCP connection to resolved destination IP was blocked or timed out.",
                domain);
        }
        else if (layer5.IsGeoBlocked)
        {
            verdict = DiagnosticVerdict.GeoBlockedByService;
            reason = layer5.GeoReason ?? "Service or companion API returned a regional geo-block response.";
            remediation = new RecommendedRemediation(
                RemediationActionKind.RouteViaVerifiedGeoUnlock,
                "Route via Verified Geo-Unlock Resolver",
                "Target service is geo-restricted on this path. Route this domain through a Tier 2 verified Geo-Unlock resolver.",
                domain);
        }
        else if (layer1.HasBrowserDohBypass)
        {
            verdict = DiagnosticVerdict.BrowserDohBypass;
            reason = layer1.Result.Summary;
            remediation = new RecommendedRemediation(
                RemediationActionKind.DisableBrowserDohOverride,
                "Disable Browser Built-in DoH Override",
                "Browser Secure DNS is bypassing the local split-DNS pipeline.",
                domain);
        }
        else
        {
            verdict = DiagnosticVerdict.Healthy;
            reason = string.Create(
                CultureInfo.InvariantCulture,
                $"All layers healthy for '{domain}' via {upstream.Name} (p50={layer2.P50Ms:F1}ms, HTTP={layer5.HttpStatusCode?.ToString(CultureInfo.InvariantCulture) ?? "N/A"}).");
            remediation = new RecommendedRemediation(
                RemediationActionKind.None,
                "No Action Required",
                "Connection, DNS integrity, X.509 authenticity, and application access are healthy.",
                domain);
        }

        sw.Stop();

        Dictionary<string, string> metrics = new(StringComparer.Ordinal)
        {
            ["verdict"] = verdict.ToString(),
            ["remediation"] = remediation.Action.ToString()
        };

        DiagnosticLayerStatus status = verdict == DiagnosticVerdict.Healthy
            ? DiagnosticLayerStatus.Passed
            : DiagnosticLayerStatus.Failed;

        return new Layer6Outcome(
            new DiagnosticLayerResult(6, "Root-Cause Classification & Fix", status, sw.Elapsed, reason, metrics),
            verdict,
            reason,
            remediation);
    }

    private static async Task<HttpProbeOutcome> ProbeHttpsEndpointAsync(
        string host,
        string path,
        IPEndPoint connectEndpoint,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.ProbeTimeout);

        using SocketsHttpHandler handler = CreateSocketsHttpHandler(host, connectEndpoint, options);
        using HttpClient client = new(handler, disposeHandler: false);
        client.Timeout = Timeout.InfiniteTimeSpan;

        string normalizedPath = path.StartsWith('/') ? path : string.Concat("/", path);
        Uri uri = new(string.Create(CultureInfo.InvariantCulture, $"https://{host}{normalizedPath}"), UriKind.Absolute);

        using HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("DnsPulse", "2.0"));

        try
        {
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            int statusCode = (int)response.StatusCode;

            string? location = response.Headers.Location?.ToString();
            if (location is null && response.Headers.TryGetValues("Location", out IEnumerable<string>? rawLocations))
            {
                location = string.Join(" ", rawLocations);
            }

            if (AntiDirectAndGeoSignatures.IsGeoBlockedRedirect(statusCode, location))
            {
                return new HttpProbeOutcome(
                    statusCode,
                    IsGeoBlocked: true,
                    IsGatewayFailure: false,
                    IsTransportFailure: false,
                    TlsMitmRejected: false,
                    Detail: string.Create(CultureInfo.InvariantCulture, $"Geo-block HTTP {statusCode} / Location '{location ?? "(none)"}' detected."));
            }

            foreach (KeyValuePair<string, IEnumerable<string>> header in response.Headers)
            {
                foreach (string val in header.Value)
                {
                    if (AntiDirectAndGeoSignatures.IsGeoBlockedResponseHeader(header.Key, val))
                    {
                        return new HttpProbeOutcome(
                            statusCode,
                            IsGeoBlocked: true,
                            IsGatewayFailure: false,
                            IsTransportFailure: false,
                            TlsMitmRejected: false,
                            Detail: string.Create(CultureInfo.InvariantCulture, $"Geo-block header '{header.Key}: {val}' detected."));
                    }
                }
            }

            string bodySnippet = await ReadBodySnippetAsync(response.Content, cts.Token).ConfigureAwait(false);
            if (AntiDirectAndGeoSignatures.IsGeoBlockedBody(bodySnippet))
            {
                return new HttpProbeOutcome(
                    statusCode,
                    IsGeoBlocked: true,
                    IsGatewayFailure: false,
                    IsTransportFailure: false,
                    TlsMitmRejected: false,
                    Detail: string.Create(CultureInfo.InvariantCulture, $"Geo-block body marker detected (HTTP {statusCode})."));
            }

            if (AntiDirectAndGeoSignatures.IsGatewayFailureStatusCode(statusCode))
            {
                return new HttpProbeOutcome(
                    statusCode,
                    IsGeoBlocked: false,
                    IsGatewayFailure: true,
                    IsTransportFailure: false,
                    TlsMitmRejected: false,
                    Detail: string.Create(CultureInfo.InvariantCulture, $"Upstream gateway failure HTTP {statusCode}."));
            }

            return new HttpProbeOutcome(
                statusCode,
                IsGeoBlocked: false,
                IsGatewayFailure: false,
                IsTransportFailure: false,
                TlsMitmRejected: false,
                Detail: string.Create(CultureInfo.InvariantCulture, $"HTTPS probe returned HTTP {statusCode}."));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException)
        {
            return new HttpProbeOutcome(null, false, false, true, true, ex.InnerException.Message);
        }
        catch (HttpRequestException ex)
        {
            return new HttpProbeOutcome(null, false, false, true, false, ex.Message);
        }
        catch (AuthenticationException ex)
        {
            return new HttpProbeOutcome(null, false, false, true, true, ex.Message);
        }
        catch (IOException ex)
        {
            return new HttpProbeOutcome(null, false, false, true, false, ex.Message);
        }
        catch (SocketException ex)
        {
            return new HttpProbeOutcome(null, false, false, true, false, ex.Message);
        }
        catch (OperationCanceledException)
        {
            return new HttpProbeOutcome(null, false, false, true, false, "HTTPS geo-probe timed out.");
        }
    }

    private async Task<IPEndPoint?> ResolveCompanionEndpointAsync(
        string companionDomain,
        DnsServerEntry upstream,
        DiagnosticProbeOptions options,
        CancellationToken cancellationToken)
    {
        if (options.CompanionEndpointOverrides is not null &&
            options.CompanionEndpointOverrides.TryGetValue(companionDomain, out IPEndPoint? overridden))
        {
            return overridden;
        }

        IDnsUpstreamClient client = _clientFactory(upstream.Protocol);
        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.ProbeTimeout);

        try
        {
            ushort id = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue + 1);
            DnsMessage query = DnsMessage.CreateQuery(id, companionDomain, DnsRecordType.A);
            UpstreamQueryResult result = await client.QueryAsync(query, upstream, cts.Token).ConfigureAwait(false);
            List<IPAddress> ips = ExtractIpAddresses(result.Response);
            foreach (IPAddress ip in ips)
            {
                if (IpSafetyInspector.IsPublicRoutable(ip))
                {
                    return new IPEndPoint(ip, options.HttpsPort);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
        }
        catch (HttpRequestException)
        {
        }
        catch (IOException)
        {
        }
        catch (TimeoutException)
        {
        }
        catch (OperationCanceledException)
        {
        }

        return null;
    }

    private static SocketsHttpHandler CreateSocketsHttpHandler(
        string targetHost,
        IPEndPoint connectEndpoint,
        DiagnosticProbeOptions options)
    {
        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.Zero,
            MaxConnectionsPerServer = 2,
            SslOptions = CreateSslClientAuthenticationOptions(targetHost, options),
            ConnectCallback = async (_, ct) =>
            {
                Socket socket = new(connectEndpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };

                try
                {
                    await socket.ConnectAsync(connectEndpoint, ct).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };

        return handler;
    }

    private static SslClientAuthenticationOptions CreateSslClientAuthenticationOptions(
        string targetHost,
        DiagnosticProbeOptions options)
    {
        SslClientAuthenticationOptions sslOptions = new()
        {
            TargetHost = targetHost,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
        };

        if (options.AdditionalTrustedRoots is { Count: > 0 } roots)
        {
            sslOptions.RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                ValidateCertificateWithCustomRoots(certificate, sslPolicyErrors, roots);
        }

        return sslOptions;
    }

    internal static bool ValidateCertificateWithCustomRoots(
        X509Certificate? certificate,
        SslPolicyErrors sslPolicyErrors,
        IReadOnlyList<X509Certificate2> additionalRoots)
    {
        if (certificate is null)
        {
            return false;
        }

        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0 ||
            (sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            return false;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        if (additionalRoots.Count == 0)
        {
            return false;
        }

        X509Certificate2? loaded = null;
        X509Certificate2? cert2 = certificate as X509Certificate2;
        if (cert2 is null)
        {
            loaded = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
            cert2 = loaded;
        }

        try
        {
            using X509Chain chain = new();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            foreach (X509Certificate2 root in additionalRoots)
            {
                chain.ChainPolicy.CustomTrustStore.Add(root);
            }

            return chain.Build(cert2);
        }
        finally
        {
            loaded?.Dispose();
        }
    }

    private static async Task<string> ReadBodySnippetAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        byte[] buffer = new byte[MaxBodyInspectBytes];
        int totalRead = 0;

        while (totalRead < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            totalRead += bytesRead;
        }

        return totalRead == 0 ? string.Empty : Encoding.UTF8.GetString(buffer, 0, totalRead);
    }

    private static IPEndPoint? ResolveTlsEndpoint(
        DnsServerEntry upstream,
        IReadOnlyList<IPAddress> resolvedAddresses,
        IReadOnlyList<IPAddress> baselineAddresses,
        DiagnosticProbeOptions options)
    {
        if (options.OverrideTlsEndpoint is not null)
        {
            return options.OverrideTlsEndpoint;
        }

        if (upstream.Protocol == DnsProtocol.SniProxy)
        {
            string? sniText = !string.IsNullOrWhiteSpace(upstream.SmartProxyIp)
                ? upstream.SmartProxyIp
                : upstream.PrimaryIp;
            if (IPAddress.TryParse(sniText, out IPAddress? sniIp))
            {
                return new IPEndPoint(sniIp, options.HttpsPort);
            }
        }

        if (resolvedAddresses.Count > 0)
        {
            return new IPEndPoint(resolvedAddresses[0], options.HttpsPort);
        }

        if (baselineAddresses.Count > 0)
        {
            return new IPEndPoint(baselineAddresses[0], options.HttpsPort);
        }

        return null;
    }

    private static List<IPAddress> ExtractIpAddresses(DnsMessage message)
    {
        List<IPAddress> addresses = [];
        foreach (DnsResourceRecord record in message.Answers)
        {
            if ((record.RecordType == DnsRecordType.A || record.RecordType == DnsRecordType.AAAA) &&
                record.Address is not null)
            {
                addresses.Add(record.Address);
            }
        }

        return addresses;
    }

    private static bool HasEchSvcParam(DnsMessage message)
    {
        foreach (DnsResourceRecord record in message.Answers)
        {
            if (HasEchParam(record))
            {
                return true;
            }
        }

        foreach (DnsResourceRecord record in message.Additionals)
        {
            if (HasEchParam(record))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasEchParam(DnsResourceRecord record)
    {
        if (record.RecordType is not (DnsRecordType.HTTPS or DnsRecordType.SVCB))
        {
            return false;
        }

        foreach (SvcParam param in record.SvcParams)
        {
            if (param.KnownKey == SvcParamKey.Ech && !param.Value.IsEmpty)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsNamedCarrierAnycastUpstream(DnsServerEntry upstream)
    {
        foreach (CarrierAnycastEndpoint endpoint in DnsRebindingValidator.BuiltinCarrierAnycastEndpoints)
        {
            if (upstream.Id.Contains(endpoint.EndpointId, StringComparison.OrdinalIgnoreCase) ||
                upstream.Name.Contains(endpoint.EndpointId, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(upstream.DohUrl) &&
                 upstream.DohUrl.Contains(endpoint.EndpointId, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetDefaultProbePath(string domain)
    {
        if (domain.Equals("aistudio.google.com", StringComparison.OrdinalIgnoreCase))
        {
            return "/welcome";
        }

        if (domain.Equals("gemini.google.com", StringComparison.OrdinalIgnoreCase))
        {
            return "/app";
        }

        return "/";
    }

    internal static double ComputePercentile(IReadOnlyList<double> values, double percentile)
    {
        if (values.Count == 0)
        {
            return 0;
        }

        double[] sorted = [.. values];
        Array.Sort(sorted);

        if (sorted.Length == 1)
        {
            return sorted[0];
        }

        double index = percentile * (sorted.Length - 1);
        int lower = (int)Math.Floor(index);
        int upper = (int)Math.Ceiling(index);
        if (lower == upper)
        {
            return sorted[lower];
        }

        double weight = index - lower;
        return sorted[lower] + (sorted[upper] - sorted[lower]) * weight;
    }

    internal static double ComputeJitter(IReadOnlyList<double> values)
    {
        if (values.Count < 2)
        {
            return 0;
        }

        double sumDiff = 0;
        for (int i = 1; i < values.Count; i++)
        {
            sumDiff += Math.Abs(values[i] - values[i - 1]);
        }

        return sumDiff / (values.Count - 1);
    }

    private sealed record Layer1Outcome(
        DiagnosticLayerResult Result,
        HostNetworkHealthSnapshot? Snapshot,
        bool HasPort53Conflict,
        bool HasBrowserDohBypass);

    private sealed record Layer2Outcome(
        DiagnosticLayerResult Result,
        DnsMessage? SampleResponse,
        double? P50Ms,
        double? P95Ms,
        double? JitterMs,
        double PacketLossPercent,
        bool SawTlsAuthFailure,
        bool SawTransportResetOrTimeout);

    private sealed record Layer3Outcome(
        DiagnosticLayerResult Result,
        IReadOnlyList<IPAddress> ResolvedAddresses,
        IReadOnlyList<IPAddress> BaselineAddresses,
        bool IsDnsPoisoned,
        bool DirectIpOnBypassUpstream,
        bool EchAdvertised);

    private sealed record Layer4Outcome(
        DiagnosticLayerResult Result,
        IPEndPoint? Endpoint,
        bool Succeeded,
        bool TlsMitmRejected,
        bool TlsSniDpiReset,
        bool TcpConnectBlocked,
        string? NegotiatedAlpn);

    private sealed record Layer5Outcome(
        DiagnosticLayerResult Result,
        int? HttpStatusCode,
        bool IsGeoBlocked,
        bool? CompanionPassed,
        string? GeoReason,
        bool TlsMitmOnCompanion);

    private sealed record Layer6Outcome(
        DiagnosticLayerResult Result,
        DiagnosticVerdict Verdict,
        string Reason,
        RecommendedRemediation Remediation);

    private sealed record HttpProbeOutcome(
        int? StatusCode,
        bool IsGeoBlocked,
        bool IsGatewayFailure,
        bool IsTransportFailure,
        bool TlsMitmRejected,
        string Detail);
}
