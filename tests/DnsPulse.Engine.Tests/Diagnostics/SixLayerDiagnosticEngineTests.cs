using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Diagnostics;

public sealed class SixLayerDiagnosticEngineTests
{
    private static readonly IPAddress PublicExampleIp = IPAddress.Parse("93.184.216.34");

    [Fact]
    public async Task DiagnoseAsync_HealthyTls200_ReturnsHealthyAndNoneRemediation()
    {
        using TestPkiBundle pki = CreateTestPki("example.com");
        await using MockTlsHttpServer server = new(
            pki.LeafServerCert,
            _ => new MockHttpResponse(200, "<html><body>Healthy OK</body></html>"));

        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("example.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(PublicExampleIp, DnsResponseCode.NoError);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 3,
            OverrideTlsEndpoint = server.Endpoint,
            AdditionalTrustedRoots = [pki.RootPublicCert],
            ProbeCompanionDomains = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("example.com", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.Healthy);
        report.Remediation.Action.Should().Be(RemediationActionKind.None);
        report.Layers.Should().HaveCount(6);
        report.TlsHandshakeSucceeded.Should().BeTrue();
        report.HttpStatusCode.Should().Be(200);
        report.PacketLossPercent.Should().Be(0);
        report.LatencyP50Ms.Should().BeGreaterThan(0);
        report.LatencyP95Ms.Should().BeGreaterThanOrEqualTo(report.LatencyP50Ms!.Value);
        report.ResolvedAddresses.Should().ContainSingle().Which.Should().Be(PublicExampleIp);
    }

    [Fact]
    public async Task DiagnoseAsync_UntrustedSelfSignedMitmCert_FailsClosedWithTlsMitmRejected()
    {
        using TestPkiBundle trustedPki = CreateTestPki("example.com");
        using TestPkiBundle mitmPki = CreateTestPki("example.com");

        await using MockTlsHttpServer mitmServer = new(
            mitmPki.LeafServerCert,
            _ => new MockHttpResponse(200, "<html>MITM Intercepted</html>"));

        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("example.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(PublicExampleIp, DnsResponseCode.NoError);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 2,
            OverrideTlsEndpoint = mitmServer.Endpoint,
            AdditionalTrustedRoots = [trustedPki.RootPublicCert],
            ProbeCompanionDomains = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("example.com", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.TlsMitmRejected);
        report.TlsHandshakeSucceeded.Should().BeFalse();
        report.HttpStatusCode.Should().BeNull();
        report.Layers[3].Status.Should().Be(DiagnosticLayerStatus.Failed);
        report.Layers[4].Status.Should().Be(DiagnosticLayerStatus.Skipped);
    }

    [Fact]
    public async Task DiagnoseAsync_SanHostnameMismatchCert_FailsClosedWithTlsMitmRejected()
    {
        using TestPkiBundle pki = CreateTestPki("wrong-host.example");

        await using MockTlsHttpServer server = new(
            pki.LeafServerCert,
            _ => new MockHttpResponse(200, "<html>Wrong Host</html>"));

        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("example.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(PublicExampleIp, DnsResponseCode.NoError);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 1,
            OverrideTlsEndpoint = server.Endpoint,
            AdditionalTrustedRoots = [pki.RootPublicCert],
            ProbeCompanionDomains = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("example.com", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.TlsMitmRejected);
        report.TlsHandshakeSucceeded.Should().BeFalse();
    }

    [Fact]
    public async Task DiagnoseAsync_GeoBlocked403AndAvailableRegionsRedirect_ReturnsGeoBlockedByService()
    {
        using TestPkiBundle pki = CreateTestPki("aistudio.google.com");

        await using MockTlsHttpServer server403 = new(
            pki.LeafServerCert,
            _ => new MockHttpResponse(
                403,
                "<html>Service not available in your region</html>",
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Location"] = "https://ai.google.dev/available-regions"
                }));

        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("aistudio.google.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(PublicExampleIp, DnsResponseCode.NoError);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 2,
            OverrideTlsEndpoint = server403.Endpoint,
            AdditionalTrustedRoots = [pki.RootPublicCert],
            ProbeCompanionDomains = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("aistudio.google.com", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.GeoBlockedByService);
        report.Remediation.Action.Should().Be(RemediationActionKind.RouteViaVerifiedGeoUnlock);
        report.HttpStatusCode.Should().Be(403);
        report.Layers[4].Status.Should().Be(DiagnosticLayerStatus.Failed);
    }

    [Fact]
    public async Task DiagnoseAsync_CompanionApiGeoBlocked_ReturnsGeoBlockedByService()
    {
        using TestPkiBundle targetPki = CreateTestPki("claude.ai");
        using TestPkiBundle companionPki = CreateTestPki("api.anthropic.com");

        await using MockTlsHttpServer targetServer = new(
            targetPki.LeafServerCert,
            _ => new MockHttpResponse(200, "<html>Claude Shell</html>"));
        await using MockTlsHttpServer companionServer = new(
            companionPki.LeafServerCert,
            _ => new MockHttpResponse(
                302,
                string.Empty,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Location"] = "https://www.anthropic.com/available-regions"
                }));

        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("claude.ai", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(PublicExampleIp, DnsResponseCode.NoError);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 1,
            OverrideTlsEndpoint = targetServer.Endpoint,
            CompanionEndpointOverrides = new Dictionary<string, IPEndPoint>(StringComparer.OrdinalIgnoreCase)
            {
                ["api.anthropic.com"] = companionServer.Endpoint
            },
            AdditionalTrustedRoots = [targetPki.RootPublicCert, companionPki.RootPublicCert],
            ProbeCompanionDomains = true,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("claude.ai", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.GeoBlockedByService);
        report.CompanionPassed.Should().BeFalse();
    }

    [Fact]
    public async Task DiagnoseAsync_PoisonedBogonAnswer_ReturnsDnsPoisoned()
    {
        IPAddress bogonIp = IPAddress.Parse("127.0.0.1");
        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("example.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(bogonIp, DnsResponseCode.NoError);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 2,
            IncludeTlsAndApplicationProbes = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("example.com", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.DnsPoisoned);
        report.Remediation.Action.Should().Be(RemediationActionKind.SwitchToDoQOrFragmentedDoh);
        report.Layers[2].Status.Should().Be(DiagnosticLayerStatus.Failed);
    }

    [Fact]
    public async Task DiagnoseAsync_PoisonedNxDomainAgainstValidBaseline_ReturnsDnsPoisoned()
    {
        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("example.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(null, DnsResponseCode.NxDomain);

        SixLayerDiagnosticEngine engine = new(bootstrap, client);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 1,
            IncludeTlsAndApplicationProbes = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport report = await engine.DiagnoseAsync("example.com", upstream, options);

        report.Verdict.Should().Be(DiagnosticVerdict.DnsPoisoned);
        report.Layers[2].Status.Should().Be(DiagnosticLayerStatus.Failed);
    }

    [Fact]
    public async Task DiagnoseAsync_Port53ConflictAndBrowserDohBypass_ClassifyAccurately()
    {
        using TestPkiBundle pki = CreateTestPki("example.com");
        await using MockTlsHttpServer server = new(
            pki.LeafServerCert,
            _ => new MockHttpResponse(200, "<html>OK</html>"));

        DnsServerEntry upstream = CreateTestUpstream();
        IBootstrapResolver bootstrap = CreateMockBootstrap("example.com", PublicExampleIp);
        IDnsUpstreamClient client = CreateMockUpstreamClient(PublicExampleIp, DnsResponseCode.NoError);

        IHostNetworkHealthProvider port53Health = Substitute.For<IHostNetworkHealthProvider>();
        port53Health.InspectAsync(Arg.Any<CancellationToken>()).Returns(new HostNetworkHealthSnapshot
        {
            HasIpv4Connectivity = true,
            Port53OccupantName = "dnscrypt-proxy",
            Port53OccupantProcessId = 4321
        });

        SixLayerDiagnosticEngine port53Engine = new(bootstrap, client, port53Health);
        DiagnosticProbeOptions options = new()
        {
            TransportProbeSamples = 1,
            OverrideTlsEndpoint = server.Endpoint,
            AdditionalTrustedRoots = [pki.RootPublicCert],
            ProbeCompanionDomains = false,
            CheckEchViaBaseline = false
        };

        DiagnosticReport port53Report = await port53Engine.DiagnoseAsync("example.com", upstream, options);
        port53Report.Verdict.Should().Be(DiagnosticVerdict.LocalPort53Conflict);
        port53Report.Remediation.Action.Should().Be(RemediationActionKind.FixLocalPort53Conflict);

        IHostNetworkHealthProvider browserHealth = Substitute.For<IHostNetworkHealthProvider>();
        browserHealth.InspectAsync(Arg.Any<CancellationToken>()).Returns(new HostNetworkHealthSnapshot
        {
            HasIpv4Connectivity = true,
            DetectedBrowserDohBypassBrowsers = ["Microsoft Edge"]
        });

        SixLayerDiagnosticEngine browserEngine = new(bootstrap, client, browserHealth);
        DiagnosticReport browserReport = await browserEngine.DiagnoseAsync("example.com", upstream, options);
        browserReport.Verdict.Should().Be(DiagnosticVerdict.BrowserDohBypass);
        browserReport.Remediation.Action.Should().Be(RemediationActionKind.DisableBrowserDohOverride);
    }

    private static DnsServerEntry CreateTestUpstream()
    {
        return new DnsServerEntry
        {
            Id = "test_doh",
            Name = "Test DoH",
            Provider = "Test",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            PrimaryIp = "1.1.1.1",
            DohUrl = "https://cloudflare-dns.com/dns-query"
        };
    }

    private static IBootstrapResolver CreateMockBootstrap(string domain, IPAddress ip)
    {
        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        bootstrap.ResolveHostAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([ip]);
        bootstrap.QueryBaselineAsync(Arg.Any<string>(), Arg.Any<DnsRecordType>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                string reqDomain = callInfo.ArgAt<string>(0);
                DnsRecordType qType = callInfo.ArgAt<DnsRecordType>(1);
                List<DnsResourceRecord> answers = qType == DnsRecordType.A
                    ? [DnsResourceRecord.CreateA(reqDomain, ip)]
                    : [];

                return new DnsMessage
                {
                    Header = new DnsHeader
                    {
                        Id = 100,
                        IsResponse = true,
                        ResponseCode = DnsResponseCode.NoError,
                        QuestionCount = 1,
                        AnswerCount = (ushort)answers.Count
                    },
                    Questions = [DnsQuestion.Create(reqDomain, qType)],
                    Answers = answers
                };
            });

        return bootstrap;
    }

    private static IDnsUpstreamClient CreateMockUpstreamClient(IPAddress? answerIp, DnsResponseCode rcode)
    {
        IDnsUpstreamClient client = Substitute.For<IDnsUpstreamClient>();
        client.Protocol.Returns(DnsProtocol.DoH);
        client.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage query = callInfo.ArgAt<DnsMessage>(0);
                string qName = query.Questions.Count > 0 ? query.Questions[0].Name : "example.com";
                List<DnsResourceRecord> answers = answerIp is not null
                    ? [DnsResourceRecord.CreateA(qName, answerIp)]
                    : [];

                DnsMessage response = new()
                {
                    Header = new DnsHeader
                    {
                        Id = query.Header.Id,
                        IsResponse = true,
                        ResponseCode = rcode,
                        QuestionCount = 1,
                        AnswerCount = (ushort)answers.Count
                    },
                    Questions = query.Questions,
                    Answers = answers
                };

                return new UpstreamQueryResult(response, TimeSpan.FromMilliseconds(12), "mock://upstream", DnsProtocol.DoH);
            });

        return client;
    }

    private static TestPkiBundle CreateTestPki(string leafSanDnsName)
    {
        using RSA rootRsa = RSA.Create(2048);
        CertificateRequest rootReq = new(
            "CN=DnsPulse Test Root CA",
            rootRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 rootCert = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

        using RSA leafRsa = RSA.Create(2048);
        CertificateRequest leafReq = new(
            $"CN={leafSanDnsName}",
            leafRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName(leafSanDnsName);
        leafReq.CertificateExtensions.Add(sanBuilder.Build());

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using X509Certificate2 leafSigned = leafReq.Create(rootCert, now.AddHours(-1), now.AddDays(7), serial);
        using X509Certificate2 leafWithKey = leafSigned.CopyWithPrivateKey(leafRsa);
        byte[] pfxBytes = leafWithKey.Export(X509ContentType.Pfx);

        X509Certificate2 serverCert = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            ReadOnlySpan<char>.Empty,
            X509KeyStorageFlags.Exportable);
        X509Certificate2 rootPublic = X509CertificateLoader.LoadCertificate(rootCert.RawData);

        return new TestPkiBundle(rootPublic, serverCert);
    }

    private sealed class TestPkiBundle(X509Certificate2 rootPublicCert, X509Certificate2 leafServerCert) : IDisposable
    {
        public X509Certificate2 RootPublicCert { get; } = rootPublicCert;

        public X509Certificate2 LeafServerCert { get; } = leafServerCert;

        public void Dispose()
        {
            LeafServerCert.Dispose();
            RootPublicCert.Dispose();
        }
    }

    private sealed record MockHttpResponse(
        int StatusCode,
        string Body,
        IReadOnlyDictionary<string, string>? Headers = null);

    private sealed class MockTlsHttpServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _serverCertificate;
        private readonly Func<string, MockHttpResponse> _handler;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _acceptTask;

        public IPEndPoint Endpoint { get; }

        public MockTlsHttpServer(X509Certificate2 serverCertificate, Func<string, MockHttpResponse> handler)
        {
            _serverCertificate = serverCertificate;
            _handler = handler;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Endpoint = (IPEndPoint)_listener.LocalEndpoint;
            _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                    break;
                }

                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            using TcpClient ownedClient = client;
            try
            {
                using SslStream ssl = new(ownedClient.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _serverCertificate,
                        ClientCertificateRequired = false,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    },
                    ct).ConfigureAwait(false);

                byte[] buffer = new byte[4096];
                int read = await ssl.ReadAsync(buffer, ct).ConfigureAwait(false);
                string requestText = read > 0 ? Encoding.ASCII.GetString(buffer, 0, read) : string.Empty;

                MockHttpResponse response = _handler(requestText);
                byte[] bodyBytes = Encoding.UTF8.GetBytes(response.Body);

                StringBuilder headerSb = new();
                headerSb.Append(CultureInfo.InvariantCulture, $"HTTP/1.1 {response.StatusCode} Mock\r\n");
                headerSb.Append(CultureInfo.InvariantCulture, $"Content-Length: {bodyBytes.Length}\r\n");
                headerSb.Append("Content-Type: text/html; charset=utf-8\r\n");
                headerSb.Append("Connection: close\r\n");

                if (response.Headers is not null)
                {
                    foreach (KeyValuePair<string, string> kvp in response.Headers)
                    {
                        headerSb.Append(CultureInfo.InvariantCulture, $"{kvp.Key}: {kvp.Value}\r\n");
                    }
                }

                headerSb.Append("\r\n");
                byte[] headerBytes = Encoding.ASCII.GetBytes(headerSb.ToString());

                await ssl.WriteAsync(headerBytes, ct).ConfigureAwait(false);
                if (bodyBytes.Length > 0)
                {
                    await ssl.WriteAsync(bodyBytes, ct).ConfigureAwait(false);
                }

                await ssl.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (AuthenticationException)
            {
            }
            catch (IOException)
            {
            }
            catch (SocketException)
            {
            }
        }

        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Cleanup during mock server disposal.")]
        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync().ConfigureAwait(false);
            _listener.Stop();
            _listener.Dispose();
            try
            {
                await _acceptTask.ConfigureAwait(false);
            }
            catch (Exception)
            {
            }

            _cts.Dispose();
        }
    }
}
