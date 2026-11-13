using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Discovery;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Discovery;

public sealed class AdvancedSubnetScannerServiceTests
{
    private static readonly string[] PrivateCidrInput = ["192.168.10.0/24"];
    private static readonly string[] PublicSlash16Input = ["93.184.0.0/16"];

    [Fact]
    public async Task ScanAsync_WithoutExplicitOptIn_ThrowsInvalidOperationException()
    {
        AdvancedSubnetScannerService scanner = new();
        SubnetScanRequest request = new()
        {
            TargetDomain = "gemini.google.com",
            UserOptedIn = false,
            CandidateTargets = ["93.184.216.34"]
        };

        Func<Task> act = async () => await scanner.ScanAsync(request).ConfigureAwait(false);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task ScanAsync_ExcludesPrivateAndBogonTargetsAndNeverProbesThem()
    {
        AdvancedSubnetScannerService scanner = new();
        ConcurrentBag<IPAddress> probedCandidates = [];

        using TestPkiBundle pki = CreateTestPki("gemini.google.com");
        await using MockTlsListenerServer mockTls = new(pki.LeafServerCert);

        SubnetScanRequest request = new()
        {
            TargetDomain = "gemini.google.com",
            UserOptedIn = true,
            CandidateTargets =
            [
                "127.0.0.1",
                "10.0.0.1",
                "192.168.1.50",
                "172.16.0.10",
                "169.254.10.10",
                "100.64.1.1",
                "224.0.0.1",
                "93.184.216.34"
            ],
            AdditionalTrustedRoots = [pki.RootPublicCert],
            EndpointOverride = ip =>
            {
                probedCandidates.Add(ip);
                return mockTls.Endpoint;
            }
        };

        IReadOnlyList<DnsServerEntry> discovered = await scanner.ScanAsync(request);

        probedCandidates.Should().ContainSingle().Which.Should().Be(IPAddress.Parse("93.184.216.34"));
        discovered.Should().ContainSingle();
        discovered[0].TrustTier.Should().Be(TrustTier.Tier4ExperimentalLab);
        discovered[0].IsEligibleForDefaultInternet.Should().BeFalse();
        discovered[0].Protocol.Should().Be(DnsProtocol.SniProxy);
        discovered[0].Category.Should().Be("Smart-DNS");
        discovered[0].Tags.Should().Contain("Gemini");
    }

    [Fact]
    public async Task ScanAsync_UntrustedCert_RejectsNodeBeforeAccepting()
    {
        AdvancedSubnetScannerService scanner = new();
        using TestPkiBundle trustedPki = CreateTestPki("gemini.google.com");
        using TestPkiBundle roguePki = CreateTestPki("gemini.google.com");
        await using MockTlsListenerServer rogueServer = new(roguePki.LeafServerCert);

        SubnetScanRequest request = new()
        {
            TargetDomain = "gemini.google.com",
            UserOptedIn = true,
            CandidateTargets = ["93.184.216.34"],
            AdditionalTrustedRoots = [trustedPki.RootPublicCert],
            EndpointOverride = _ => rogueServer.Endpoint
        };

        IReadOnlyList<DnsServerEntry> discovered = await scanner.ScanAsync(request);

        discovered.Should().BeEmpty();
    }

    [Fact]
    public void FilterAndExpandCandidates_CidrPrefix_ExcludesPrivateAndRespectsHostCap()
    {
        IReadOnlyList<IPAddress> privateCidr = AdvancedSubnetScannerService.FilterAndExpandCandidates(
            PrivateCidrInput,
            maxCidrHosts: 1200,
            out int excludedPrivate);

        privateCidr.Should().BeEmpty();
        excludedPrivate.Should().Be(254);

        IReadOnlyList<IPAddress> cappedPublic = AdvancedSubnetScannerService.FilterAndExpandCandidates(
            PublicSlash16Input,
            maxCidrHosts: 5000,
            out _);

        cappedPublic.Should().HaveCount(AdvancedSubnetScannerService.HardMaxCidrHostCap);
    }

    [Theory]
    [InlineData("login.live.com", "Игры и Регионы", "Xbox", true)]
    [InlineData("gemini.google.com", "Smart-DNS", "Gemini", true)]
    [InlineData("one.one.one.one", "Скоростные", "CleanPing", false)]
    public void ClassifyTargetDomain_PreservesV153ClassificationRules(
        string domain,
        string expectedCategory,
        string expectedServiceTag,
        bool expectedBypass)
    {
        DomainClassification classification = AdvancedSubnetScannerService.ClassifyTargetDomain(domain);

        classification.Category.Should().Be(expectedCategory);
        classification.ServiceTag.Should().Be(expectedServiceTag);
        classification.RequiresBypass.Should().Be(expectedBypass);
    }

    private static TestPkiBundle CreateTestPki(string leafSanDnsName)
    {
        using RSA rootRsa = RSA.Create(2048);
        CertificateRequest rootReq = new(
            "CN=DnsPulse Lab Root CA",
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

    private sealed class MockTlsListenerServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _cert;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loopTask;

        public IPEndPoint Endpoint { get; }

        public MockTlsListenerServer(X509Certificate2 cert)
        {
            _cert = cert;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Endpoint = (IPEndPoint)_listener.LocalEndpoint;
            _loopTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
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
            using TcpClient owned = client;
            try
            {
                using SslStream ssl = new(owned.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _cert,
                        ClientCertificateRequired = false,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    },
                    ct).ConfigureAwait(false);
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
                await _loopTask.ConfigureAwait(false);
            }
            catch (Exception)
            {
            }

            _cts.Dispose();
        }
    }
}
