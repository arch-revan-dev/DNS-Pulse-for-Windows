using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class DotDnsClientTests
{
    [Fact]
    public async Task QueryAsync_ValidCertAndMatchingSpkiPin_SucceedsAndReusesConnection()
    {
        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("dot.test.local", IPAddress.Loopback);
        string spkiPin = TlsCertificateValidator.ComputeSpkiPinSha256Base64(cert);

        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        int acceptedConnections = 0;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        Task serverTask = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                Interlocked.Increment(ref acceptedConnections);
                _ = HandleDotClientAsync(client, cert, cts.Token);
            }
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(5),
            CustomTrustAnchors = [cert]
        };

        await using DotDnsClient dotClient = new(options: options);
        DnsServerEntry upstream = new()
        {
            Id = "mock-dot",
            Name = "Mock DoT",
            Protocol = DnsProtocol.DoT,
            PrimaryIp = "127.0.0.1",
            DotHost = "dot.test.local",
            SpkiPinSha256 = spkiPin,
            Port = port
        };

        UpstreamQueryResult r1 = await dotClient.QueryAsync(DnsMessage.CreateQuery(1111, "first.example", DnsRecordType.A), upstream, cts.Token);
        UpstreamQueryResult r2 = await dotClient.QueryAsync(DnsMessage.CreateQuery(2222, "second.example", DnsRecordType.A), upstream, cts.Token);

        await cts.CancelAsync();
        listener.Stop();
        await serverTask;

        r1.ProtocolUsed.Should().Be(DnsProtocol.DoT);
        r1.Response.Header.Id.Should().Be(1111);
        r2.Response.Header.Id.Should().Be(2222);
        acceptedConnections.Should().Be(1, "persistent DoT connection should be reused across sequential queries");
    }

    [Fact]
    public async Task QueryAsync_WrongSpkiPin_RejectsHandshake()
    {
        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("dot.test.local", IPAddress.Loopback);
        string wrongPin = Convert.ToBase64String(new byte[32]);

        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task serverTask = Task.Run(async () =>
        {
            try
            {
                using TcpClient client = await listener.AcceptTcpClientAsync(cts.Token);
                await using SslStream ssl = new(client.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions { ServerCertificate = cert },
                    cts.Token);
            }
            catch (IOException)
            {
            }
            catch (AuthenticationException)
            {
            }
            catch (OperationCanceledException)
            {
            }
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(4),
            CustomTrustAnchors = [cert]
        };

        await using DotDnsClient dotClient = new(options: options);
        DnsServerEntry upstream = new()
        {
            Id = "mock-dot-bad-pin",
            Name = "Mock DoT Bad Pin",
            Protocol = DnsProtocol.DoT,
            PrimaryIp = "127.0.0.1",
            DotHost = "dot.test.local",
            SpkiPinSha256 = wrongPin,
            Port = port
        };

        Func<Task> act = () => dotClient.QueryAsync(DnsMessage.CreateQuery(3333, "pin.example", DnsRecordType.A), upstream, cts.Token);
        await act.Should().ThrowAsync<AuthenticationException>();

        await cts.CancelAsync();
        listener.Stop();
        await serverTask;
    }

    [Fact]
    public async Task QueryAsync_WithTlsFragmentationEnabled_Succeeds()
    {
        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("frag-dot.test.local", IPAddress.Loopback);
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task serverTask = Task.Run(async () =>
        {
            using TcpClient accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await HandleDotClientAsync(accepted, cert, cts.Token);
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(4),
            EnableTlsFragmentation = true,
            TlsFragmentChunkSize = 40,
            CustomTrustAnchors = [cert]
        };

        await using DotDnsClient dotClient = new(options: options);
        DnsServerEntry upstream = new()
        {
            Id = "mock-dot-frag",
            Name = "Mock DoT Frag",
            Protocol = DnsProtocol.DoT,
            PrimaryIp = "127.0.0.1",
            DotHost = "frag-dot.test.local",
            Port = port
        };

        UpstreamQueryResult result = await dotClient.QueryAsync(DnsMessage.CreateQuery(4444, "frag.example", DnsRecordType.A), upstream, cts.Token);
        await serverTask;

        result.Response.Header.Id.Should().Be(4444);
        result.Response.Answers.Should().ContainSingle();
    }

    private static async Task HandleDotClientAsync(TcpClient client, X509Certificate2 cert, CancellationToken cancellationToken)
    {
        using (client)
        await using (SslStream ssl = new(client.GetStream(), leaveInnerStreamOpen: false))
        {
            try
            {
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions { ServerCertificate = cert },
                    cancellationToken);
                byte[] lenBuf = new byte[2];
                while (!cancellationToken.IsCancellationRequested)
                {
                    await ssl.ReadExactlyAsync(lenBuf, cancellationToken);
                    int len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
                    byte[] reqBuf = new byte[len];
                    await ssl.ReadExactlyAsync(reqBuf, cancellationToken);

                    DnsMessage req = DnsWireCodec.Parse(reqBuf);
                    DnsMessage resp = new()
                    {
                        Header = new DnsHeader
                        {
                            Id = req.Header.Id,
                            IsResponse = true,
                            RecursionDesired = true,
                            RecursionAvailable = true,
                            QuestionCount = (ushort)req.Questions.Count,
                            AnswerCount = 1
                        },
                        Questions = req.Questions,
                        Answers = [DnsResourceRecord.CreateA(req.Questions[0].Name, IPAddress.Parse("93.184.216.34"))]
                    };

                    byte[] wire = DnsWireCodec.Serialize(resp);
                    byte[] frame = new byte[2 + wire.Length];
                    BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, 2), (ushort)wire.Length);
                    wire.CopyTo(frame.AsSpan(2));
                    await ssl.WriteAsync(frame, cancellationToken);
                    await ssl.FlushAsync(cancellationToken);
                }
            }
            catch (EndOfStreamException)
            {
            }
            catch (IOException)
            {
            }
            catch (OperationCanceledException)
            {
            }
        }
    }
}
