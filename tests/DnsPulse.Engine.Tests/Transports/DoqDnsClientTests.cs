using System.Buffers.Binary;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class DoqDnsClientTests
{
    [Fact]
    public async Task QueryAsync_GuardsQuicSupportCleanlyAndWorksWhenSupported()
    {
        DnsServerEntry upstream = new()
        {
            Id = "mock-doq",
            Name = "Mock DoQ",
            Protocol = DnsProtocol.DoQ,
            PrimaryIp = "127.0.0.1",
            DotHost = "doq.test.local",
            Port = 853
        };

        DnsMessage query = DnsMessage.CreateQuery(1234, "doq.example", DnsRecordType.A);

        if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            || !QuicConnection.IsSupported
            || !QuicListener.IsSupported)
        {
            if (!QuicConnection.IsSupported)
            {
                await using DoqDnsClient unsupportedClient = new();
                Func<Task> act = () => unsupportedClient.QueryAsync(query, upstream);
                await act.Should().ThrowAsync<PlatformNotSupportedException>();
            }

            return;
        }

        await RunLiveQuicRoundTripAsync(upstream, query);
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private static async Task RunLiveQuicRoundTripAsync(DnsServerEntry upstream, DnsMessage query)
    {

        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("doq.test.local", IPAddress.Loopback);
        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));

        await using QuicListener listener = await QuicListener.ListenAsync(
            new QuicListenerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
                ApplicationProtocols = [new SslApplicationProtocol("doq")],
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
                {
                    DefaultStreamErrorCode = 0,
                    DefaultCloseErrorCode = 0,
                    ServerAuthenticationOptions = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = cert,
                        ApplicationProtocols = [new SslApplicationProtocol("doq")]
                    }
                })
            },
            cts.Token);

        int port = listener.LocalEndPoint.Port;
        Task serverTask = Task.Run(async () =>
        {
            await using QuicConnection conn = await listener.AcceptConnectionAsync(cts.Token);
            await using QuicStream stream = await conn.AcceptInboundStreamAsync(cts.Token);

            byte[] lenBuf = new byte[2];
            await stream.ReadExactlyAsync(lenBuf, cts.Token);
            int len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
            byte[] reqBuf = new byte[len];
            await stream.ReadExactlyAsync(reqBuf, cts.Token);

            DnsMessage req = DnsWireCodec.Parse(reqBuf);
            req.Header.Id.Should().Be(0, "RFC 9250 mandates DNS Message ID 0 on the wire");

            DnsMessage resp = new()
            {
                Header = new DnsHeader
                {
                    Id = 0,
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
            await stream.WriteAsync(frame, completeWrites: true, cts.Token);
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(5),
            CustomTrustAnchors = [cert]
        };

        await using DoqDnsClient doqClient = new(options: options);
        DnsServerEntry liveUpstream = upstream with
        {
            Port = port,
            SpkiPinSha256 = TlsCertificateValidator.ComputeSpkiPinSha256Base64(cert)
        };

        UpstreamQueryResult result = await doqClient.QueryAsync(query, liveUpstream, cts.Token);
        await serverTask;

        result.ProtocolUsed.Should().Be(DnsProtocol.DoQ);
        result.Response.Header.Id.Should().Be(1234);
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }
}
