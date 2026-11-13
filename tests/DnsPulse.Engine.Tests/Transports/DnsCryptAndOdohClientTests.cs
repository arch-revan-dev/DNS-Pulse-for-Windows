using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class DnsCryptAndOdohClientTests
{
    private static readonly byte[] DnsCryptServerMagic = [0x72, 0x36, 0x66, 0x6E, 0x76, 0x57, 0x6A, 0x38];
    private static readonly byte[] AnonRelayMagic = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];

    [Fact]
    public void X25519ScalarMult_MatchesRfc7748Section6_1TestVector()
    {
        byte[] aliceSk = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobSk = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        byte[] baseU = new byte[32];
        baseU[0] = 9;

        byte[] alicePk = DnsCryptClient.X25519ScalarMult(aliceSk, baseU);
        byte[] bobPk = DnsCryptClient.X25519ScalarMult(bobSk, baseU);

        Convert.ToHexStringLower(alicePk).Should().Be("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        Convert.ToHexStringLower(bobPk).Should().Be("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        byte[] sharedAlice = DnsCryptClient.X25519ScalarMult(aliceSk, bobPk);
        byte[] sharedBob = DnsCryptClient.X25519ScalarMult(bobSk, alicePk);

        Convert.ToHexStringLower(sharedAlice).Should().Be("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        sharedBob.Should().Equal(sharedAlice);
    }

    [Theory]
    [InlineData((ushort)1)]
    [InlineData((ushort)2)]
    public void SealAndOpenBox_BothCipherSuites_RoundtripAndRejectTamper(ushort esVersion)
    {
        (byte[] clientSk, byte[] clientPk) = DnsCryptClient.GenerateX25519KeyPair();
        (byte[] serverSk, byte[] serverPk) = DnsCryptClient.GenerateX25519KeyPair();

        byte[] clientShared = DnsCryptClient.DeriveSharedKey(esVersion, clientSk, serverPk);
        byte[] serverShared = DnsCryptClient.DeriveSharedKey(esVersion, serverSk, clientPk);
        clientShared.Should().Equal(serverShared);

        byte[] nonce = RandomNumberGenerator.GetBytes(24);
        byte[] plaintext = Encoding.UTF8.GetBytes("hello-dnscrypt-v2-payload");
        byte[] box = DnsCryptClient.SealBox(esVersion, clientShared, nonce, plaintext);
        byte[] opened = DnsCryptClient.OpenBox(esVersion, serverShared, nonce, box);
        opened.Should().Equal(plaintext);

        box[0] ^= 0xFF;
        Action tampered = () => DnsCryptClient.OpenBox(esVersion, serverShared, nonce, box);
        tampered.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void ParseCertificate_TamperedSignature_ThrowsCryptographicException()
    {
        byte[] cert = new byte[124];
        cert[0] = (byte)'D';
        cert[1] = (byte)'N';
        cert[2] = (byte)'S';
        cert[3] = (byte)'C';
        BinaryPrimitives.WriteUInt16BigEndian(cert.AsSpan(4, 2), 2);
        byte[] providerPk = new byte[32];
        providerPk[0] = 1;

        Action act = () => DnsCryptClient.ParseCertificate(cert, providerPk);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public async Task QueryAsync_DnsCryptV2LiveMockServer_RoundtripsEncryptedQuery()
    {
        (byte[] resolverSk, byte[] resolverPk) = DnsCryptClient.GenerateX25519KeyPair();
        byte[] clientMagic = [0x4D, 0x41, 0x47, 0x49, 0x43, 0x30, 0x30, 0x31];

        using UdpClient serverUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)serverUdp.Client.LocalEndPoint!).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task serverTask = Task.Run(async () =>
        {
            UdpReceiveResult received = await serverUdp.ReceiveAsync(cts.Token);
            byte[] respPacket = ProcessDnsCryptPacket(received.Buffer, clientMagic, resolverSk, esVersion: 2);
            await serverUdp.SendAsync(respPacket, received.RemoteEndPoint, cts.Token);
        }, cts.Token);

        string stampUri = DnsStampCodec.Encode(new DnsStamp
        {
            Protocol = DnsStampProtocol.DnsCrypt,
            Properties = DnsStampFlags.NoLog,
            ServerAddress = string.Create(CultureInfo.InvariantCulture, $"127.0.0.1:{port}"),
            PublicKey = ImmutableArray.Create(new byte[32]),
            ProviderName = "2.dnscrypt-cert.mock.local"
        });

        DnsCryptClient client = new(DnsProtocol.DnsCrypt);
        client.RegisterCertificate(
            string.Create(CultureInfo.InvariantCulture, $"127.0.0.1:{port}|2.dnscrypt-cert.mock.local"),
            new DnsCryptCertificate
            {
                EsVersion = 2,
                MinorVersion = 0,
                ResolverPublicKey = ImmutableArray.Create(resolverPk),
                ClientMagic = ImmutableArray.Create(clientMagic),
                Serial = 1,
                ValidFromUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                ValidUntilUtc = DateTimeOffset.UtcNow.AddHours(1)
            });

        DnsServerEntry upstream = new()
        {
            Id = "dnscrypt-mock",
            Name = "Mock DNSCrypt",
            Protocol = DnsProtocol.DnsCrypt,
            DnsStampUri = stampUri
        };

        DnsMessage query = DnsMessage.CreateQuery(8899, "dnscrypt.example", DnsRecordType.A);
        UpstreamQueryResult result = await client.QueryAsync(query, upstream, cts.Token);
        await serverTask;

        result.ProtocolUsed.Should().Be(DnsProtocol.DnsCrypt);
        result.Response.Header.Id.Should().Be(8899);
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public async Task QueryAsync_AnonymizedDnsCryptViaRelay_ForwardsWrappedPacket()
    {
        (byte[] resolverSk, byte[] resolverPk) = DnsCryptClient.GenerateX25519KeyPair();
        byte[] clientMagic = [0x41, 0x4E, 0x4F, 0x4E, 0x30, 0x30, 0x30, 0x31];

        using UdpClient targetUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        using UdpClient relayUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        int targetPort = ((IPEndPoint)targetUdp.Client.LocalEndPoint!).Port;
        int relayPort = ((IPEndPoint)relayUdp.Client.LocalEndPoint!).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task relayTask = Task.Run(async () =>
        {
            UdpReceiveResult clientMsg = await relayUdp.ReceiveAsync(cts.Token);
            byte[] pkt = clientMsg.Buffer;
            pkt.AsSpan(0, 10).SequenceEqual(AnonRelayMagic).Should().BeTrue();

            IPAddress destIp = new IPAddress(pkt.AsSpan(10, 16));
            if (destIp.IsIPv4MappedToIPv6)
            {
                destIp = destIp.MapToIPv4();
            }

            ushort destPort = BinaryPrimitives.ReadUInt16BigEndian(pkt.AsSpan(26, 2));
            destIp.Should().Be(IPAddress.Loopback);
            destPort.Should().Be((ushort)targetPort);

            using UdpClient forwardSocket = new();
            await forwardSocket.SendAsync(pkt.AsMemory(28), new IPEndPoint(destIp, destPort), cts.Token);
            UdpReceiveResult targetResp = await forwardSocket.ReceiveAsync(cts.Token);
            await relayUdp.SendAsync(targetResp.Buffer, clientMsg.RemoteEndPoint, cts.Token);
        }, cts.Token);

        Task targetTask = Task.Run(async () =>
        {
            UdpReceiveResult forwarded = await targetUdp.ReceiveAsync(cts.Token);
            byte[] respPacket = ProcessDnsCryptPacket(forwarded.Buffer, clientMagic, resolverSk, esVersion: 1);
            await targetUdp.SendAsync(respPacket, forwarded.RemoteEndPoint, cts.Token);
        }, cts.Token);

        string targetStamp = DnsStampCodec.Encode(new DnsStamp
        {
            Protocol = DnsStampProtocol.DnsCrypt,
            ServerAddress = string.Create(CultureInfo.InvariantCulture, $"127.0.0.1:{targetPort}"),
            PublicKey = ImmutableArray.Create(new byte[32]),
            ProviderName = "2.dnscrypt-cert.anon.local"
        });
        string relayStamp = DnsStampCodec.Encode(new DnsStamp
        {
            Protocol = DnsStampProtocol.AnonymizedDnsCryptRelay,
            ServerAddress = string.Create(CultureInfo.InvariantCulture, $"127.0.0.1:{relayPort}")
        });

        DnsCryptClient client = new(DnsProtocol.AnonymizedDnsCrypt);
        client.RegisterCertificate(
            string.Create(CultureInfo.InvariantCulture, $"127.0.0.1:{targetPort}|2.dnscrypt-cert.anon.local"),
            new DnsCryptCertificate
            {
                EsVersion = 1,
                MinorVersion = 0,
                ResolverPublicKey = ImmutableArray.Create(resolverPk),
                ClientMagic = ImmutableArray.Create(clientMagic),
                Serial = 1,
                ValidFromUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                ValidUntilUtc = DateTimeOffset.UtcNow.AddHours(1)
            });

        DnsServerEntry upstream = new()
        {
            Id = "anon-dnscrypt-mock",
            Name = "Mock Anon DNSCrypt",
            Protocol = DnsProtocol.AnonymizedDnsCrypt,
            DnsStampUri = string.Concat(targetStamp, " ", relayStamp)
        };

        DnsMessage query = DnsMessage.CreateQuery(9900, "anon.example", DnsRecordType.A);
        UpstreamQueryResult result = await client.QueryAsync(query, upstream, cts.Token);
        await Task.WhenAll(relayTask, targetTask);

        result.ProtocolUsed.Should().Be(DnsProtocol.AnonymizedDnsCrypt);
        result.Response.Header.Id.Should().Be(9900);
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public async Task OdohClient_FetchesConfigEncryptsQueryThroughRelayAndDecryptsResponse()
    {
        (byte[] targetSk, byte[] targetPk) = DnsCryptClient.GenerateX25519KeyPair();
        byte[] contents = new byte[8 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(contents.AsSpan(0, 2), 0x0020);
        BinaryPrimitives.WriteUInt16BigEndian(contents.AsSpan(2, 2), 0x0001);
        BinaryPrimitives.WriteUInt16BigEndian(contents.AsSpan(4, 2), 0x0001);
        BinaryPrimitives.WriteUInt16BigEndian(contents.AsSpan(6, 2), 32);
        targetPk.CopyTo(contents.AsSpan(8));

        OdohTargetConfig config = new()
        {
            Version = 0x0001,
            KemId = 0x0020,
            KdfId = 0x0001,
            AeadId = 0x0001,
            PublicKey = ImmutableArray.Create(targetPk),
            KeyId = ImmutableArray.Create(OdohClient.ComputeKeyId(contents))
        };

        byte[] configsBlob = OdohClient.SerializeConfigs(config);
        IReadOnlyList<OdohTargetConfig> parsedConfigs = OdohClient.ParseConfigs(configsBlob);
        parsedConfigs.Should().ContainSingle();
        parsedConfigs[0].KeyId.AsSpan().ToArray().Should().Equal(config.KeyId.AsSpan().ToArray());

        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("odoh.test.local", IPAddress.Loopback);
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        bool configFetched = false;
        bool relayUsed = false;

        Task serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                using TcpClient tcp = await listener.AcceptTcpClientAsync(cts.Token);
                await using SslStream ssl = new(tcp.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = cert,
                        ApplicationProtocols = [SslApplicationProtocol.Http11]
                    },
                    cts.Token);

                (string method, string path, byte[] body) = await DohDnsClientTests.ReadHttpRequestAsync(ssl, cts.Token);
                byte[] respBytes;
                string contentType;
                if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(path, "/.well-known/odohconfigs", StringComparison.Ordinal))
                {
                    configFetched = true;
                    respBytes = configsBlob;
                    contentType = "application/oblivious-dns-configs";
                }
                else
                {
                    relayUsed = path.StartsWith("/proxy?targethost=", StringComparison.Ordinal);
                    (byte[] dnsQueryWire, _) = OdohClient.ProcessQueryAsTarget(body, targetSk, config);
                    DnsMessage dnsReq = DnsWireCodec.Parse(dnsQueryWire);
                    DnsMessage dnsResp = new()
                    {
                        Header = new DnsHeader
                        {
                            Id = dnsReq.Header.Id,
                            IsResponse = true,
                            RecursionDesired = true,
                            RecursionAvailable = true,
                            QuestionCount = (ushort)dnsReq.Questions.Count,
                            AnswerCount = 1
                        },
                        Questions = dnsReq.Questions,
                        Answers = [DnsResourceRecord.CreateA(dnsReq.Questions[0].Name, IPAddress.Parse("93.184.216.34"))]
                    };

                    respBytes = OdohClient.SealResponseAsTarget(body, targetSk, config, DnsWireCodec.Serialize(dnsResp));
                    contentType = "application/oblivious-dns-message";
                }

                string header = string.Create(
                    CultureInfo.InvariantCulture,
                    $"HTTP/1.1 200 OK\r\nContent-Type: {contentType}\r\nContent-Length: {respBytes.Length}\r\nConnection: close\r\n\r\n");
                await ssl.WriteAsync(Encoding.ASCII.GetBytes(header), cts.Token);
                await ssl.WriteAsync(respBytes, cts.Token);
                await ssl.FlushAsync(cts.Token);
            }
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(5),
            CustomTrustAnchors = [cert]
        };

        using OdohClient odohClient = new(options: options);
        DnsServerEntry upstream = new()
        {
            Id = "odoh-mock",
            Name = "Mock ODoH",
            Protocol = DnsProtocol.ODoH,
            DohUrl = string.Create(CultureInfo.InvariantCulture, $"https://odoh.test.local:{port}/dns-query"),
            SmartProxyIp = string.Create(CultureInfo.InvariantCulture, $"https://odoh.test.local:{port}/proxy"),
            BootstrapIps = ["127.0.0.1"],
            PrimaryIp = "127.0.0.1",
            Port = port
        };

        DnsMessage query = DnsMessage.CreateQuery(31415, "odoh.example", DnsRecordType.A);
        UpstreamQueryResult result = await odohClient.QueryAsync(query, upstream, cts.Token);
        await serverTask;

        configFetched.Should().BeTrue();
        relayUsed.Should().BeTrue();
        result.ProtocolUsed.Should().Be(DnsProtocol.ODoH);
        result.Response.Header.Id.Should().Be(31415);
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }

    private static byte[] ProcessDnsCryptPacket(byte[] packet, byte[] expectedMagic, byte[] resolverSk, ushort esVersion)
    {
        packet.AsSpan(0, 8).SequenceEqual(expectedMagic).Should().BeTrue();
        ReadOnlySpan<byte> clientPk = packet.AsSpan(8, 32);
        ReadOnlySpan<byte> clientNonce = packet.AsSpan(40, 12);
        ReadOnlySpan<byte> encryptedBox = packet.AsSpan(52);

        byte[] sharedKey = DnsCryptClient.DeriveSharedKey(esVersion, resolverSk, clientPk);
        byte[] queryNonce = new byte[24];
        clientNonce.CopyTo(queryNonce);

        byte[] paddedQuery = DnsCryptClient.OpenBox(esVersion, sharedKey, queryNonce, encryptedBox);
        byte[] rawQuery = DnsCryptClient.UnpadIso7816(paddedQuery);
        DnsMessage req = DnsWireCodec.Parse(rawQuery);

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

        byte[] paddedResp = DnsCryptClient.PadIso7816(DnsWireCodec.Serialize(resp), 256, 64);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(12);
        byte[] fullRespNonce = new byte[24];
        clientNonce.CopyTo(fullRespNonce.AsSpan(0, 12));
        serverNonce.CopyTo(fullRespNonce.AsSpan(12, 12));

        byte[] respBox = DnsCryptClient.SealBox(esVersion, sharedKey, fullRespNonce, paddedResp);
        byte[] responsePacket = new byte[8 + 12 + 12 + respBox.Length];
        DnsCryptServerMagic.CopyTo(responsePacket.AsSpan(0, 8));
        clientNonce.CopyTo(responsePacket.AsSpan(8, 12));
        serverNonce.CopyTo(responsePacket.AsSpan(20, 12));
        respBox.CopyTo(responsePacket.AsSpan(32));
        return responsePacket;
    }
}
