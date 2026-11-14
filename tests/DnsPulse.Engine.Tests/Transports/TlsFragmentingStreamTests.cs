using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class TlsFragmentingStreamTests
{
    [Fact]
    public async Task WriteAsync_FragmentsInitialTlsClientHelloAndPreservesSubsequentWrites()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task<Socket> acceptTask = listener.AcceptSocketAsync();
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port);
        using Socket serverSocket = await acceptTask;

        await using TlsFragmentingStream fragStream = new(clientSocket, chunkSize: 40, ownsSocket: false);
        clientSocket.NoDelay.Should().BeTrue();

        byte[] clientHello = new byte[165];
        clientHello[0] = 0x16; // Handshake
        clientHello[1] = 0x03; // TLS major
        clientHello[2] = 0x01; // TLS 1.0 record version
        clientHello[3] = 0x00;
        clientHello[4] = 160;
        clientHello[5] = 0x01; // ClientHello
        for (int i = 6; i < clientHello.Length; i++)
        {
            clientHello[i] = (byte)(i & 0xFF);
        }

        byte[] appData = [0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];

        await fragStream.WriteAsync(clientHello.AsMemory(), CancellationToken.None);
        await fragStream.WriteAsync(appData.AsMemory(), CancellationToken.None);
        await fragStream.FlushAsync(CancellationToken.None);

        byte[] received = await ReadExactAsync(serverSocket, clientHello.Length + appData.Length);
        received.AsSpan(0, clientHello.Length).ToArray().Should().Equal(clientHello);
        received.AsSpan(clientHello.Length).ToArray().Should().Equal(appData);

        fragStream.WasClientHelloFragmented.Should().BeTrue();
        fragStream.ClientHelloChunkSizes.Should().Equal([40, 40, 40, 40, 5]);
    }

    [Fact]
    public async Task SslStreamOverTlsFragmentingStream_CompletesLiveTlsHandshake()
    {
        using X509Certificate2 serverCert = MockTlsServerHelper.CreateSelfSignedServerCertificate("frag.test.local", IPAddress.Loopback);
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task serverHandshakeTask = Task.Run(async () =>
        {
            using Socket accepted = await listener.AcceptSocketAsync();
            await using NetworkStream serverNet = new(accepted, ownsSocket: false);
            await using SslStream serverSsl = new(serverNet, leaveInnerStreamOpen: false);
            await serverSsl.AuthenticateAsServerAsync(serverCert);

            byte[] ping = new byte[4];
            await serverSsl.ReadExactlyAsync(ping);
            await serverSsl.WriteAsync(ping);
        });

        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await clientSocket.ConnectAsync(IPAddress.Loopback, port);
        await using TlsFragmentingStream fragStream = new(clientSocket, chunkSize: 32, ownsSocket: false);

        X509Certificate2Collection trust = [serverCert];
        await using SslStream clientSsl = new(
            fragStream,
            leaveInnerStreamOpen: false,
            (_, cert, _, errors) => errors == SslPolicyErrors.None && cert is not null);

        SslClientAuthenticationOptions authOptions = new()
        {
            TargetHost = "frag.test.local",
            CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustStore = { serverCert }
            }
        };

        await clientSsl.AuthenticateAsClientAsync(authOptions);
        await clientSsl.WriteAsync(new byte[] { 1, 2, 3, 4 });
        byte[] echo = new byte[4];
        await clientSsl.ReadExactlyAsync(echo);
        await serverHandshakeTask;

        echo.Should().Equal([1, 2, 3, 4]);
        fragStream.WasClientHelloFragmented.Should().BeTrue();
        fragStream.ClientHelloChunkSizes.Count.Should().BeGreaterThan(1);
        fragStream.ClientHelloChunkSizes.Should().OnlyContain(size => size <= 32);
    }

    private static async Task<byte[]> ReadExactAsync(Socket socket, int count)
    {
        byte[] result = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await socket.ReceiveAsync(result.AsMemory(offset), SocketFlags.None);
            if (read <= 0)
            {
                break;
            }

            offset += read;
        }

        return result;
    }
}
