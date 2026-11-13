using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class DohDnsClientTests
{
    [Fact]
    public async Task QueryAsync_PostWithBootstrapIpAndSpkiPin_Succeeds()
    {
        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("doh.test.local", IPAddress.Loopback);
        string spkiPin = TlsCertificateValidator.ComputeSpkiPinSha256Base64(cert);

        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        string? observedMethod = null;
        string? observedPath = null;
        Task serverTask = Task.Run(async () =>
        {
            using TcpClient accepted = await listener.AcceptTcpClientAsync(cts.Token);
            (observedMethod, observedPath) = await HandleSingleDohHttpRequestAsync(accepted, cert, cts.Token);
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(5),
            DohMethod = DohHttpMethod.Post,
            EnableTlsFragmentation = true,
            TlsFragmentChunkSize = 40,
            CustomTrustAnchors = [cert]
        };

        using DohDnsClient dohClient = new(DnsProtocol.DoH, options: options);
        DnsServerEntry upstream = new()
        {
            Id = "mock-doh-post",
            Name = "Mock DoH POST",
            Protocol = DnsProtocol.DoH,
            PrimaryIp = "127.0.0.1",
            DohUrl = string.Create(CultureInfo.InvariantCulture, $"https://doh.test.local:{port}/dns-query"),
            BootstrapIps = ["127.0.0.1"],
            SpkiPinSha256 = spkiPin,
            Port = port
        };

        DnsMessage query = DnsMessage.CreateQuery(5555, "doh.example", DnsRecordType.A);
        UpstreamQueryResult result = await dohClient.QueryAsync(query, upstream, cts.Token);
        await serverTask;

        observedMethod.Should().Be("POST");
        observedPath.Should().Be("/dns-query");
        result.ProtocolUsed.Should().Be(DnsProtocol.DoH);
        result.Response.Header.Id.Should().Be(5555);
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public async Task QueryAsync_GetMethod_SendsBase64UrlDnsQueryParameter()
    {
        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("doh-get.test.local", IPAddress.Loopback);
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(10));
        string? observedMethod = null;
        string? observedPath = null;
        Task serverTask = Task.Run(async () =>
        {
            using TcpClient accepted = await listener.AcceptTcpClientAsync(cts.Token);
            (observedMethod, observedPath) = await HandleSingleDohHttpRequestAsync(accepted, cert, cts.Token);
        }, cts.Token);

        TransportOptions options = new()
        {
            Timeout = TimeSpan.FromSeconds(5),
            DohMethod = DohHttpMethod.Get,
            CustomTrustAnchors = [cert]
        };

        using DohDnsClient dohClient = new(DnsProtocol.DoH, options: options);
        DnsServerEntry upstream = new()
        {
            Id = "mock-doh-get",
            Name = "Mock DoH GET",
            Protocol = DnsProtocol.DoH,
            PrimaryIp = "127.0.0.1",
            DohUrl = string.Create(CultureInfo.InvariantCulture, $"https://doh-get.test.local:{port}/dns-query"),
            BootstrapIps = ["127.0.0.1"],
            Port = port
        };

        DnsMessage query = DnsMessage.CreateQuery(6666, "get.example", DnsRecordType.A);
        UpstreamQueryResult result = await dohClient.QueryAsync(query, upstream, cts.Token);
        await serverTask;

        observedMethod.Should().Be("GET");
        observedPath.Should().StartWith("/dns-query?dns=");
        result.Response.Header.Id.Should().Be(6666);
    }

    [Fact]
    public async Task QueryAsync_WrongSpkiPin_ThrowsAuthenticationException()
    {
        using X509Certificate2 cert = MockTlsServerHelper.CreateSelfSignedServerCertificate("doh-pin.test.local", IPAddress.Loopback);
        string wrongPin = Convert.ToBase64String(new byte[32]);

        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task serverTask = Task.Run(async () =>
        {
            try
            {
                using TcpClient accepted = await listener.AcceptTcpClientAsync(cts.Token);
                await HandleSingleDohHttpRequestAsync(accepted, cert, cts.Token);
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

        using DohDnsClient dohClient = new(DnsProtocol.DoH, options: options);
        DnsServerEntry upstream = new()
        {
            Id = "mock-doh-bad-pin",
            Name = "Mock DoH Bad Pin",
            Protocol = DnsProtocol.DoH,
            PrimaryIp = "127.0.0.1",
            DohUrl = string.Create(CultureInfo.InvariantCulture, $"https://doh-pin.test.local:{port}/dns-query"),
            BootstrapIps = ["127.0.0.1"],
            SpkiPinSha256 = wrongPin,
            Port = port
        };

        Func<Task> act = () => dohClient.QueryAsync(DnsMessage.CreateQuery(7777, "badpin.example", DnsRecordType.A), upstream, cts.Token);
        await act.Should().ThrowAsync<HttpRequestException>();

        await cts.CancelAsync();
        listener.Stop();
        await serverTask;
    }

    internal static async Task<(string Method, string Path)> HandleSingleDohHttpRequestAsync(
        TcpClient client,
        X509Certificate2 cert,
        CancellationToken cancellationToken)
    {
        using (client)
        await using (SslStream ssl = new(client.GetStream(), leaveInnerStreamOpen: false))
        {
            await ssl.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    ApplicationProtocols = [SslApplicationProtocol.Http11]
                },
                cancellationToken);

            (string method, string path, byte[] body) = await ReadHttpRequestAsync(ssl, cancellationToken);
            byte[] dnsQueryBytes = string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
                ? DecodeDnsQueryParam(path)
                : body;

            DnsMessage req = DnsWireCodec.Parse(dnsQueryBytes);
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
            string header = string.Create(
                CultureInfo.InvariantCulture,
                $"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {wire.Length}\r\nConnection: close\r\n\r\n");
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            await ssl.WriteAsync(headerBytes, cancellationToken);
            await ssl.WriteAsync(wire, cancellationToken);
            await ssl.FlushAsync(cancellationToken);
            return (method, path);
        }
    }

    internal static async Task<(string Method, string Path, byte[] Body)> ReadHttpRequestAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[16384];
        int totalRead = 0;
        int headerEnd = -1;

        while (headerEnd < 0 && totalRead < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(totalRead), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Connection closed before HTTP headers completed.");
            }

            totalRead += read;
            headerEnd = IndexOfHeaderEnd(buffer.AsSpan(0, totalRead));
        }

        if (headerEnd < 0)
        {
            throw new InvalidDataException("HTTP request headers exceeded mock buffer size.");
        }

        string headerText = Encoding.ASCII.GetString(buffer, 0, headerEnd);
        string[] lines = headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        string[] requestLine = lines[0].Split(' ');
        string method = requestLine[0];
        string path = requestLine[1];

        int contentLength = 0;
        foreach (string line in lines)
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                string lenText = line["Content-Length:".Length..].Trim();
                contentLength = int.Parse(lenText, CultureInfo.InvariantCulture);
            }
        }

        int bodyStart = headerEnd + 4;
        int alreadyReadBody = totalRead - bodyStart;
        byte[] body = new byte[contentLength];
        if (alreadyReadBody > 0)
        {
            int copyCount = Math.Min(alreadyReadBody, contentLength);
            buffer.AsSpan(bodyStart, copyCount).CopyTo(body);
        }

        if (alreadyReadBody < contentLength)
        {
            await stream.ReadExactlyAsync(body.AsMemory(alreadyReadBody, contentLength - alreadyReadBody), cancellationToken);
        }

        return (method, path, body);
    }

    private static int IndexOfHeaderEnd(ReadOnlySpan<byte> data)
    {
        for (int i = 0; i <= data.Length - 4; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
            {
                return i;
            }
        }

        return -1;
    }

    private static byte[] DecodeDnsQueryParam(string path)
    {
        int idx = path.IndexOf("dns=", StringComparison.Ordinal);
        string raw = path[(idx + 4)..];
        int amp = raw.IndexOf('&', StringComparison.Ordinal);
        if (amp >= 0)
        {
            raw = raw[..amp];
        }

        string b64 = raw.Replace('-', '+').Replace('_', '/');
        int mod = b64.Length % 4;
        if (mod == 2)
        {
            b64 = string.Concat(b64, "==");
        }
        else if (mod == 3)
        {
            b64 = string.Concat(b64, "=");
        }

        return Convert.FromBase64String(b64);
    }
}
