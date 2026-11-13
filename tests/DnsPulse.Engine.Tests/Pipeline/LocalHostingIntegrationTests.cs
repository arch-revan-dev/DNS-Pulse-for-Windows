using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Hosting;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Pipeline;

public sealed class LocalHostingIntegrationTests
{
    [Fact]
    public async Task LocalDnsServer_UdpAndTcp_RoundTripsAndSignalsTruncationAbove512Bytes()
    {
        IPulseDnsResolver resolver = Substitute.For<IPulseDnsResolver>();
        resolver.ResolveAsync(Arg.Any<DnsMessage>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage query = callInfo.Arg<DnsMessage>();
                string domain = query.Questions[0].Name;

                if (string.Equals(domain, "large.example.com", StringComparison.OrdinalIgnoreCase))
                {
                    List<DnsResourceRecord> manyAnswers = [];
                    for (int i = 1; i <= 35; i++)
                    {
                        string ip = string.Create(CultureInfo.InvariantCulture, $"93.184.216.{i}");
                        manyAnswers.Add(DnsResourceRecord.CreateA(domain, IPAddress.Parse(ip), 120));
                    }

                    return new DnsMessage
                    {
                        Header = new DnsHeader
                        {
                            Id = query.Header.Id,
                            IsResponse = true,
                            RecursionDesired = true,
                            RecursionAvailable = true,
                            ResponseCode = DnsResponseCode.NoError,
                            QuestionCount = 1,
                            AnswerCount = (ushort)manyAnswers.Count
                        },
                        Questions = query.Questions,
                        Answers = manyAnswers
                    };
                }

                return new DnsMessage
                {
                    Header = new DnsHeader
                    {
                        Id = query.Header.Id,
                        IsResponse = true,
                        RecursionDesired = true,
                        RecursionAvailable = true,
                        ResponseCode = DnsResponseCode.NoError,
                        QuestionCount = 1,
                        AnswerCount = 1
                    },
                    Questions = query.Questions,
                    Answers = [DnsResourceRecord.CreateA(domain, IPAddress.Parse("93.184.216.34"), 120)]
                };
            });

        await using LocalDnsServer server = new(resolver, new LocalDnsServerOptions
        {
            ListenAddress = IPAddress.Loopback,
            Port = 0
        });
        await server.StartAsync();

        server.BoundPort.Should().BeGreaterThan(0);

        // 1. Standard UDP query round-trip.
        using UdpClient udp = new();
        udp.Client.ReceiveTimeout = 3000;
        byte[] smallWire = DnsWireCodec.Serialize(DnsMessage.CreateQuery(1001, "small.example.com", DnsRecordType.A, enableEdns0: false));
        IPEndPoint target = new(IPAddress.Loopback, server.BoundPort);
        await udp.SendAsync(smallWire, target);

        UdpReceiveResult udpResult = await udp.ReceiveAsync();
        DnsMessage smallResponse = DnsWireCodec.Parse(udpResult.Buffer);
        smallResponse.Header.Id.Should().Be(1001);
        smallResponse.IsTruncated.Should().BeFalse();
        smallResponse.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("93.184.216.34")));

        // 2. Non-EDNS0 large UDP query truncates with TC=1 <= 512 bytes, then TCP receives all 35 answers.
        byte[] largeWire = DnsWireCodec.Serialize(DnsMessage.CreateQuery(1002, "large.example.com", DnsRecordType.A, enableEdns0: false));
        await udp.SendAsync(largeWire, target);
        UdpReceiveResult truncatedResult = await udp.ReceiveAsync();
        truncatedResult.Buffer.Length.Should().BeLessThanOrEqualTo(512);
        DnsMessage truncatedMsg = DnsWireCodec.Parse(truncatedResult.Buffer);
        truncatedMsg.Header.Id.Should().Be(1002);
        truncatedMsg.IsTruncated.Should().BeTrue();

        using TcpClient tcp = new();
        await tcp.ConnectAsync(IPAddress.Loopback, server.BoundPort);
        using NetworkStream tcpStream = tcp.GetStream();

        byte[] tcpFrame = new byte[2 + largeWire.Length];
        BinaryPrimitives.WriteUInt16BigEndian(tcpFrame.AsSpan(0, 2), (ushort)largeWire.Length);
        largeWire.CopyTo(tcpFrame.AsSpan(2));
        await tcpStream.WriteAsync(tcpFrame.AsMemory());
        await tcpStream.FlushAsync();

        byte[] lenBuf = new byte[2];
        await tcpStream.ReadExactlyAsync(lenBuf);
        ushort respLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
        byte[] respBuf = new byte[respLen];
        await tcpStream.ReadExactlyAsync(respBuf);

        DnsMessage fullTcpMsg = DnsWireCodec.Parse(respBuf);
        fullTcpMsg.Header.Id.Should().Be(1002);
        fullTcpMsg.IsTruncated.Should().BeFalse();
        fullTcpMsg.Answers.Should().HaveCount(35);
    }

    [Fact]
    public async Task LocalDohHttpListener_PostAndGet_RoundTripsDnsMessages()
    {
        IPulseDnsResolver resolver = Substitute.For<IPulseDnsResolver>();
        resolver.ResolveAsync(Arg.Any<DnsMessage>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage query = callInfo.Arg<DnsMessage>();
                return new DnsMessage
                {
                    Header = new DnsHeader
                    {
                        Id = query.Header.Id,
                        IsResponse = true,
                        RecursionDesired = true,
                        RecursionAvailable = true,
                        ResponseCode = DnsResponseCode.NoError,
                        QuestionCount = 1,
                        AnswerCount = 1
                    },
                    Questions = query.Questions,
                    Answers = [DnsResourceRecord.CreateA(query.Questions[0].Name, IPAddress.Parse("1.1.1.1"), 90)]
                };
            });

        await using LocalDohHttpListener dohServer = new(resolver, new LocalDohServerOptions
        {
            ListenAddress = IPAddress.Loopback,
            Port = 0
        });
        await dohServer.StartAsync();

        dohServer.ListenUri.Should().NotBeNull();

        using HttpClient http = new();

        // 1. POST /dns-query (application/dns-message)
        byte[] postWire = DnsWireCodec.Serialize(DnsMessage.CreateQuery(2001, "doh-post.example.com", DnsRecordType.A));
        using ByteArrayContent content = new(postWire);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

        using HttpResponseMessage postResp = await http.PostAsync(dohServer.ListenUri, content);
        postResp.StatusCode.Should().Be(HttpStatusCode.OK);
        postResp.Content.Headers.ContentType!.MediaType.Should().Be("application/dns-message");
        byte[] postRespBytes = await postResp.Content.ReadAsByteArrayAsync();
        DnsMessage postParsed = DnsWireCodec.Parse(postRespBytes);
        postParsed.Header.Id.Should().Be(2001);
        postParsed.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("1.1.1.1")));

        // 2. GET /dns-query?dns=<base64url>
        byte[] getWire = DnsWireCodec.Serialize(DnsMessage.CreateQuery(2002, "doh-get.example.com", DnsRecordType.A));
        string base64Url = Convert.ToBase64String(getWire).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Uri getUri = new(dohServer.ListenUri + "?dns=" + base64Url);

        using HttpResponseMessage getResp = await http.GetAsync(getUri);
        getResp.StatusCode.Should().Be(HttpStatusCode.OK);
        getResp.Content.Headers.ContentType!.MediaType.Should().Be("application/dns-message");
        byte[] getRespBytes = await getResp.Content.ReadAsByteArrayAsync();
        DnsMessage getParsed = DnsWireCodec.Parse(getRespBytes);
        getParsed.Header.Id.Should().Be(2002);
        getParsed.Answers.Should().ContainSingle(a => Equals(a.Address, IPAddress.Parse("1.1.1.1")));

        // 3. Unsupported Content-Type returns 415.
        using StringContent wrongContent = new("not-dns");
        using HttpResponseMessage unsupportedResp = await http.PostAsync(dohServer.ListenUri, wrongContent);
        unsupportedResp.StatusCode.Should().Be(HttpStatusCode.UnsupportedMediaType);
    }
}
