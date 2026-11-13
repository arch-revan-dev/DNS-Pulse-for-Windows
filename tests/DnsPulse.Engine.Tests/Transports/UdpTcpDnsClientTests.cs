using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class UdpTcpDnsClientTests
{
    [Fact]
    public async Task QueryAsync_Udp_ReturnsParsedResponseFromLiveServer()
    {
        using UdpClient serverUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)serverUdp.Client.LocalEndPoint!).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task serverTask = Task.Run(async () =>
        {
            UdpReceiveResult received = await serverUdp.ReceiveAsync(cts.Token);
            DnsMessage req = DnsWireCodec.Parse(received.Buffer);
            DnsMessage resp = BuildAResponse(req, IPAddress.Parse("93.184.216.34"), truncated: false);
            byte[] wire = DnsWireCodec.Serialize(resp);
            await serverUdp.SendAsync(wire, received.RemoteEndPoint, cts.Token);
        }, cts.Token);

        UdpTcpDnsClient client = new(DnsProtocol.Udp, options: new TransportOptions { Timeout = TimeSpan.FromSeconds(3) });
        DnsServerEntry upstream = new()
        {
            Id = "test-udp",
            Name = "Mock UDP",
            Protocol = DnsProtocol.Udp,
            PrimaryIp = "127.0.0.1",
            Port = port
        };

        DnsMessage query = DnsMessage.CreateQuery(4242, "example.com", DnsRecordType.A);
        UpstreamQueryResult result = await client.QueryAsync(query, upstream, cts.Token);
        await serverTask;

        result.ProtocolUsed.Should().Be(DnsProtocol.Udp);
        result.Response.Header.Id.Should().Be(4242);
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public async Task QueryAsync_UdpTruncatedTc1_FallsBackAutomaticallyToTcp()
    {
        using TcpListener tcpServer = new(IPAddress.Loopback, 0);
        tcpServer.Start();
        int port = ((IPEndPoint)tcpServer.LocalEndpoint).Port;

        using UdpClient udpServer = new(new IPEndPoint(IPAddress.Loopback, port));
        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));

        Task udpTask = Task.Run(async () =>
        {
            UdpReceiveResult received = await udpServer.ReceiveAsync(cts.Token);
            DnsMessage req = DnsWireCodec.Parse(received.Buffer);
            DnsMessage tcResp = BuildAResponse(req, IPAddress.Parse("93.184.216.34"), truncated: true);
            await udpServer.SendAsync(DnsWireCodec.Serialize(tcResp), received.RemoteEndPoint, cts.Token);
        }, cts.Token);

        Task tcpTask = Task.Run(async () =>
        {
            using TcpClient accepted = await tcpServer.AcceptTcpClientAsync(cts.Token);
            await using NetworkStream stream = accepted.GetStream();
            byte[] lenBuf = new byte[2];
            await stream.ReadExactlyAsync(lenBuf, cts.Token);
            int len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
            byte[] reqBuf = new byte[len];
            await stream.ReadExactlyAsync(reqBuf, cts.Token);

            DnsMessage req = DnsWireCodec.Parse(reqBuf);
            DnsMessage fullResp = BuildAResponse(req, IPAddress.Parse("198.51.100.42"), truncated: false);
            byte[] wire = DnsWireCodec.Serialize(fullResp);

            byte[] frame = new byte[2 + wire.Length];
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, 2), (ushort)wire.Length);
            wire.CopyTo(frame.AsSpan(2));
            await stream.WriteAsync(frame, cts.Token);
        }, cts.Token);

        UdpTcpDnsClient client = new(DnsProtocol.Udp, options: new TransportOptions { Timeout = TimeSpan.FromSeconds(3) });
        DnsServerEntry upstream = new()
        {
            Id = "test-udp-tc1",
            Name = "Mock UDP TC=1",
            Protocol = DnsProtocol.Udp,
            PrimaryIp = "127.0.0.1",
            Port = port
        };

        DnsMessage query = DnsMessage.CreateQuery(7788, "tc-fallback.example", DnsRecordType.A);
        UpstreamQueryResult result = await client.QueryAsync(query, upstream, cts.Token);
        await Task.WhenAll(udpTask, tcpTask);

        result.ProtocolUsed.Should().Be(DnsProtocol.Tcp);
        result.Response.IsTruncated.Should().BeFalse();
        result.Response.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("198.51.100.42")));
    }

    [Fact]
    public async Task QueryAsync_BlackholeUdp_EnforcesStrictTimeout()
    {
        using UdpClient blackhole = new(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)blackhole.Client.LocalEndPoint!).Port;

        UdpTcpDnsClient client = new(DnsProtocol.Udp, options: new TransportOptions { Timeout = TimeSpan.FromMilliseconds(150) });
        DnsServerEntry upstream = new()
        {
            Id = "blackhole",
            Name = "Blackhole",
            Protocol = DnsProtocol.Udp,
            PrimaryIp = "127.0.0.1",
            Port = port
        };

        DnsMessage query = DnsMessage.CreateQuery(1010, "timeout.example", DnsRecordType.A);
        Func<Task> act = () => client.QueryAsync(query, upstream);

        await act.Should().ThrowAsync<TimeoutException>();
    }

    private static DnsMessage BuildAResponse(DnsMessage query, IPAddress answerIp, bool truncated)
    {
        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = query.Header.Id,
                IsResponse = true,
                RecursionDesired = query.Header.RecursionDesired,
                RecursionAvailable = true,
                Truncated = truncated,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = (ushort)query.Questions.Count,
                AnswerCount = (ushort)(truncated ? 0 : 1)
            },
            Questions = query.Questions,
            Answers = truncated ? [] : [DnsResourceRecord.CreateA(query.Questions[0].Name, answerIp, 120)]
        };
    }
}
