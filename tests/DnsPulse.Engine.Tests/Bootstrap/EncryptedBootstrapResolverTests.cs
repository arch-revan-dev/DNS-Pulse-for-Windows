using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Bootstrap;
using DnsPulse.Engine.Contracts;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Bootstrap;

public sealed class EncryptedBootstrapResolverTests
{
    [Fact]
    public async Task QueryBaselineAsync_HappyEyeballsRace_StaggersAndSelectsFastestValidEncryptedWinner()
    {
        DnsServerEntry slowDoh = CreateEndpoint("slow-doh", DnsProtocol.DoH, "1.1.1.1");
        DnsServerEntry fastDot = CreateEndpoint("fast-dot", DnsProtocol.DoT, "9.9.9.9");

        IDnsUpstreamClient mockDoh = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockFragDoh = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockDot = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockPlain = Substitute.For<IDnsUpstreamClient>();

        mockDoh.QueryAsync(Arg.Any<DnsMessage>(), slowDoh, Arg.Any<CancellationToken>())
            .Returns(async callInfo =>
            {
                CancellationToken ct = callInfo.Arg<CancellationToken>();
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
                DnsMessage q = callInfo.Arg<DnsMessage>();
                return CreateResult(q, IPAddress.Parse("1.1.1.1"), DnsProtocol.DoH);
            });

        mockDot.QueryAsync(Arg.Any<DnsMessage>(), fastDot, Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                return Task.FromResult(CreateResult(q, IPAddress.Parse("93.184.216.34"), DnsProtocol.DoT));
            });

        BootstrapOptions options = new()
        {
            StaggerDelay = TimeSpan.FromMilliseconds(50),
            CandidateTimeout = TimeSpan.FromSeconds(3),
            DirectEncryptedEndpoints = [slowDoh, fastDot],
            FragmentedDohEndpoints = [],
            PlaintextFallbackEndpoints = []
        };

        await using EncryptedBootstrapResolver resolver = new(options, mockDoh, mockFragDoh, mockDot, mockPlain);
        DnsMessage result = await resolver.QueryBaselineAsync("example.com", DnsRecordType.A);

        result.Answers.Should().ContainSingle(r => r.Address != null && r.Address.Equals(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public async Task QueryBaselineAsync_DirectEncryptedFails_FallsBackToTlsFragmentedDoh()
    {
        DnsServerEntry directDoh = CreateEndpoint("direct-doh", DnsProtocol.DoH, "1.1.1.1");
        DnsServerEntry fragDoh = CreateEndpoint("frag-doh", DnsProtocol.DoH, "9.9.9.9");

        IDnsUpstreamClient mockDoh = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockFragDoh = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockDot = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockPlain = Substitute.For<IDnsUpstreamClient>();

        mockDoh.QueryAsync(Arg.Any<DnsMessage>(), directDoh, Arg.Any<CancellationToken>())
            .Returns<Task<UpstreamQueryResult>>(_ => throw new IOException("SNI DPI RST"));

        mockFragDoh.QueryAsync(Arg.Any<DnsMessage>(), fragDoh, Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                return Task.FromResult(CreateResult(q, IPAddress.Parse("104.16.132.229"), DnsProtocol.DoH));
            });

        BootstrapOptions options = new()
        {
            StaggerDelay = TimeSpan.FromMilliseconds(20),
            DirectEncryptedEndpoints = [directDoh],
            FragmentedDohEndpoints = [fragDoh],
            PlaintextFallbackEndpoints = []
        };

        await using EncryptedBootstrapResolver resolver = new(options, mockDoh, mockFragDoh, mockDot, mockPlain);
        IReadOnlyList<IPAddress> ips = await resolver.ResolveHostAsync("cloudflare.com");

        ips.Should().ContainSingle().Which.Should().Be(IPAddress.Parse("104.16.132.229"));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.10")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    public async Task QueryBaselineAsync_PlaintextReturnsBogonOrSinkhole_RejectsPoisonedResponse(string bogonIp)
    {
        DnsServerEntry plain = CreateEndpoint("plain-udp", DnsProtocol.Udp, "1.1.1.1");

        IDnsUpstreamClient mockDoh = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockFragDoh = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockDot = Substitute.For<IDnsUpstreamClient>();
        IDnsUpstreamClient mockPlain = Substitute.For<IDnsUpstreamClient>();

        mockPlain.QueryAsync(Arg.Any<DnsMessage>(), plain, Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                DnsMessage q = callInfo.Arg<DnsMessage>();
                return Task.FromResult(CreateResult(q, IPAddress.Parse(bogonIp), DnsProtocol.Udp));
            });

        BootstrapOptions options = new()
        {
            StaggerDelay = TimeSpan.FromMilliseconds(10),
            DirectEncryptedEndpoints = [],
            FragmentedDohEndpoints = [],
            PlaintextFallbackEndpoints = [plain]
        };

        await using EncryptedBootstrapResolver resolver = new(options, mockDoh, mockFragDoh, mockDot, mockPlain);
        Func<Task> act = () => resolver.QueryBaselineAsync("poisoned.example", DnsRecordType.A);

        await act.Should().ThrowAsync<AggregateException>();
    }

    [Fact]
    public async Task QueryBaselineAsync_LiveUdpAntiPoisoning_SkipsBogonServerAndAcceptsCleanServer()
    {
        using UdpClient poisonedUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        using UdpClient cleanUdp = new(new IPEndPoint(IPAddress.Loopback, 0));
        int poisonedPort = ((IPEndPoint)poisonedUdp.Client.LocalEndPoint!).Port;
        int cleanPort = ((IPEndPoint)cleanUdp.Client.LocalEndPoint!).Port;

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
        Task poisonedServer = Task.Run(async () =>
        {
            UdpReceiveResult req = await poisonedUdp.ReceiveAsync(cts.Token);
            DnsMessage parsed = DnsWireCodec.Parse(req.Buffer);
            DnsMessage resp = CreateResult(parsed, IPAddress.Parse("127.0.0.1"), DnsProtocol.Udp).Response;
            await poisonedUdp.SendAsync(DnsWireCodec.Serialize(resp), req.RemoteEndPoint, cts.Token);
        }, cts.Token);

        Task cleanServer = Task.Run(async () =>
        {
            UdpReceiveResult req = await cleanUdp.ReceiveAsync(cts.Token);
            DnsMessage parsed = DnsWireCodec.Parse(req.Buffer);
            DnsMessage resp = CreateResult(parsed, IPAddress.Parse("93.184.216.34"), DnsProtocol.Udp).Response;
            await cleanUdp.SendAsync(DnsWireCodec.Serialize(resp), req.RemoteEndPoint, cts.Token);
        }, cts.Token);

        BootstrapOptions options = new()
        {
            StaggerDelay = TimeSpan.FromMilliseconds(30),
            CandidateTimeout = TimeSpan.FromSeconds(3),
            QueryIpv6 = false,
            DirectEncryptedEndpoints = [],
            FragmentedDohEndpoints = [],
            PlaintextFallbackEndpoints =
            [
                new DnsServerEntry { Id = "poisoned", Name = "Poisoned", Protocol = DnsProtocol.Udp, PrimaryIp = "127.0.0.1", Port = poisonedPort },
                new DnsServerEntry { Id = "clean", Name = "Clean", Protocol = DnsProtocol.Udp, PrimaryIp = "127.0.0.1", Port = cleanPort }
            ]
        };

        await using EncryptedBootstrapResolver resolver = new(options);
        IReadOnlyList<IPAddress> resolved = await resolver.ResolveHostAsync("example.com", cts.Token);
        await Task.WhenAll(poisonedServer, cleanServer);

        resolved.Should().ContainSingle().Which.Should().Be(IPAddress.Parse("93.184.216.34"));
    }

    private static DnsServerEntry CreateEndpoint(string id, DnsProtocol protocol, string ip)
    {
        return new DnsServerEntry
        {
            Id = id,
            Name = id,
            Protocol = protocol,
            PrimaryIp = ip,
            Port = protocol == DnsProtocol.DoT ? 853 : protocol == DnsProtocol.Udp ? 53 : 443,
            DohUrl = protocol is DnsProtocol.DoH or DnsProtocol.DoH3 ? $"https://{ip}/dns-query" : null,
            DotHost = protocol == DnsProtocol.DoT ? ip : null
        };
    }

    private static UpstreamQueryResult CreateResult(DnsMessage query, IPAddress answerIp, DnsProtocol protocol)
    {
        DnsResourceRecord rr = answerIp.AddressFamily == AddressFamily.InterNetworkV6
            ? DnsResourceRecord.CreateAaaa(query.Questions[0].Name, answerIp)
            : DnsResourceRecord.CreateA(query.Questions[0].Name, answerIp);

        DnsMessage msg = new()
        {
            Header = new DnsHeader
            {
                Id = query.Header.Id,
                IsResponse = true,
                RecursionDesired = true,
                RecursionAvailable = true,
                QuestionCount = (ushort)query.Questions.Count,
                AnswerCount = 1
            },
            Questions = query.Questions,
            Answers = [rr]
        };

        return new UpstreamQueryResult(msg, TimeSpan.FromMilliseconds(2), answerIp.ToString(), protocol);
    }
}
