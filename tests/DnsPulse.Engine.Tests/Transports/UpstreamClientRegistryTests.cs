using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class UpstreamClientRegistryTests
{
    [Fact]
    public async Task CreateDefault_RegistersAllStandardAndEncryptedProtocols()
    {
        await using UpstreamClientRegistry registry = UpstreamClientRegistry.CreateDefault();

        DnsProtocol[] expectedProtocols =
        [
            DnsProtocol.Udp,
            DnsProtocol.Tcp,
            DnsProtocol.DoT,
            DnsProtocol.DoH,
            DnsProtocol.DoH3,
            DnsProtocol.DoQ,
            DnsProtocol.DnsCrypt,
            DnsProtocol.AnonymizedDnsCrypt,
            DnsProtocol.ODoH
        ];

        foreach (DnsProtocol protocol in expectedProtocols)
        {
            registry.TryGetClient(protocol, out IDnsUpstreamClient? client).Should().BeTrue();
            client!.Protocol.Should().Be(protocol);
        }

        Action unsupported = () => registry.GetClient(DnsProtocol.SniProxy);
        unsupported.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public async Task QueryAsync_DispatchesToMatchingProtocolClient()
    {
        IDnsUpstreamClient mockDoh = Substitute.For<IDnsUpstreamClient>();
        mockDoh.Protocol.Returns(DnsProtocol.DoH);

        DnsMessage query = DnsMessage.CreateQuery(100, "dispatch.example", DnsRecordType.A);
        DnsServerEntry server = new()
        {
            Id = "doh",
            Name = "Mock DoH",
            Protocol = DnsProtocol.DoH,
            DohUrl = "https://dns.example/dns-query"
        };

        UpstreamQueryResult expected = new(
            new DnsMessage
            {
                Header = new DnsHeader { Id = 100, IsResponse = true, QuestionCount = 1, AnswerCount = 1 },
                Questions = query.Questions,
                Answers = [DnsResourceRecord.CreateA("dispatch.example", IPAddress.Parse("93.184.216.34"))]
            },
            TimeSpan.FromMilliseconds(3),
            "https://dns.example/dns-query",
            DnsProtocol.DoH);

        mockDoh.QueryAsync(query, server, Arg.Any<CancellationToken>()).Returns(Task.FromResult(expected));

        using UpstreamClientRegistry registry = new([mockDoh]);
        UpstreamQueryResult actual = await registry.QueryAsync(query, server);

        actual.Should().Be(expected);
        await mockDoh.Received(1).QueryAsync(query, server, Arg.Any<CancellationToken>());
    }
}
