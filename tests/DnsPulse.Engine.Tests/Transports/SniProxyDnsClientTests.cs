using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Transports;

public sealed class SniProxyDnsClientTests
{
    [Fact]
    public async Task QueryAsync_SynthesizesAWith45sTtlAndEmptyNoErrorForAaaaHttpsSvcb()
    {
        IPEndPoint? probedEndpoint = null;
        SniProxyDnsClient client = new(
            new TransportOptions { Timeout = TimeSpan.FromSeconds(2) },
            (endpoint, _) =>
            {
                probedEndpoint = endpoint;
                return Task.CompletedTask;
            });

        DnsServerEntry upstream = new()
        {
            Id = "sni_1",
            Name = "GeoHide Node #1",
            Protocol = DnsProtocol.SniProxy,
            TrustTier = TrustTier.Tier4ExperimentalLab,
            PrimaryIp = "192.255.159.240",
            SmartProxyIp = "192.255.159.240",
            DohUrl = "smartproxy://192.255.159.240:443",
            SupportsBypass = true
        };

        UpstreamQueryResult aResult = await client.QueryAsync(
            DnsMessage.CreateQuery(10, "aistudio.google.com", DnsRecordType.A),
            upstream);

        probedEndpoint.Should().Be(new IPEndPoint(IPAddress.Parse("192.255.159.240"), 443));
        aResult.ProtocolUsed.Should().Be(DnsProtocol.SniProxy);
        aResult.Response.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
        aResult.Response.Answers.Should().ContainSingle(r =>
            r.RecordType == DnsRecordType.A &&
            Equals(r.Address, IPAddress.Parse("192.255.159.240")) &&
            r.TimeToLive == 45u);

        foreach (DnsRecordType stripType in new[] { DnsRecordType.AAAA, DnsRecordType.HTTPS, DnsRecordType.SVCB })
        {
            UpstreamQueryResult stripped = await client.QueryAsync(
                DnsMessage.CreateQuery(11, "aistudio.google.com", stripType),
                upstream);
            stripped.Response.EffectiveResponseCode.Should().Be(DnsResponseCode.NoError);
            stripped.Response.Answers.Should().BeEmpty();
        }
    }

    [Fact]
    public async Task QueryAsync_RejectsLoopbackOrPrivateSmartProxyIpByDefault()
    {
        SniProxyDnsClient client = new(
            new TransportOptions(),
            (_, _) => Task.CompletedTask);

        DnsServerEntry loopbackProxy = new()
        {
            Id = "sni_bad",
            Name = "Loopback SNI",
            Protocol = DnsProtocol.SniProxy,
            PrimaryIp = "127.0.0.1",
            SmartProxyIp = "127.0.0.1"
        };

        Func<Task> act = async () => await client.QueryAsync(
            DnsMessage.CreateQuery(12, "gemini.google.com", DnsRecordType.A),
            loopbackProxy);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }
}
