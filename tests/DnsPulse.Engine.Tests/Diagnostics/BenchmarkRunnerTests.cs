using System.Net;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.Engine.Tests.Diagnostics;

public sealed class BenchmarkRunnerTests
{
    private static readonly IPAddress PublicIp = IPAddress.Parse("93.184.216.34");

    [Fact]
    public async Task RunAsync_ConcurrentPool_UpdatesP50P95AndVerdicts()
    {
        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        bootstrap.QueryBaselineAsync(Arg.Any<string>(), Arg.Any<DnsRecordType>(), Arg.Any<CancellationToken>())
            .Returns(callInfo => BuildResponse(1, callInfo.ArgAt<string>(0), PublicIp, DnsResponseCode.NoError));

        IDnsUpstreamClient client = Substitute.For<IDnsUpstreamClient>();
        client.Protocol.Returns(DnsProtocol.DoH);
        client.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(async callInfo =>
            {
                DnsMessage query = callInfo.ArgAt<DnsMessage>(0);
                DnsServerEntry server = callInfo.ArgAt<DnsServerEntry>(1);
                await Task.Delay(5, callInfo.ArgAt<CancellationToken>(2)).ConfigureAwait(false);
                double latencyMs = server.Id == "fast" ? 10.0 : 42.0;
                IPAddress answer = server.Id == "poisoned" ? IPAddress.Parse("127.0.0.1") : PublicIp;
                DnsMessage resp = BuildResponse(query.Header.Id, query.Questions[0].Name, answer, DnsResponseCode.NoError);
                return new UpstreamQueryResult(resp, TimeSpan.FromMilliseconds(latencyMs), "mock://doh", DnsProtocol.DoH);
            });

        BenchmarkRunner runner = new(bootstrap, _ => client);
        IReadOnlyList<DnsServerEntry> input =
        [
            CreateServer("fast", "Fast DoH"),
            CreateServer("slow", "Slow DoH"),
            CreateServer("poisoned", "Poisoned DoH")
        ];

        List<BenchmarkProgressUpdate> updates = [];
        IProgress<BenchmarkProgressUpdate> progress = new SyncProgress(updates.Add);

        IReadOnlyList<DnsServerEntry> output = await runner.RunAsync(
            input,
            "example.com",
            new BenchmarkOptions
            {
                MaxConcurrency = 2,
                SamplesPerServer = 3,
                RunFullSixLayerDiagnostics = false
            },
            progress);

        output.Should().HaveCount(3);
        updates.Should().HaveCount(3);

        output[0].Verdict.Should().Be(DiagnosticVerdict.Healthy);
        output[0].LatencyP50Ms.Should().BeApproximately(10.0, 0.5);
        output[0].LatencyP95Ms.Should().BeApproximately(10.0, 0.5);
        output[0].SuccessRatePercent.Should().Be(100);
        output[0].HistoryMs.Should().ContainSingle().Which.Should().Be(10);

        output[1].Verdict.Should().Be(DiagnosticVerdict.Healthy);
        output[1].LatencyP50Ms.Should().BeApproximately(42.0, 0.5);

        output[2].Verdict.Should().Be(DiagnosticVerdict.DnsPoisoned);
    }

    [Fact]
    public async Task StreamAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        bootstrap.QueryBaselineAsync(Arg.Any<string>(), Arg.Any<DnsRecordType>(), Arg.Any<CancellationToken>())
            .Returns(callInfo => BuildResponse(1, callInfo.ArgAt<string>(0), PublicIp, DnsResponseCode.NoError));

        IDnsUpstreamClient client = Substitute.For<IDnsUpstreamClient>();
        client.QueryAsync(Arg.Any<DnsMessage>(), Arg.Any<DnsServerEntry>(), Arg.Any<CancellationToken>())
            .Returns(async callInfo =>
            {
                await Task.Delay(500, callInfo.ArgAt<CancellationToken>(2)).ConfigureAwait(false);
                DnsMessage query = callInfo.ArgAt<DnsMessage>(0);
                return new UpstreamQueryResult(
                    BuildResponse(query.Header.Id, query.Questions[0].Name, PublicIp, DnsResponseCode.NoError),
                    TimeSpan.FromMilliseconds(500),
                    "mock://doh",
                    DnsProtocol.DoH);
            });

        BenchmarkRunner runner = new(bootstrap, _ => client);
        using CancellationTokenSource cts = new(TimeSpan.FromMilliseconds(40));

        Func<Task> act = async () =>
        {
            await foreach (BenchmarkProgressUpdate _ in runner.StreamAsync(
                [CreateServer("s1", "S1"), CreateServer("s2", "S2")],
                "example.com",
                new BenchmarkOptions { MaxConcurrency = 1, SamplesPerServer = 2 },
                cts.Token))
            {
            }
        };

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private static DnsServerEntry CreateServer(string id, string name)
    {
        return new DnsServerEntry
        {
            Id = id,
            Name = name,
            Provider = "Test",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            PrimaryIp = "1.1.1.1",
            DohUrl = "https://cloudflare-dns.com/dns-query"
        };
    }

    private static DnsMessage BuildResponse(ushort id, string domain, IPAddress ip, DnsResponseCode rcode)
    {
        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = id,
                IsResponse = true,
                ResponseCode = rcode,
                QuestionCount = 1,
                AnswerCount = 1
            },
            Questions = [DnsQuestion.Create(domain, DnsRecordType.A)],
            Answers = [DnsResourceRecord.CreateA(domain, ip)]
        };
    }

    private sealed class SyncProgress(Action<BenchmarkProgressUpdate> callback) : IProgress<BenchmarkProgressUpdate>
    {
        public void Report(BenchmarkProgressUpdate value)
        {
            callback(value);
        }
    }
}
