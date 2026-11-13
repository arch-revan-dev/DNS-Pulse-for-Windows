using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Pipeline;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Pipeline;

public sealed class QueryTelemetryBufferTests
{
    [Fact]
    public void Record_BoundedRingBuffer_EvictsOldestAndComputesMetrics()
    {
        ManualTimeProvider clock = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        QueryTelemetryBuffer buffer = new(capacity: 3, timeProvider: clock);

        buffer.Record(CreateEvent(clock.GetUtcNow().AddMinutes(-2), "old.example", 100.0));
        buffer.Record(CreateEvent(clock.GetUtcNow().AddSeconds(-30), "a.example", 10.0));
        buffer.Record(CreateEvent(clock.GetUtcNow().AddSeconds(-20), "b.example", 20.0));
        buffer.Record(CreateEvent(clock.GetUtcNow().AddSeconds(-10), "c.example", 50.0));

        buffer.Count.Should().Be(3);
        buffer.TotalRecordedCount.Should().Be(4);
        buffer.QueriesPerMinute.Should().Be(3.0);
        buffer.P50LatencyMs.Should().Be(20.0);

        IReadOnlyList<DnsQueryTelemetryEvent> recent = buffer.GetRecentEvents(2);
        recent.Select(e => e.Domain).Should().ContainInOrder("c.example", "b.example");
    }

    private static DnsQueryTelemetryEvent CreateEvent(DateTimeOffset timestampUtc, string domain, double latencyMs)
    {
        return new DnsQueryTelemetryEvent(
            timestampUtc,
            domain,
            DnsRecordType.A,
            RouteZone.Zone4EncryptedTrusted,
            "Cloudflare",
            DnsProtocol.DoH,
            latencyMs,
            CacheHit: false,
            RewrittenSvcb: false,
            DnsResponseCode.NoError,
            "Resolved");
    }

    private sealed class ManualTimeProvider(DateTimeOffset initialUtc) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => initialUtc;
    }
}
