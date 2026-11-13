using System.Diagnostics;
using System.Net;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Cache;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Cache;

public sealed class OptimisticDnsCacheTests
{
    [Fact]
    public void TryGetOrRefresh_FreshEntry_ReturnsSubMillisecondHitWithDecrementedTtl()
    {
        ManualTimeProvider clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using OptimisticDnsCache cache = new(new OptimisticCacheOptions
        {
            MinTtl = TimeSpan.FromSeconds(5),
            MaxTtl = TimeSpan.FromHours(1),
            ServeStaleGrace = TimeSpan.FromMinutes(10),
            TimeProvider = clock
        });

        DnsCacheKey key = new("example.com.", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        DnsMessage upstreamResponse = CreateAResponse(100, "example.com", "93.184.216.34", ttl: 120);
        cache.Set(key, upstreamResponse).Should().BeTrue();

        clock.Advance(TimeSpan.FromSeconds(45));

        int refreshCalls = 0;
        Stopwatch sw = Stopwatch.StartNew();
        bool found = cache.TryGetOrRefresh(
            key,
            _ =>
            {
                Interlocked.Increment(ref refreshCalls);
                return Task.FromResult(upstreamResponse);
            },
            out CacheLookupResult result);
        sw.Stop();

        found.Should().BeTrue();
        result.Status.Should().Be(CacheLookupStatus.FreshHit);
        result.RefreshTriggered.Should().BeFalse();
        result.Message.Should().NotBeNull();
        result.Message!.Answers.Should().ContainSingle();
        result.Message.Answers[0].TimeToLive.Should().Be(75u);
        sw.ElapsedMilliseconds.Should().BeLessThan(10);
        refreshCalls.Should().Be(0);
        cache.TotalHits.Should().Be(1);
        cache.StaleHits.Should().Be(0);
        cache.TotalMisses.Should().Be(0);
        cache.HitRatePercent.Should().Be(100.0);
    }

    [Fact]
    public async Task TryGetOrRefresh_ExpiredWithinStaleGrace_ServesStaleImmediatelyAndDeduplicatesRefresh()
    {
        ManualTimeProvider clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using OptimisticDnsCache cache = new(new OptimisticCacheOptions
        {
            MinTtl = TimeSpan.FromSeconds(5),
            MaxTtl = TimeSpan.FromHours(1),
            ServeStaleGrace = TimeSpan.FromMinutes(30),
            StaleResponseTtlSeconds = 30,
            TimeProvider = clock
        });

        DnsCacheKey key = new("api.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        DnsMessage initial = CreateAResponse(1, "api.example.com", "1.1.1.1", ttl: 60);
        DnsMessage refreshed = CreateAResponse(2, "api.example.com", "8.8.8.8", ttl: 180);
        cache.Set(key, initial).Should().BeTrue();

        // Advance past 60s fresh TTL, but inside 30m ServeStaleGrace.
        clock.Advance(TimeSpan.FromSeconds(90));

        TaskCompletionSource<DnsMessage> refreshGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int refreshCount = 0;

        bool hit1 = cache.TryGetOrRefresh(
            key,
            async _ =>
            {
                Interlocked.Increment(ref refreshCount);
                return await refreshGate.Task.ConfigureAwait(false);
            },
            out CacheLookupResult staleResult1);

        bool hit2 = cache.TryGetOrRefresh(
            key,
            _ =>
            {
                Interlocked.Increment(ref refreshCount);
                return Task.FromResult(refreshed);
            },
            out CacheLookupResult staleResult2);

        hit1.Should().BeTrue();
        hit2.Should().BeTrue();
        staleResult1.Status.Should().Be(CacheLookupStatus.StaleHit);
        staleResult1.RefreshTriggered.Should().BeTrue();
        staleResult1.Message!.Answers[0].Address.Should().Be(IPAddress.Parse("1.1.1.1"));
        staleResult1.Message.Answers[0].TimeToLive.Should().Be(30u);

        staleResult2.Status.Should().Be(CacheLookupStatus.StaleHit);
        staleResult2.RefreshTriggered.Should().BeFalse();

        // Complete the single-flight refresh and await completion.
        refreshGate.SetResult(refreshed);
        await cache.WaitForPendingRefreshesAsync();

        refreshCount.Should().Be(1);
        cache.TotalHits.Should().Be(2);
        cache.StaleHits.Should().Be(2);

        bool hit3 = cache.TryGet(key, out CacheLookupResult freshAfterRefresh);
        hit3.Should().BeTrue();
        freshAfterRefresh.Status.Should().Be(CacheLookupStatus.FreshHit);
        freshAfterRefresh.Message!.Answers[0].Address.Should().Be(IPAddress.Parse("8.8.8.8"));
    }

    [Fact]
    public async Task TryGetOrRefresh_StaleRefreshFailsWithServFail_PreservesStaleEntry()
    {
        ManualTimeProvider clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using OptimisticDnsCache cache = new(new OptimisticCacheOptions
        {
            MinTtl = TimeSpan.FromSeconds(5),
            MaxTtl = TimeSpan.FromHours(1),
            ServeStaleGrace = TimeSpan.FromMinutes(10),
            TimeProvider = clock
        });

        DnsCacheKey key = new("resilient.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        cache.Set(key, CreateAResponse(1, "resilient.example.com", "93.184.216.34", ttl: 30)).Should().BeTrue();

        clock.Advance(TimeSpan.FromSeconds(45));

        DnsMessage servFail = new()
        {
            Header = new DnsHeader
            {
                Id = 1,
                IsResponse = true,
                ResponseCode = DnsResponseCode.ServFail
            }
        };

        bool hit = cache.TryGetOrRefresh(key, _ => Task.FromResult(servFail), out CacheLookupResult staleResult);
        hit.Should().BeTrue();
        staleResult.Status.Should().Be(CacheLookupStatus.StaleHit);

        await cache.WaitForPendingRefreshesAsync();

        bool stillCached = cache.TryGet(key, out CacheLookupResult stillStale);
        stillCached.Should().BeTrue();
        stillStale.Status.Should().Be(CacheLookupStatus.StaleHit);
        stillStale.Message!.Answers[0].Address.Should().Be(IPAddress.Parse("93.184.216.34"));
    }

    [Fact]
    public void TryGet_ExpiredPastGrace_MissesAndEvicts()
    {
        ManualTimeProvider clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using OptimisticDnsCache cache = new(new OptimisticCacheOptions
        {
            MinTtl = TimeSpan.FromSeconds(5),
            MaxTtl = TimeSpan.FromHours(1),
            ServeStaleGrace = TimeSpan.FromSeconds(60),
            TimeProvider = clock
        });

        DnsCacheKey key = new("expired.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        cache.Set(key, CreateAResponse(1, "expired.example.com", "93.184.216.34", ttl: 30)).Should().BeTrue();

        clock.Advance(TimeSpan.FromSeconds(91));

        bool found = cache.TryGet(key, out CacheLookupResult result);
        found.Should().BeFalse();
        result.Status.Should().Be(CacheLookupStatus.Miss);
        result.Message.Should().BeNull();
        cache.Count.Should().Be(0);
        cache.TotalMisses.Should().Be(1);
    }

    [Theory]
    [InlineData(DnsResponseCode.ServFail)]
    [InlineData(DnsResponseCode.Refused)]
    [InlineData(DnsResponseCode.FormErr)]
    public void Set_ErrorResponsesAndZeroTtl_AreNotCached(DnsResponseCode rcode)
    {
        using OptimisticDnsCache cache = new();
        DnsCacheKey key = new("nocache.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);

        DnsMessage errorResponse = new()
        {
            Header = new DnsHeader
            {
                Id = 1,
                IsResponse = true,
                ResponseCode = rcode
            }
        };

        cache.Set(key, errorResponse).Should().BeFalse();

        DnsMessage zeroTtl = CreateAResponse(1, "nocache.example.com", "93.184.216.34", ttl: 0);
        cache.Set(key, zeroTtl).Should().BeFalse();
        cache.Count.Should().Be(0);
    }

    [Fact]
    public void Set_NxDomainWithSoaMinimum_IsNegativelyCached()
    {
        ManualTimeProvider clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using OptimisticDnsCache cache = new(new OptimisticCacheOptions
        {
            MinTtl = TimeSpan.FromSeconds(5),
            MaxTtl = TimeSpan.FromHours(1),
            ServeStaleGrace = TimeSpan.FromMinutes(5),
            TimeProvider = clock
        });

        DnsCacheKey key = new("missing.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        DnsMessage nxDomain = new()
        {
            Header = new DnsHeader
            {
                Id = 7,
                IsResponse = true,
                ResponseCode = DnsResponseCode.NxDomain,
                QuestionCount = 1,
                AuthorityCount = 1
            },
            Questions = [DnsQuestion.Create("missing.example.com", DnsRecordType.A)],
            Authorities = [DnsResourceRecord.CreateSoa("example.com", "ns1.example.com", "hostmaster.example.com", 1, 3600, 900, 86400, minimum: 45, ttl: 120)]
        };

        cache.Set(key, nxDomain).Should().BeTrue();

        clock.Advance(TimeSpan.FromSeconds(20));
        cache.TryGet(key, out CacheLookupResult freshHit).Should().BeTrue();
        freshHit.Status.Should().Be(CacheLookupStatus.FreshHit);
        freshHit.Message!.EffectiveResponseCode.Should().Be(DnsResponseCode.NxDomain);

        clock.Advance(TimeSpan.FromSeconds(30));
        cache.TryGet(key, out CacheLookupResult staleHit).Should().BeTrue();
        staleHit.Status.Should().Be(CacheLookupStatus.StaleHit);
    }

    [Fact]
    public void Set_ExceedingMaxEntries_EvictsLeastRecentlyUsed()
    {
        using OptimisticDnsCache cache = new(new OptimisticCacheOptions
        {
            MaxEntries = 2
        });

        DnsCacheKey k1 = new("one.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        DnsCacheKey k2 = new("two.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);
        DnsCacheKey k3 = new("three.example.com", DnsRecordType.A, RouteZone.Zone4EncryptedTrusted);

        cache.Set(k1, CreateAResponse(1, "one.example.com", "1.1.1.1", 60)).Should().BeTrue();
        cache.Set(k2, CreateAResponse(2, "two.example.com", "2.2.2.2", 60)).Should().BeTrue();

        // Touch k1 so k2 becomes LRU.
        cache.TryGet(k1, out _).Should().BeTrue();

        cache.Set(k3, CreateAResponse(3, "three.example.com", "3.3.3.3", 60)).Should().BeTrue();

        cache.Count.Should().Be(2);
        cache.TryGet(k1, out _).Should().BeTrue();
        cache.TryGet(k2, out _).Should().BeFalse();
        cache.TryGet(k3, out _).Should().BeTrue();
    }

    private static DnsMessage CreateAResponse(ushort id, string domain, string ip, uint ttl)
    {
        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = id,
                IsResponse = true,
                RecursionDesired = true,
                RecursionAvailable = true,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = 1,
                AnswerCount = 1
            },
            Questions = [DnsQuestion.Create(domain, DnsRecordType.A)],
            Answers = [DnsResourceRecord.CreateA(domain, IPAddress.Parse(ip), ttl)]
        };
    }

    private sealed class ManualTimeProvider(DateTimeOffset initialUtc) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtc;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan delta)
        {
            _utcNow = _utcNow.Add(delta);
        }
    }
}
