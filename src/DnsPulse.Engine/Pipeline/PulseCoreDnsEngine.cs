using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Security;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Pipeline;

/// <summary>
/// Central split-DNS resolution pipeline executing 4-zone routing, optimistic RFC 8767 caching,
/// trust-tier enforcement, DNS rebinding validation, SVCB/HTTPS rewriting, and in-memory telemetry.
/// </summary>
public sealed class PulseCoreDnsEngine : IPulseDnsResolver
{
    private readonly SplitNamespaceRouter _router;
    private readonly OptimisticDnsCache _cache;
    private readonly UpstreamPoolManager _poolManager;
    private readonly Func<DnsProtocol, IDnsUpstreamClient> _clientFactory;
    private readonly QueryTelemetryBuffer _telemetry;
    private PulseCoreEngineOptions _options;

    public PulseCoreDnsEngine(
        SplitNamespaceRouter router,
        OptimisticDnsCache cache,
        UpstreamPoolManager poolManager,
        Func<DnsProtocol, IDnsUpstreamClient> clientFactory,
        PulseCoreEngineOptions? options = null,
        QueryTelemetryBuffer? telemetry = null)
    {
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(poolManager);
        ArgumentNullException.ThrowIfNull(clientFactory);

        _router = router;
        _cache = cache;
        _poolManager = poolManager;
        _clientFactory = clientFactory;
        _options = options ?? new PulseCoreEngineOptions();
        _telemetry = telemetry ?? new QueryTelemetryBuffer(QueryTelemetryBuffer.DefaultCapacity, _options.TimeProvider);
    }

    public PulseCoreDnsEngine(
        SplitNamespaceRouter router,
        OptimisticDnsCache cache,
        UpstreamPoolManager poolManager,
        IReadOnlyDictionary<DnsProtocol, IDnsUpstreamClient> clients,
        PulseCoreEngineOptions? options = null,
        QueryTelemetryBuffer? telemetry = null)
        : this(
            router,
            cache,
            poolManager,
            CreateClientLookup(clients),
            options,
            telemetry)
    {
    }

    public QueryTelemetryBuffer Telemetry => _telemetry;

    /// <summary>
    /// Atomically swaps engine options (such as Zone 1 / Zone 3 upstreams or Zone 4 pool strategy).
    /// </summary>
    public void UpdateOptions(PulseCoreEngineOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Interlocked.Exchange(ref _options, options);
    }

    public async Task<DnsMessage> ResolveAsync(DnsMessage query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        cancellationToken.ThrowIfCancellationRequested();

        long startedAt = Stopwatch.GetTimestamp();
        PulseCoreEngineOptions options = Volatile.Read(ref _options);

        if (query.Questions.Count == 0)
        {
            DnsMessage formErr = CreateErrorResponse(query, DnsResponseCode.FormErr);
            RecordTelemetry(options, string.Empty, DnsRecordType.None, RouteZone.None, "Engine", DnsProtocol.Udp, startedAt, false, false, DnsResponseCode.FormErr, "EmptyQuestionSection");
            return formErr;
        }

        DnsQuestion question = query.Questions[0];
        string domain = question.Name;
        RouteDecision decision = string.IsNullOrWhiteSpace(domain)
            ? new RouteDecision(RouteZone.Zone4EncryptedTrusted, false, false, ".", null)
            : _router.Route(domain);

        // Zone 2: Blocklist sinkhole (NXDOMAIN or 0.0.0.0 / ::)
        if (decision.IsBlocked)
        {
            DnsMessage blocked = CreateBlockedResponse(query, question, options);
            RecordTelemetry(
                options,
                domain,
                question.RecordType,
                RouteZone.Zone2BlockOrProtect,
                "LocalBlock",
                DnsProtocol.Udp,
                startedAt,
                cacheHit: false,
                rewrittenSvcb: false,
                blocked.EffectiveResponseCode,
                string.Create(CultureInfo.InvariantCulture, $"Blocked:{decision.MatchedRule}"));
            return blocked;
        }

        // Security-pinned domains strictly force Zone 4 EncryptedTrusted.
        RouteZone effectiveZone = decision.IsSecurityPinned
            ? RouteZone.Zone4EncryptedTrusted
            : decision.Zone;

        DnsCacheKey cacheKey = new(domain, question.RecordType, effectiveZone);
        if (_cache.TryGetOrRefresh(
            cacheKey,
            ct => FetchAndCacheUpstreamAsync(query, question, decision, effectiveZone, options, cacheKey, ct),
            out CacheLookupResult cacheResult) && cacheResult.Message is not null)
        {
            DnsMessage adapted = AdaptResponseForQuery(cacheResult.Message, query);
            RecordTelemetry(
                options,
                domain,
                question.RecordType,
                effectiveZone,
                "Cache",
                DnsProtocol.Udp,
                startedAt,
                cacheHit: true,
                rewrittenSvcb: false,
                adapted.EffectiveResponseCode,
                cacheResult.Status == CacheLookupStatus.StaleHit ? "CacheStaleHit" : "CacheFreshHit");
            return adapted;
        }

        ResolutionResult resolution = await ResolveFromUpstreamAsync(
            query,
            question,
            decision,
            effectiveZone,
            options,
            cancellationToken).ConfigureAwait(false);

        if (resolution.Cacheable)
        {
            _cache.Set(cacheKey, resolution.Message);
        }

        DnsMessage finalResponse = AdaptResponseForQuery(resolution.Message, query);
        RecordTelemetry(
            options,
            domain,
            question.RecordType,
            effectiveZone,
            resolution.UpstreamName,
            resolution.Protocol,
            startedAt,
            cacheHit: false,
            resolution.RewrittenSvcb,
            finalResponse.EffectiveResponseCode,
            resolution.Note);

        return finalResponse;
    }

    private async Task<DnsMessage> FetchAndCacheUpstreamAsync(
        DnsMessage query,
        DnsQuestion question,
        RouteDecision decision,
        RouteZone effectiveZone,
        PulseCoreEngineOptions options,
        DnsCacheKey cacheKey,
        CancellationToken cancellationToken)
    {
        ResolutionResult result = await ResolveFromUpstreamAsync(
            query,
            question,
            decision,
            effectiveZone,
            options,
            cancellationToken).ConfigureAwait(false);

        if (result.Cacheable)
        {
            _cache.Set(cacheKey, result.Message);
        }

        return result.Message;
    }

    private async Task<ResolutionResult> ResolveFromUpstreamAsync(
        DnsMessage query,
        DnsQuestion question,
        RouteDecision decision,
        RouteZone effectiveZone,
        PulseCoreEngineOptions options,
        CancellationToken cancellationToken)
    {
        return effectiveZone switch
        {
            RouteZone.Zone1LocalBypass => await ResolveZone1Async(query, decision, options, cancellationToken).ConfigureAwait(false),
            RouteZone.Zone3GeoUnlock => await ResolveZone3Async(query, question, decision, options, cancellationToken).ConfigureAwait(false),
            _ => await ResolveZone4Async(query, decision, options, cancellationToken).ConfigureAwait(false)
        };
    }

    private async Task<ResolutionResult> ResolveZone1Async(
        DnsMessage query,
        RouteDecision decision,
        PulseCoreEngineOptions options,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<DnsServerEntry> candidates = SelectScopedCandidates(
            options.LocalBypassUpstreams,
            decision.TargetProfileId);

        if (candidates.Count == 0)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                "Zone1Local",
                DnsProtocol.Udp,
                RewrittenSvcb: false,
                Cacheable: false,
                "NoZone1Upstreams");
        }

        PoolExecutionResult outcome = await _poolManager.QueryPoolAsync(
            candidates,
            options.Zone1Strategy,
            (server, ct) => ExecuteUpstreamClientAsync(query, server, ct),
            responseValidator: null,
            enforceZone4TrustTier: false,
            cancellationToken).ConfigureAwait(false);

        if (!outcome.Succeeded || outcome.QueryResult is null || outcome.ServerUsed is null)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                outcome.ServerUsed?.Name ?? "Zone1Local",
                outcome.ServerUsed?.Protocol ?? DnsProtocol.Udp,
                RewrittenSvcb: false,
                Cacheable: false,
                outcome.Note);
        }

        return new ResolutionResult(
            outcome.QueryResult.Response,
            outcome.ServerUsed.Name,
            outcome.QueryResult.ProtocolUsed,
            RewrittenSvcb: false,
            Cacheable: true,
            "Zone1Resolved");
    }

    private async Task<ResolutionResult> ResolveZone3Async(
        DnsMessage query,
        DnsQuestion question,
        RouteDecision decision,
        PulseCoreEngineOptions options,
        CancellationToken cancellationToken)
    {
        List<DnsServerEntry> eligible = [];
        foreach (DnsServerEntry entry in SelectScopedCandidates(options.GeoUnlockUpstreams, decision.TargetProfileId))
        {
            if (TrustTierPolicy.CanServeGeoUnlock(entry.TrustTier) || TrustTierPolicy.CanServeDefaultInternet(entry.TrustTier, entry.Protocol))
            {
                eligible.Add(entry);
            }
        }

        if (eligible.Count == 0)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                "Zone3GeoUnlock",
                DnsProtocol.Udp,
                RewrittenSvcb: false,
                Cacheable: false,
                "NoZone3Upstreams");
        }

        // Check if the targeted GeoUnlock node is an SNI-Proxy synthesizing IPv4 A records directly.
        if (eligible[0].Protocol == DnsProtocol.SniProxy)
        {
            return ResolveSniProxy(query, question, eligible[0], options);
        }

        PoolExecutionResult outcome = await _poolManager.QueryPoolAsync(
            eligible,
            options.Zone3Strategy,
            (server, ct) => ExecuteUpstreamClientAsync(query, server, ct),
            (upstreamResult, _) => ValidateRebinding(RouteZone.Zone3GeoUnlock, upstreamResult.Response, options).IsSafe,
            enforceZone4TrustTier: false,
            cancellationToken).ConfigureAwait(false);

        if (!outcome.Succeeded || outcome.QueryResult is null || outcome.ServerUsed is null)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                outcome.ServerUsed?.Name ?? "Zone3GeoUnlock",
                outcome.ServerUsed?.Protocol ?? DnsProtocol.DoH,
                RewrittenSvcb: false,
                Cacheable: false,
                outcome.Note);
        }

        DnsRebindingValidationResult rebinding = ValidateRebinding(RouteZone.Zone3GeoUnlock, outcome.QueryResult.Response, options);
        if (!rebinding.IsSafe)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                outcome.ServerUsed.Name,
                outcome.QueryResult.ProtocolUsed,
                RewrittenSvcb: false,
                Cacheable: false,
                "RejectedDnsRebinding");
        }

        DnsMessage original = outcome.QueryResult.Response;
        DnsMessage rewritten = HttpsSvcbRouteRewriter.Rewrite(original, geoUnlockIpv4Only: true);
        bool svcbChanged = !ReferenceEquals(rewritten, original);

        return new ResolutionResult(
            rewritten,
            outcome.ServerUsed.Name,
            outcome.QueryResult.ProtocolUsed,
            RewrittenSvcb: svcbChanged,
            Cacheable: true,
            "Zone3SmartDnsResolved");
    }

    private static ResolutionResult ResolveSniProxy(
        DnsMessage query,
        DnsQuestion question,
        DnsServerEntry sniProxy,
        PulseCoreEngineOptions options)
    {
        string rawIp = !string.IsNullOrWhiteSpace(sniProxy.SmartProxyIp) ? sniProxy.SmartProxyIp : sniProxy.PrimaryIp;
        if (!IPAddress.TryParse(rawIp, out IPAddress? proxyIp) || proxyIp.AddressFamily != AddressFamily.InterNetwork)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                sniProxy.Name,
                DnsProtocol.SniProxy,
                RewrittenSvcb: false,
                Cacheable: false,
                "InvalidSniProxyIp");
        }

        if (question.RecordType == DnsRecordType.A)
        {
            DnsResourceRecord answer = DnsResourceRecord.CreateA(
                question.Name,
                proxyIp,
                options.SniProxySyntheticTtlSeconds);

            DnsMessage synthesized = new()
            {
                Header = new DnsHeader
                {
                    Id = query.Header.Id,
                    IsResponse = true,
                    RecursionDesired = query.Header.RecursionDesired,
                    RecursionAvailable = true,
                    ResponseCode = DnsResponseCode.NoError,
                    QuestionCount = (ushort)query.Questions.Count,
                    AnswerCount = 1
                },
                Questions = query.Questions,
                Answers = [answer]
            };

            return new ResolutionResult(
                synthesized,
                sniProxy.Name,
                DnsProtocol.SniProxy,
                RewrittenSvcb: false,
                Cacheable: true,
                "SniProxySynthesizedA");
        }

        // For AAAA, HTTPS (65), and SVCB (64), return clean NOERROR NODATA so clients route over IPv4 A to SNI-Proxy.
        DnsMessage noData = new()
        {
            Header = new DnsHeader
            {
                Id = query.Header.Id,
                IsResponse = true,
                RecursionDesired = query.Header.RecursionDesired,
                RecursionAvailable = true,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = (ushort)query.Questions.Count
            },
            Questions = query.Questions
        };

        bool stripped = question.RecordType is DnsRecordType.AAAA or DnsRecordType.HTTPS or DnsRecordType.SVCB;
        return new ResolutionResult(
            noData,
            sniProxy.Name,
            DnsProtocol.SniProxy,
            RewrittenSvcb: stripped,
            Cacheable: true,
            "SniProxyStrippedNoData");
    }

    private async Task<ResolutionResult> ResolveZone4Async(
        DnsMessage query,
        RouteDecision decision,
        PulseCoreEngineOptions options,
        CancellationToken cancellationToken)
    {
        PoolExecutionResult outcome = await _poolManager.QueryZone4Async(
            options.Zone4Strategy,
            (server, ct) => ExecuteUpstreamClientAsync(query, server, ct),
            (upstreamResult, _) => ValidateRebinding(RouteZone.Zone4EncryptedTrusted, upstreamResult.Response, options).IsSafe,
            cancellationToken).ConfigureAwait(false);

        if (!outcome.Succeeded || outcome.QueryResult is null || outcome.ServerUsed is null)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                outcome.ServerUsed?.Name ?? "Zone4Encrypted",
                outcome.ServerUsed?.Protocol ?? DnsProtocol.DoH,
                RewrittenSvcb: false,
                Cacheable: false,
                outcome.Note);
        }

        DnsRebindingValidationResult rebinding = ValidateRebinding(
            RouteZone.Zone4EncryptedTrusted,
            outcome.QueryResult.Response,
            options);

        if (!rebinding.IsSafe)
        {
            return new ResolutionResult(
                CreateErrorResponse(query, DnsResponseCode.ServFail),
                outcome.ServerUsed.Name,
                outcome.QueryResult.ProtocolUsed,
                RewrittenSvcb: false,
                Cacheable: false,
                "RejectedDnsRebinding");
        }

        // Zone 4 preserves HTTPS/SVCB and ECH intact.
        DnsMessage preserved = HttpsSvcbRouteRewriter.Rewrite(outcome.QueryResult.Response, geoUnlockIpv4Only: false);
        string note = decision.IsSecurityPinned ? "SecurityPinnedResolved" : "Zone4Resolved";

        return new ResolutionResult(
            preserved,
            outcome.ServerUsed.Name,
            outcome.QueryResult.ProtocolUsed,
            RewrittenSvcb: false,
            Cacheable: true,
            note);
    }

    private Task<UpstreamQueryResult> ExecuteUpstreamClientAsync(
        DnsMessage query,
        DnsServerEntry server,
        CancellationToken cancellationToken)
    {
        IDnsUpstreamClient client = _clientFactory(server.Protocol);
        return client.QueryAsync(query, server, cancellationToken);
    }

    private static DnsRebindingValidationResult ValidateRebinding(
        RouteZone zone,
        DnsMessage response,
        PulseCoreEngineOptions options)
    {
        List<IPAddress> addresses = [];
        CollectAddresses(response.Answers, addresses);
        CollectAddresses(response.Additionals, addresses);

        return DnsRebindingValidator.ValidateAnswer(
            zone,
            addresses,
            options.AllowCarrierAnycastExceptions,
            options.NamedCarrierEndpointId);
    }

    private static void CollectAddresses(IReadOnlyList<DnsResourceRecord> records, List<IPAddress> destination)
    {
        foreach (DnsResourceRecord record in records)
        {
            if (record.RecordType is DnsRecordType.A or DnsRecordType.AAAA && record.Address is not null)
            {
                destination.Add(record.Address);
            }
            else if (record.RecordType is DnsRecordType.HTTPS or DnsRecordType.SVCB)
            {
                foreach (SvcParam param in record.SvcParams)
                {
                    if (param.Key == (ushort)SvcParamKey.Ipv4Hint)
                    {
                        destination.AddRange(param.ParseIpv4Hints());
                    }
                    else if (param.Key == (ushort)SvcParamKey.Ipv6Hint)
                    {
                        destination.AddRange(param.ParseIpv6Hints());
                    }
                }
            }
        }
    }

    private static IReadOnlyList<DnsServerEntry> SelectScopedCandidates(
        IReadOnlyList<DnsServerEntry> configured,
        string? targetProfileId)
    {
        if (configured.Count == 0 || string.IsNullOrWhiteSpace(targetProfileId))
        {
            return configured;
        }

        List<DnsServerEntry> matched = [];
        foreach (DnsServerEntry entry in configured)
        {
            if (string.Equals(entry.Id, targetProfileId, StringComparison.OrdinalIgnoreCase))
            {
                matched.Add(entry);
            }
        }

        return matched.Count > 0 ? matched : configured;
    }

    private static DnsMessage CreateBlockedResponse(
        DnsMessage query,
        DnsQuestion question,
        PulseCoreEngineOptions options)
    {
        if (options.BlockMode == BlockResponseMode.NullIp)
        {
            List<DnsResourceRecord> answers = [];
            if (question.RecordType == DnsRecordType.A)
            {
                answers.Add(DnsResourceRecord.CreateA(question.Name, IPAddress.Any, options.BlockNullIpTtlSeconds));
            }
            else if (question.RecordType == DnsRecordType.AAAA)
            {
                answers.Add(DnsResourceRecord.CreateAaaa(question.Name, IPAddress.IPv6None, options.BlockNullIpTtlSeconds));
            }

            return new DnsMessage
            {
                Header = new DnsHeader
                {
                    Id = query.Header.Id,
                    IsResponse = true,
                    RecursionDesired = query.Header.RecursionDesired,
                    RecursionAvailable = true,
                    ResponseCode = DnsResponseCode.NoError,
                    QuestionCount = (ushort)query.Questions.Count,
                    AnswerCount = (ushort)answers.Count
                },
                Questions = query.Questions,
                Answers = answers
            };
        }

        return CreateErrorResponse(query, DnsResponseCode.NxDomain);
    }

    private static DnsMessage CreateErrorResponse(DnsMessage query, DnsResponseCode responseCode)
    {
        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = query.Header.Id,
                IsResponse = true,
                OpCode = query.Header.OpCode,
                RecursionDesired = query.Header.RecursionDesired,
                RecursionAvailable = true,
                ResponseCode = responseCode,
                QuestionCount = (ushort)query.Questions.Count
            },
            Questions = query.Questions
        };
    }

    private static DnsMessage AdaptResponseForQuery(DnsMessage response, DnsMessage query)
    {
        return response with
        {
            Header = response.Header with
            {
                Id = query.Header.Id,
                IsResponse = true,
                OpCode = query.Header.OpCode,
                RecursionDesired = query.Header.RecursionDesired,
                RecursionAvailable = true,
                QuestionCount = (ushort)query.Questions.Count,
                AnswerCount = (ushort)response.Answers.Count,
                AuthorityCount = (ushort)response.Authorities.Count,
                AdditionalCount = (ushort)response.Additionals.Count
            },
            Questions = query.Questions
        };
    }

    private void RecordTelemetry(
        PulseCoreEngineOptions options,
        string domain,
        DnsRecordType recordType,
        RouteZone zone,
        string upstreamName,
        DnsProtocol protocol,
        long startedAtTimestamp,
        bool cacheHit,
        bool rewrittenSvcb,
        DnsResponseCode responseCode,
        string decisionNote)
    {
        double elapsedMs = Stopwatch.GetElapsedTime(startedAtTimestamp).TotalMilliseconds;
        _telemetry.Record(new DnsQueryTelemetryEvent(
            options.TimeProvider.GetUtcNow(),
            domain,
            recordType,
            zone,
            upstreamName,
            protocol,
            elapsedMs,
            cacheHit,
            rewrittenSvcb,
            responseCode,
            decisionNote));
    }

    private static Func<DnsProtocol, IDnsUpstreamClient> CreateClientLookup(
        IReadOnlyDictionary<DnsProtocol, IDnsUpstreamClient> clients)
    {
        ArgumentNullException.ThrowIfNull(clients);
        return protocol =>
        {
            if (clients.TryGetValue(protocol, out IDnsUpstreamClient? client))
            {
                return client;
            }

            throw new InvalidOperationException(
                string.Create(CultureInfo.InvariantCulture, $"No upstream transport client registered for protocol '{protocol}'."));
        };
    }

    private sealed record ResolutionResult(
        DnsMessage Message,
        string UpstreamName,
        DnsProtocol Protocol,
        bool RewrittenSvcb,
        bool Cacheable,
        string Note);
}
