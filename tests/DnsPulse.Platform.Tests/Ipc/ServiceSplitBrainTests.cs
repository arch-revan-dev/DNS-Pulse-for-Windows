using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Ipc;
using DnsPulse.Service;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Ipc;

public sealed class ServiceSplitBrainTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private static readonly IPAddress Zone3AnswerIp = IPAddress.Parse("151.101.1.69");
    private static readonly IPAddress Zone3SecondaryIp = IPAddress.Parse("185.199.108.153");
    private static readonly IPAddress Zone4AnswerIp = IPAddress.Parse("93.184.216.34");

    [Fact]
    public async Task Connect_WithFullServiceConnectRequest_ResolvesZone3AndZone4OverUdpAndSetsPacUrl()
    {
        string pipeName = CreateUniquePipeName();
        RecordingUpstreamClient upstreamClient = new(new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase)
        {
            ["z3-primary"] = Zone3AnswerIp,
            ["z4-trusted"] = Zone4AnswerIp
        });

        List<(InterceptionMode Mode, string? PacUrl, IReadOnlyList<string> SplitDomains)> activations = [];

        SplitNamespaceRouter router = new();
        OptimisticDnsCache cache = new();
        UpstreamPoolManager poolManager = new();
        PulseCoreDnsEngine engine = new(router, cache, poolManager, _ => upstreamClient);

        PulseServiceOptions serviceOptions = new()
        {
            PipeName = pipeName,
            DnsPort = 0,
            DohPort = 0,
            ProxyPort = 0,
            PacPort = 0,
            EnableDohListener = false,
            EnableSidecarProxy = true,
            InterceptionMode = InterceptionMode.AdapterDns,
            HealthCheckInterval = TimeSpan.FromSeconds(10),
            UnhealthyRollbackThreshold = TimeSpan.FromSeconds(30)
        };

        using DefaultPulseRuntimeBackend backend = new(
            serviceOptions,
            engine,
            cache,
            poolManager,
            router: router,
            interceptorFactory: (mode, pacUrl, _) => new RecordingInterceptor(mode, pacUrl, activations));

        using DnsPulseWorkerService worker = new(backend, serviceOptions);
        await worker.StartAsync(CancellationToken.None);

        try
        {
            await WaitForIpcReadyAsync(pipeName);
            PulsePipeIpcClient client = new(pipeName, TimeSpan.FromSeconds(5));

            ServiceConnectRequest connectRequest = CreateSampleConnectRequest(
                InterceptionMode.LocalProxyPacOnly,
                "z3-primary",
                Zone3AnswerIp);

            PipeRpcResponse connectResp = await client.SendAsync(new PipeRpcRequest(
                Guid.NewGuid().ToString("N"),
                PipeCommandNames.Connect,
                JsonSerializer.Serialize(connectRequest, JsonOptions)));

            connectResp.Success.Should().BeTrue(connectResp.ErrorMessage);
            ServiceStatusSnapshot? connected = JsonSerializer.Deserialize<ServiceStatusSnapshot>(connectResp.PayloadJson!, JsonOptions);
            connected.Should().NotBeNull();
            connected!.IsConnected.Should().BeTrue();
            connected.RequestedMode.Should().Be(InterceptionMode.LocalProxyPacOnly);
            connected.ActiveMode.Should().Be(InterceptionMode.LocalProxyPacOnly);
            connected.InterceptionActive.Should().BeTrue();
            connected.BoundDnsPort.Should().BeGreaterThan(0);
            connected.BoundProxyPort.Should().BeGreaterThan(0);
            connected.BoundPacPort.Should().BeGreaterThan(0);
            connected.PacUrl.Should().Be($"http://{serviceOptions.SidecarLoopbackAddress}:{connected.BoundPacPort}/proxy.pac");
            connected.ActiveUpstreamsCount.Should().Be(1);
            connected.ActiveGeoUnlockUpstreamId.Should().Be("z3-primary");
            connected.ActiveTrustedUpstreamId.Should().Be("z4-trusted");
            connected.ActiveGeoUnlockRulesCount.Should().BeGreaterThanOrEqualTo(2);

            activations.Should().ContainSingle();
            activations[0].Mode.Should().Be(InterceptionMode.LocalProxyPacOnly);
            activations[0].PacUrl.Should().Be(connected.PacUrl);

            IPAddress dnsIp = IPAddress.Parse(connected.ActiveLoopbackIp!);

            // Live UDP DNS query for Zone 3 domain must hit z3-primary, NOT ServFail or bootstrap
            DnsMessage zone3Reply = await QueryLocalDnsUdpAsync(dnsIp, connected.BoundDnsPort, "chatgpt.com");
            zone3Reply.Header.ResponseCode.Should().Be(DnsResponseCode.NoError);
            zone3Reply.Answers.Should().Contain(a => Equals(a.Address, Zone3AnswerIp));

            // Live UDP DNS query for Zone 4 domain must hit z4-trusted
            DnsMessage zone4Reply = await QueryLocalDnsUdpAsync(dnsIp, connected.BoundDnsPort, "example.org");
            zone4Reply.Header.ResponseCode.Should().Be(DnsResponseCode.NoError);
            zone4Reply.Answers.Should().Contain(a => Equals(a.Address, Zone4AnswerIp));

            upstreamClient.QueriedUpstreamIds.Should().Contain("z3-primary");
            upstreamClient.QueriedUpstreamIds.Should().Contain("z4-trusted");
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task LiveIpcUpdates_UpdateRoutingConfigPoolAndBlocklist_ApplyWhileConnected()
    {
        string pipeName = CreateUniquePipeName();
        RecordingUpstreamClient upstreamClient = new(new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase)
        {
            ["z3-primary"] = Zone3AnswerIp,
            ["z3-secondary"] = Zone3SecondaryIp,
            ["z4-trusted"] = Zone4AnswerIp
        });

        List<(InterceptionMode Mode, string? PacUrl, IReadOnlyList<string> SplitDomains)> activations = [];
        SplitNamespaceRouter router = new();
        OptimisticDnsCache cache = new();
        UpstreamPoolManager poolManager = new();
        PulseCoreDnsEngine engine = new(router, cache, poolManager, _ => upstreamClient);

        PulseServiceOptions serviceOptions = new()
        {
            PipeName = pipeName,
            DnsPort = 0,
            DohPort = 0,
            ProxyPort = 0,
            PacPort = 0,
            EnableDohListener = false,
            EnableSidecarProxy = true,
            HealthCheckInterval = TimeSpan.FromSeconds(10),
            UnhealthyRollbackThreshold = TimeSpan.FromSeconds(30)
        };

        using DefaultPulseRuntimeBackend backend = new(
            serviceOptions,
            engine,
            cache,
            poolManager,
            router: router,
            interceptorFactory: (mode, pacUrl, _) => new RecordingInterceptor(mode, pacUrl, activations));

        using DnsPulseWorkerService worker = new(backend, serviceOptions);
        await worker.StartAsync(CancellationToken.None);

        try
        {
            await WaitForIpcReadyAsync(pipeName);
            PulsePipeIpcClient client = new(pipeName, TimeSpan.FromSeconds(5));

            ServiceConnectRequest initialConnect = CreateSampleConnectRequest(
                InterceptionMode.LocalProxyPacOnly,
                "z3-primary",
                Zone3AnswerIp);

            PipeRpcResponse connectResp = await client.SendAsync(new PipeRpcRequest(
                Guid.NewGuid().ToString("N"),
                PipeCommandNames.Connect,
                JsonSerializer.Serialize(initialConnect, JsonOptions)));
            connectResp.Success.Should().BeTrue(connectResp.ErrorMessage);
            ServiceStatusSnapshot connected = JsonSerializer.Deserialize<ServiceStatusSnapshot>(connectResp.PayloadJson!, JsonOptions)!;

            IPAddress dnsIp = IPAddress.Parse(connected.ActiveLoopbackIp!);

            // Initially custom.example routes to Zone 4
            DnsMessage beforeUpdate = await QueryLocalDnsUdpAsync(dnsIp, connected.BoundDnsPort, "custom.example");
            beforeUpdate.Answers.Should().Contain(a => Equals(a.Address, Zone4AnswerIp));

            // Push UpdateRoutingConfig + UpdatePool live while connected
            SplitNamespaceRouterConfig updatedRouting = initialConnect.RoutingConfig! with
            {
                GeoUnlockRules = [new GeoUnlockRule("chatgpt.com"), new GeoUnlockRule("custom.example")]
            };
            PipeRpcResponse routeResp = await client.SendAsync(new PipeRpcRequest(
                Guid.NewGuid().ToString("N"),
                PipeCommandNames.UpdateRoutingConfig,
                JsonSerializer.Serialize(new ServiceRoutingConfigRequest(updatedRouting, ClearCache: true), JsonOptions)));
            routeResp.Success.Should().BeTrue(routeResp.ErrorMessage);

            DnsServerEntry secondaryZ3 = new()
            {
                Id = "z3-secondary",
                Name = "Zone 3 Secondary",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
                PrimaryIp = Zone3SecondaryIp.ToString(),
                DohUrl = "https://z3-secondary.invalid/dns-query",
                Port = 443
            };

            PipeRpcResponse poolResp = await client.SendAsync(new PipeRpcRequest(
                Guid.NewGuid().ToString("N"),
                PipeCommandNames.UpdatePool,
                JsonSerializer.Serialize(new ServicePoolUpdateRequest(
                    GeoUnlockUpstreams: [secondaryZ3],
                    ActiveGeoUnlockUpstreamId: "z3-secondary",
                    ClearCache: true), JsonOptions)));
            poolResp.Success.Should().BeTrue(poolResp.ErrorMessage);

            ServiceStatusSnapshot afterPool = JsonSerializer.Deserialize<ServiceStatusSnapshot>(poolResp.PayloadJson!, JsonOptions)!;
            afterPool.ActiveGeoUnlockUpstreamId.Should().Be("z3-secondary");

            DnsMessage afterUpdate = await QueryLocalDnsUdpAsync(dnsIp, connected.BoundDnsPort, "custom.example");
            afterUpdate.Answers.Should().Contain(a => Equals(a.Address, Zone3SecondaryIp));

            // Push UpdateBlocklist live while connected
            PipeRpcResponse blockResp = await client.SendAsync(new PipeRpcRequest(
                Guid.NewGuid().ToString("N"),
                PipeCommandNames.UpdateBlocklist,
                JsonSerializer.Serialize(new ServiceBlocklistUpdateRequest(
                    BlockRules: ["ads.example"],
                    ClearCache: true), JsonOptions)));
            blockResp.Success.Should().BeTrue(blockResp.ErrorMessage);

            DnsMessage blockedReply = await QueryLocalDnsUdpAsync(dnsIp, connected.BoundDnsPort, "ads.example");
            blockedReply.Header.ResponseCode.Should().Be(DnsResponseCode.NxDomain);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Connect_WithAdapterDnsAndNon53Port_TransparentlyFallsBackToLocalProxyPacOnly()
    {
        int customDnsPort = FindFreeEphemeralUdpTcpPort();
        List<(InterceptionMode Mode, string? PacUrl, IReadOnlyList<string> SplitDomains)> activations = [];

        SplitNamespaceRouter router = new();
        OptimisticDnsCache cache = new();
        UpstreamPoolManager poolManager = new();
        RecordingUpstreamClient upstreamClient = new(new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase)
        {
            ["z4-trusted"] = Zone4AnswerIp
        });
        PulseCoreDnsEngine engine = new(router, cache, poolManager, _ => upstreamClient);

        PulseServiceOptions serviceOptions = new()
        {
            DnsPort = customDnsPort,
            DohPort = 0,
            ProxyPort = 0,
            PacPort = 0,
            EnableDohListener = false,
            EnableSidecarProxy = true,
            InterceptionMode = InterceptionMode.AdapterDns,
            AutoFallbackToPacOnPort53Conflict = true
        };

        using DefaultPulseRuntimeBackend backend = new(
            serviceOptions,
            engine,
            cache,
            poolManager,
            router: router,
            interceptorFactory: (mode, pacUrl, _) => new RecordingInterceptor(mode, pacUrl, activations));

        ServiceStatusSnapshot status = await backend.ConnectAsync();

        try
        {
            status.IsConnected.Should().BeTrue();
            status.RequestedMode.Should().Be(InterceptionMode.AdapterDns);
            status.ActiveMode.Should().Be(InterceptionMode.LocalProxyPacOnly);
            status.InterceptionActive.Should().BeTrue();
            status.BoundDnsPort.Should().Be(customDnsPort);
            status.PacUrl.Should().Be($"http://{serviceOptions.SidecarLoopbackAddress}:{status.BoundPacPort}/proxy.pac");
            status.InterceptionStatusDetail.Should().Contain("LocalProxyPacOnly");
            activations.Should().ContainSingle(a => a.Mode == InterceptionMode.LocalProxyPacOnly && a.PacUrl == status.PacUrl);
        }
        finally
        {
            await backend.DisconnectAsync();
        }
    }

    [Fact]
    public async Task Connect_WithSplitNrptNon53PortAndFallbackDisabled_ThrowsNotSupportedException()
    {
        int customDnsPort = FindFreeEphemeralUdpTcpPort();
        SplitNamespaceRouter router = new();
        OptimisticDnsCache cache = new();
        UpstreamPoolManager poolManager = new();
        PulseCoreDnsEngine engine = new(router, cache, poolManager, _ => new RecordingUpstreamClient(new Dictionary<string, IPAddress>()));

        PulseServiceOptions serviceOptions = new()
        {
            DnsPort = customDnsPort,
            DohPort = 0,
            ProxyPort = 0,
            PacPort = 0,
            EnableDohListener = false,
            EnableSidecarProxy = true,
            InterceptionMode = InterceptionMode.SplitNrpt,
            AutoFallbackToPacOnPort53Conflict = false
        };

        using DefaultPulseRuntimeBackend backend = new(
            serviceOptions,
            engine,
            cache,
            poolManager,
            router: router);

        Func<Task> act = () => backend.ConnectAsync();
        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task SidecarProxy_DoesNotFallbackToBootstrap_WhenZone3OrBlockedResolutionFails()
    {
        int bootstrapCalls = 0;
        SplitNamespaceRouter router = new();
        OptimisticDnsCache cache = new();
        UpstreamPoolManager poolManager = new();
        FailingUpstreamClient failingClient = new();
        PulseCoreDnsEngine engine = new(router, cache, poolManager, _ => failingClient);

        PulseServiceOptions serviceOptions = new()
        {
            DnsPort = 0,
            DohPort = 0,
            ProxyPort = 0,
            PacPort = 0,
            EnableDohListener = false,
            EnableSidecarProxy = true,
            InterceptionMode = InterceptionMode.LocalProxyPacOnly
        };

        using DefaultPulseRuntimeBackend backend = new(
            serviceOptions,
            engine,
            cache,
            poolManager,
            sidecarHostResolver: (_, _) =>
            {
                Interlocked.Increment(ref bootstrapCalls);
                return Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse("198.51.100.99")]);
            },
            router: router,
            interceptorFactory: (mode, pacUrl, _) => new RecordingInterceptor(mode, pacUrl, []));

        await backend.ApplyConnectConfigurationAsync(new ServiceConnectRequest(
            DnsPort: 0,
            DohPort: 0,
            ProxyPort: 0,
            PacPort: 0,
            InterceptionMode: InterceptionMode.LocalProxyPacOnly,
            EnableSidecarProxy: true,
            EnableDohListener: false,
            RoutingConfig: new SplitNamespaceRouterConfig
            {
                GeoUnlockRules = [new GeoUnlockRule("chatgpt.com")],
                BlockRules = ["ads.example"]
            },
            Zone4Servers:
            [
                new DnsServerEntry
                {
                    Id = "z4-fail",
                    Name = "Z4 Fail",
                    Protocol = DnsProtocol.DoH,
                    TrustTier = TrustTier.Tier1EncryptedTrusted,
                    PrimaryIp = "203.0.113.10",
                    DohUrl = "https://z4-fail.invalid/dns-query",
                    Port = 443
                }
            ],
            GeoUnlockUpstreams:
            [
                new DnsServerEntry
                {
                    Id = "z3-fail",
                    Name = "Z3 Fail",
                    Protocol = DnsProtocol.DoH,
                    TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
                    PrimaryIp = "198.51.100.10",
                    DohUrl = "https://z3-fail.invalid/dns-query",
                    Port = 443
                }
            ]));

        ServiceStatusSnapshot status = await backend.ConnectAsync();

        try
        {
            using TcpClient tcp = new();
            await tcp.ConnectAsync(serviceOptions.SidecarLoopbackAddress, status.BoundProxyPort);
            NetworkStream stream = tcp.GetStream();
            byte[] req = System.Text.Encoding.ASCII.GetBytes("CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n");
            await stream.WriteAsync(req);

            byte[] buffer = new byte[1024];
            int read = await stream.ReadAsync(buffer);
            string responseText = System.Text.Encoding.ASCII.GetString(buffer, 0, read);

            responseText.Should().NotContain("200 Connection Established");
            Volatile.Read(ref bootstrapCalls).Should().Be(0);
        }
        finally
        {
            await backend.DisconnectAsync();
        }
    }

    private static ServiceConnectRequest CreateSampleConnectRequest(
        InterceptionMode mode,
        string geoUpstreamId,
        IPAddress geoUpstreamIp)
    {
        DnsServerEntry z3 = new()
        {
            Id = geoUpstreamId,
            Name = "Zone 3 Smart",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
            PrimaryIp = geoUpstreamIp.ToString(),
            DohUrl = "https://z3.invalid/dns-query",
            Port = 443
        };

        DnsServerEntry z4 = new()
        {
            Id = "z4-trusted",
            Name = "Zone 4 Trusted",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            PrimaryIp = Zone4AnswerIp.ToString(),
            DohUrl = "https://z4.invalid/dns-query",
            Port = 443
        };

        SplitNamespaceRouterConfig routingConfig = new()
        {
            GeoUnlockRules = [new GeoUnlockRule("chatgpt.com"), new GeoUnlockRule("claude.ai")]
        };

        return new ServiceConnectRequest(
            DnsPort: 0,
            DohPort: 0,
            ProxyPort: 0,
            PacPort: 0,
            InterceptionMode: mode,
            EnableSidecarProxy: true,
            EnableDohListener: false,
            ActiveTrustedUpstreamId: "z4-trusted",
            ActiveGeoUnlockUpstreamId: geoUpstreamId,
            RoutingConfig: routingConfig,
            SplitDomains: ["chatgpt.com", "claude.ai"],
            Zone4Servers: [z4],
            GeoUnlockUpstreams: [z3]);
    }

    private static async Task<DnsMessage> QueryLocalDnsUdpAsync(IPAddress serverIp, int port, string domain)
    {
        DnsMessage query = DnsMessage.CreateQuery(4242, domain, DnsRecordType.A);
        byte[] queryBytes = DnsWireCodec.Serialize(query);

        using UdpClient udp = new();
        udp.Client.ReceiveTimeout = 3000;
        await udp.SendAsync(queryBytes, new IPEndPoint(serverIp, port));
        UdpReceiveResult receiveResult = await udp.ReceiveAsync();
        return DnsWireCodec.Parse(receiveResult.Buffer);
    }

    private static async Task WaitForIpcReadyAsync(string pipeName)
    {
        PulsePipeIpcClient client = new(pipeName, TimeSpan.FromSeconds(1));
        for (int attempt = 0; attempt < 30; attempt++)
        {
            try
            {
                PipeRpcResponse ping = await client.SendAsync(new PipeRpcRequest(Guid.NewGuid().ToString("N"), PipeCommandNames.GetStatus));
                if (ping.Success)
                {
                    return;
                }
            }
            catch (TimeoutException)
            {
            }
            catch (IOException)
            {
            }

            await Task.Delay(50);
        }

        throw new TimeoutException($"Named pipe '{pipeName}' did not become ready in time.");
    }

    private static int FindFreeEphemeralUdpTcpPort()
    {
        using TcpListener tcp = new(IPAddress.Loopback, 0);
        tcp.Start();
        return ((IPEndPoint)tcp.LocalEndpoint).Port;
    }

    private static string CreateUniquePipeName() =>
        string.Create(CultureInfo.InvariantCulture, $"DnsPulseSplitBrainTest_{Guid.NewGuid():N}");

    private sealed class RecordingUpstreamClient : IDnsUpstreamClient
    {
        private readonly Dictionary<string, IPAddress> _answersByServerId;

        public RecordingUpstreamClient(Dictionary<string, IPAddress> answersByServerId)
        {
            _answersByServerId = answersByServerId;
        }

        public List<string> QueriedUpstreamIds { get; } = [];

        public DnsProtocol Protocol => DnsProtocol.DoH;

        public Task<UpstreamQueryResult> QueryAsync(
            DnsMessage query,
            DnsServerEntry upstream,
            CancellationToken cancellationToken = default)
        {
            QueriedUpstreamIds.Add(upstream.Id);
            IPAddress answerIp = _answersByServerId.TryGetValue(upstream.Id, out IPAddress? configured)
                ? configured
                : IPAddress.Parse("192.0.2.1");

            string qname = query.Questions.Count > 0 ? query.Questions[0].Name : "example.org";
            DnsMessage response = new()
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
                Answers = [DnsResourceRecord.CreateA(qname, answerIp, 120)]
            };

            return Task.FromResult(new UpstreamQueryResult(response, TimeSpan.FromMilliseconds(5), upstream.PrimaryIp, DnsProtocol.DoH));
        }
    }

    private sealed class RecordingInterceptor : IDnsInterceptor
    {
        private readonly string? _pacUrl;
        private readonly List<(InterceptionMode Mode, string? PacUrl, IReadOnlyList<string> SplitDomains)> _records;

        public RecordingInterceptor(
            InterceptionMode mode,
            string? pacUrl,
            List<(InterceptionMode Mode, string? PacUrl, IReadOnlyList<string> SplitDomains)> records)
        {
            Mode = mode;
            _pacUrl = pacUrl;
            _records = records;
        }

        public InterceptionMode Mode { get; }

        public Task ActivateAsync(
            IPAddress localDnsIp,
            int dnsPort,
            IReadOnlyList<string> splitDomains,
            CancellationToken ct = default)
        {
            _records.Add((Mode, _pacUrl, [.. splitDomains]));
            return Task.CompletedTask;
        }

        public Task DeactivateAsync(CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class FailingUpstreamClient : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => DnsProtocol.DoH;

        public Task<UpstreamQueryResult> QueryAsync(
            DnsMessage query,
            DnsServerEntry upstream,
            CancellationToken cancellationToken = default)
        {
            throw new TimeoutException("Simulated upstream failure.");
        }
    }
}
