using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text.Json;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Engine.Bootstrap;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Hosting;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Engine.Sidecar;
using DnsPulse.Engine.Transports;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Ipc;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Recovery;
using Serilog;

namespace DnsPulse.App.Services;

/// <summary>
/// Hybrid runtime bridge: communicates with <c>DnsPulseService</c> via ACL-hardened Named Pipe IPC
/// when available, and gracefully falls back to an in-process Portable Mode runtime
/// (<see cref="LocalProxyPacInterceptor"/> unprivileged or <see cref="AdapterDnsInterceptor"/>/NRPT when elevated).
/// </summary>
public sealed class HybridPulseRuntimeService : IPulseRuntimeService, IDisposable
{
    private static readonly JsonSerializerOptions IpcJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private static readonly TimeSpan IpcProbeTimeout = TimeSpan.FromMilliseconds(750);

    private readonly PulsePipeIpcClient _ipcClient;
    private readonly NetworkSnapshotJournal _journal;
    private readonly HostNetworkHealthProvider _hostHealthProvider;
    private readonly LoopbackPortSelector _portSelector;
    private readonly SplitNamespaceRouter _router;
    private readonly OptimisticDnsCache _cache;
    private readonly UpstreamPoolManager _poolManager;
    private readonly UpstreamClientRegistry _clientRegistry;
    private readonly EncryptedBootstrapResolver _bootstrapResolver;
    private readonly PulseCoreDnsEngine _dnsEngine;
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);

    private LocalDnsServer? _localDnsServer;
    private LocalDohHttpListener? _localDohListener;
    private TlsFragmentationProxyServer? _localProxyServer;
    private AutoPacServer? _localPacServer;
    private IDnsInterceptor? _activeInterceptor;
    private ServiceStatusSnapshot _currentStatus = new();
    private DnsServerEntry? _activeTrustedUpstream;
    private DnsServerEntry? _activeGeoUnlockUpstream;
    private IReadOnlyList<string> _activeSplitDomains;
    private PulseAppSettings _lastSettings = new();
    private bool _isServiceMode;
    private bool _disposed;

    public HybridPulseRuntimeService(
        PulsePipeIpcClient? ipcClient = null,
        NetworkSnapshotJournal? journal = null,
        HostNetworkHealthProvider? hostHealthProvider = null)
    {
        _ipcClient = ipcClient ?? new PulsePipeIpcClient(PipeSecurityBuilder.DefaultPipeName, IpcProbeTimeout);
        _journal = journal ?? new NetworkSnapshotJournal();
        _hostHealthProvider = hostHealthProvider ?? new HostNetworkHealthProvider(enableOsProbes: true);
        _portSelector = new LoopbackPortSelector();
        _router = new SplitNamespaceRouter();
        _cache = new OptimisticDnsCache();
        _poolManager = new UpstreamPoolManager();
        _clientRegistry = UpstreamClientRegistry.CreateDefault();
        _bootstrapResolver = new EncryptedBootstrapResolver();
        _dnsEngine = new PulseCoreDnsEngine(_router, _cache, _poolManager, _clientRegistry.GetClient);
        _dnsEngine.Telemetry.EventRecorded += OnEngineTelemetryRecorded;

        _activeSplitDomains =
        [
            .. BuiltInCatalogPresets.BuiltinAiDomains,
            .. BuiltInCatalogPresets.BuiltinStreamingDomains,
            .. BuiltInCatalogPresets.BuiltinGamingDomains
        ];
    }

    public event EventHandler<RuntimeStatusChangedEventArgs>? StatusChanged;

    public event EventHandler<DnsQueryTelemetryEventArgs>? TelemetryReceived;

    public ServiceStatusSnapshot CurrentStatus => _currentStatus;

    public bool IsServiceMode => _isServiceMode;

    public bool IsElevated => IsProcessElevated();

    public DnsServerEntry? ActiveTrustedUpstream => _activeTrustedUpstream;

    public DnsServerEntry? ActiveGeoUnlockUpstream => _activeGeoUnlockUpstream;

    public SplitNamespaceRouter Router => _router;

    public IBootstrapResolver BootstrapResolver => _bootstrapResolver;

    public Func<DnsProtocol, IDnsUpstreamClient> ClientFactory => _clientRegistry.GetClient;

    public IHostNetworkHealthProvider HostHealthProvider => _hostHealthProvider;

    public SixLayerDiagnosticEngine CreateDiagnosticEngine()
    {
        return new SixLayerDiagnosticEngine(_bootstrapResolver, _clientRegistry.GetClient, _hostHealthProvider);
    }

    public BenchmarkRunner CreateBenchmarkRunner()
    {
        return new BenchmarkRunner(CreateDiagnosticEngine());
    }

    public async Task<ServiceStatusSnapshot> RefreshStatusAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ServiceStatusSnapshot? ipcStatus = await TrySendIpcAsync<ServiceStatusSnapshot>(
            PipeCommandNames.GetStatus,
            payload: null,
            cancellationToken).ConfigureAwait(false);

        if (ipcStatus is not null)
        {
            _isServiceMode = true;
            UpdateSnapshot(ipcStatus);
            return ipcStatus;
        }

        _isServiceMode = false;
        ServiceStatusSnapshot portable = BuildPortableSnapshot(lastError: _currentStatus.LastErrorMessage);
        UpdateSnapshot(portable);
        return portable;
    }

    public async Task<ServiceStatusSnapshot> ConnectAsync(
        DnsServerEntry? trustedUpstream,
        DnsServerEntry? geoUnlockUpstream = null,
        IReadOnlyList<DnsServerEntry>? fallbackTrustedPool = null,
        PulseAppSettings? settings = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PulseAppSettings effectiveSettings = settings?.Clone() ?? _lastSettings.Clone();
            _lastSettings = effectiveSettings;

            ConfigureEngineUpstreams(trustedUpstream, geoUnlockUpstream, fallbackTrustedPool, effectiveSettings);

            ServiceStatusSnapshot? ipcStatus = await TrySendIpcAsync<ServiceStatusSnapshot>(
                PipeCommandNames.Connect,
                payload: null,
                cancellationToken).ConfigureAwait(false);

            if (ipcStatus is not null)
            {
                _isServiceMode = true;
                UpdateSnapshot(ipcStatus);
                return ipcStatus;
            }

            _isServiceMode = false;
            return await ConnectPortableLockedAsync(effectiveSettings, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> DisconnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_isServiceMode)
            {
                ServiceStatusSnapshot? ipcStatus = await TrySendIpcAsync<ServiceStatusSnapshot>(
                    PipeCommandNames.Disconnect,
                    payload: null,
                    cancellationToken).ConfigureAwait(false);

                if (ipcStatus is not null)
                {
                    UpdateSnapshot(ipcStatus);
                    return ipcStatus;
                }
            }

            await StopPortableLockedAsync(markCleanShutdown: true, cancellationToken).ConfigureAwait(false);
            ServiceStatusSnapshot snapshot = BuildPortableSnapshot(lastError: null);
            UpdateSnapshot(snapshot);
            return snapshot;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<DnsServerEntry?> RotateUpstreamAsync(
        IReadOnlyList<DnsServerEntry> candidates,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        ObjectDisposedException.ThrowIf(_disposed, this);

        List<DnsServerEntry> eligible =
        [
            .. candidates.Where(static c => c is not null && TrustTierPolicy.CanServeDefaultInternet(c.TrustTier, c.Protocol))
        ];

        if (eligible.Count == 0)
        {
            return null;
        }

        int currentIdx = _activeTrustedUpstream is null
            ? -1
            : eligible.FindIndex(c => string.Equals(c.Id, _activeTrustedUpstream.Id, StringComparison.OrdinalIgnoreCase));

        DnsServerEntry next = eligible[(currentIdx + 1) % eligible.Count];
        _activeTrustedUpstream = next;
        _poolManager.UpdateZone4Pool([next, .. eligible.Where(e => !string.Equals(e.Id, next.Id, StringComparison.OrdinalIgnoreCase))]);

        if (_currentStatus.IsConnected && !_isServiceMode)
        {
            _cache.Clear();
        }

        await RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
        return next;
    }

    public async Task<NetworkRestoredResult> EmergencyRestoreAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_isServiceMode)
            {
                NetworkRestoredResult? ipcRestore = await TrySendIpcAsync<NetworkRestoredResult>(
                    PipeCommandNames.EmergencyRestore,
                    payload: null,
                    cancellationToken).ConfigureAwait(false);

                if (ipcRestore is not null)
                {
                    UpdateSnapshot(new ServiceStatusSnapshot
                    {
                        IsConnected = false,
                        IsHealthy = false,
                        ActiveMode = InterceptionMode.None,
                        LastErrorMessage = ipcRestore.Summary
                    });
                    return ipcRestore;
                }
            }

            await StopPortableLockedAsync(markCleanShutdown: false, cancellationToken).ConfigureAwait(false);

            NetworkRestoredResult recovered = await _journal.RecoverIfDirtyAsync(cancellationToken).ConfigureAwait(false);
            if (!recovered.HadDirtyState)
            {
                recovered = NetworkSnapshotJournal.ExecuteNativeRestore(null);
            }

            UpdateSnapshot(BuildPortableSnapshot(lastError: null));
            return recovered;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<IReadOnlyList<DnsQueryTelemetryEvent>> GetRecentTelemetryAsync(
        int maxCount = 200,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxCount);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_isServiceMode)
        {
            List<DnsQueryTelemetryEvent>? ipcEvents = await TrySendIpcAsync<List<DnsQueryTelemetryEvent>>(
                PipeCommandNames.GetRecentTelemetry,
                new { maxCount },
                cancellationToken).ConfigureAwait(false);

            if (ipcEvents is not null)
            {
                return ipcEvents;
            }
        }

        return _dnsEngine.Telemetry.GetRecentEvents(maxCount);
    }

    public Task UpdateRoutingConfigAsync(
        SplitNamespaceRouterConfig config,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        _router.UpdateConfiguration(config);

        HashSet<string> splitDomains = new(StringComparer.OrdinalIgnoreCase);
        foreach (string domain in BuiltInCatalogPresets.BuiltinAiDomains
            .Concat(BuiltInCatalogPresets.BuiltinStreamingDomains)
            .Concat(BuiltInCatalogPresets.BuiltinGamingDomains))
        {
            splitDomains.Add(domain);
        }

        foreach (GeoUnlockRule rule in config.GeoUnlockRules)
        {
            if (!string.IsNullOrWhiteSpace(rule.Pattern))
            {
                splitDomains.Add(rule.Pattern.Trim().TrimStart('*').TrimStart('.'));
            }
        }

        _activeSplitDomains = [.. splitDomains];
        _localPacServer?.UpdateSplitDomains(_activeSplitDomains);
        _cache.Clear();

        return Task.CompletedTask;
    }

    public Task UpdateEngineOptionsAsync(
        PulseAppSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        _lastSettings = settings.Clone();
        ConfigureEngineUpstreams(_activeTrustedUpstream, _activeGeoUnlockUpstream, fallbackPool: null, settings);
        return Task.CompletedTask;
    }

    public Task<HostNetworkHealthSnapshot> InspectHostHealthAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _hostHealthProvider.InspectAsync(cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dnsEngine.Telemetry.EventRecorded -= OnEngineTelemetryRecorded;

        _localPacServer?.Dispose();
        _localProxyServer?.Dispose();
        _localDohListener?.Dispose();
        _localDnsServer?.Dispose();
        _localPacServer = null;
        _localProxyServer = null;
        _localDohListener = null;
        _localDnsServer = null;

        _cache.Dispose();
        _bootstrapResolver.Dispose();
        _clientRegistry.Dispose();
        _lifecycleLock.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dnsEngine.Telemetry.EventRecorded -= OnEngineTelemetryRecorded;

        await StopPortableLockedAsync(markCleanShutdown: true, CancellationToken.None).ConfigureAwait(false);

        _cache.Dispose();
        await _bootstrapResolver.DisposeAsync().ConfigureAwait(false);
        await _clientRegistry.DisposeAsync().ConfigureAwait(false);
        _lifecycleLock.Dispose();
    }

    private void ConfigureEngineUpstreams(
        DnsServerEntry? trustedUpstream,
        DnsServerEntry? geoUnlockUpstream,
        IReadOnlyList<DnsServerEntry>? fallbackPool,
        PulseAppSettings settings)
    {
        List<DnsServerEntry> zone4Candidates = [];
        if (trustedUpstream is not null && TrustTierPolicy.CanServeDefaultInternet(trustedUpstream.TrustTier, trustedUpstream.Protocol))
        {
            _activeTrustedUpstream = trustedUpstream;
            zone4Candidates.Add(trustedUpstream);
        }

        if (fallbackPool is not null)
        {
            foreach (DnsServerEntry candidate in fallbackPool)
            {
                if (candidate is not null &&
                    TrustTierPolicy.CanServeDefaultInternet(candidate.TrustTier, candidate.Protocol) &&
                    !zone4Candidates.Any(c => string.Equals(c.Id, candidate.Id, StringComparison.OrdinalIgnoreCase)))
                {
                    zone4Candidates.Add(candidate);
                }
            }
        }

        if (zone4Candidates.Count > 0)
        {
            _poolManager.UpdateZone4Pool(zone4Candidates);
        }

        if (geoUnlockUpstream is not null)
        {
            _activeGeoUnlockUpstream = geoUnlockUpstream;
        }

        List<DnsServerEntry> geoList = _activeGeoUnlockUpstream is not null ? [_activeGeoUnlockUpstream] : [];
        _dnsEngine.UpdateOptions(new PulseCoreEngineOptions
        {
            GeoUnlockUpstreams = geoList,
            Zone4Strategy = settings.PoolStrategy,
            Zone3Strategy = PoolSelectionStrategy.Failover
        });
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Portable mode startup cleans up partially started listeners and falls back gracefully on unprivileged environments.")]
    private async Task<ServiceStatusSnapshot> ConnectPortableLockedAsync(
        PulseAppSettings settings,
        CancellationToken cancellationToken)
    {
        if (_localDnsServer is not null)
        {
            ServiceStatusSnapshot existing = BuildPortableSnapshot(lastError: null);
            UpdateSnapshot(existing);
            return existing;
        }

        LocalDnsServer? dnsServer = null;
        LocalDohHttpListener? dohListener = null;
        TlsFragmentationProxyServer? proxyServer = null;
        AutoPacServer? pacServer = null;
        IDnsInterceptor? interceptor = null;

        bool elevated = IsElevated;
        bool wantsSystemDns = elevated && settings.InterceptionMode is InterceptionMode.AdapterDns or InterceptionMode.SplitNrpt or InterceptionMode.WfpDivertPlugin;

        try
        {
            IPAddress loopbackIp = IPAddress.Loopback;
            int desiredDnsPort = 0;

            if (wantsSystemDns)
            {
                try
                {
                    loopbackIp = _portSelector.SelectAvailableDnsEndpoint(53);
                    desiredDnsPort = 53;
                }
                catch (InvalidOperationException)
                {
                    loopbackIp = IPAddress.Loopback;
                    desiredDnsPort = 0;
                }
            }

            dnsServer = new LocalDnsServer(
                _dnsEngine,
                new LocalDnsServerOptions
                {
                    ListenAddress = loopbackIp,
                    Port = desiredDnsPort
                });
            await dnsServer.StartAsync(cancellationToken).ConfigureAwait(false);

            dohListener = new LocalDohHttpListener(
                _dnsEngine,
                new LocalDohServerOptions
                {
                    ListenAddress = IPAddress.Loopback,
                    Port = 0
                });
            await dohListener.StartAsync(cancellationToken).ConfigureAwait(false);

            proxyServer = new TlsFragmentationProxyServer(
                new TlsFragmentationProxyOptions
                {
                    BindAddress = IPAddress.Loopback,
                    Port = 0
                },
                (host, ct) => _bootstrapResolver.ResolveHostAsync(host, ct));
            await proxyServer.StartAsync(cancellationToken).ConfigureAwait(false);

            int proxyPort = proxyServer.BoundEndPoint?.Port ?? 10808;
            pacServer = new AutoPacServer(
                new AutoPacServerOptions
                {
                    BindAddress = IPAddress.Loopback,
                    Port = 0,
                    ProxyHost = IPAddress.Loopback.ToString(),
                    ProxyPort = proxyPort
                },
                _activeSplitDomains);
            await pacServer.StartAsync(cancellationToken).ConfigureAwait(false);

            InterceptionMode effectiveMode = elevated ? settings.InterceptionMode : InterceptionMode.LocalProxyPacOnly;
            if (dnsServer.BoundPort != 53 && effectiveMode is InterceptionMode.AdapterDns or InterceptionMode.SplitNrpt)
            {
                effectiveMode = InterceptionMode.LocalProxyPacOnly;
            }

            string pacUrl = pacServer.PacUrl ?? string.Create(
                CultureInfo.InvariantCulture,
                $"http://{IPAddress.Loopback}:{pacServer.BoundEndPoint?.Port ?? 10809}/proxy.pac");
            interceptor = CreatePortableInterceptor(effectiveMode, pacUrl, settings.BlockIpv6OnBypass);
            if (interceptor is not null)
            {
                if (elevated && effectiveMode is InterceptionMode.AdapterDns or InterceptionMode.SplitNrpt)
                {
                    IReadOnlyList<AdapterDnsConfiguration> adapters = Win32NetworkInterop.GetActivePhysicalAdapters();
                    await _journal.BeginTransactionAsync(
                        effectiveMode,
                        loopbackIp,
                        adapters,
                        SmhnrPolicyManager.IsSmhnrDisabled(),
                        NrptPolicyManager.GetPulseNrptRuleNames(),
                        cancellationToken).ConfigureAwait(false);
                }

                await interceptor.ActivateAsync(
                    loopbackIp,
                    dnsServer.BoundPort,
                    _activeSplitDomains,
                    cancellationToken).ConfigureAwait(false);
            }

            _localDnsServer = dnsServer;
            _localDohListener = dohListener;
            _localProxyServer = proxyServer;
            _localPacServer = pacServer;
            _activeInterceptor = interceptor;

            dnsServer = null;
            dohListener = null;
            proxyServer = null;
            pacServer = null;
            interceptor = null;

            ServiceStatusSnapshot connected = BuildPortableSnapshot(lastError: null);
            UpdateSnapshot(connected);
            Log.Information("PulseCore connected in Portable Mode (DNS:{DnsPort}, DoH:{DohPort}, PAC:{PacPort}, Mode:{Mode}).",
                connected.BoundDnsPort,
                connected.BoundDoHPort,
                connected.BoundPacPort,
                connected.ActiveMode);
            return connected;
        }
        catch (Exception ex)
        {
            await DisposePortableResourcesAsync(interceptor, pacServer, proxyServer, dohListener, dnsServer).ConfigureAwait(false);
            ServiceStatusSnapshot errorSnapshot = BuildPortableSnapshot(lastError: ex.Message);
            UpdateSnapshot(errorSnapshot);
            throw;
        }
    }

    private async Task StopPortableLockedAsync(bool markCleanShutdown, CancellationToken cancellationToken)
    {
        IDnsInterceptor? interceptor = _activeInterceptor;
        AutoPacServer? pacServer = _localPacServer;
        TlsFragmentationProxyServer? proxyServer = _localProxyServer;
        LocalDohHttpListener? dohListener = _localDohListener;
        LocalDnsServer? dnsServer = _localDnsServer;

        _activeInterceptor = null;
        _localPacServer = null;
        _localProxyServer = null;
        _localDohListener = null;
        _localDnsServer = null;

        await DisposePortableResourcesAsync(interceptor, pacServer, proxyServer, dohListener, dnsServer).ConfigureAwait(false);

        if (markCleanShutdown)
        {
            await SafeMarkCleanShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Teardown must clean up all remaining listeners even if one fails.")]
    private static async Task DisposePortableResourcesAsync(
        IDnsInterceptor? interceptor,
        AutoPacServer? pacServer,
        TlsFragmentationProxyServer? proxyServer,
        LocalDohHttpListener? dohListener,
        LocalDnsServer? dnsServer)
    {
        if (interceptor is not null)
        {
            try
            {
                await interceptor.DeactivateAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }

        if (pacServer is not null)
        {
            try
            {
                await pacServer.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }

        if (proxyServer is not null)
        {
            try
            {
                await proxyServer.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }

        if (dohListener is not null)
        {
            try
            {
                await dohListener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }

        if (dnsServer is not null)
        {
            try
            {
                await dnsServer.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Clean shutdown journal update must not fail disconnect.")]
    private async Task SafeMarkCleanShutdownAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _journal.MarkCleanShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
    }

    private static IDnsInterceptor? CreatePortableInterceptor(
        InterceptionMode mode,
        string pacUrl,
        bool blockIpv6OnBypass)
    {
        return mode switch
        {
            InterceptionMode.AdapterDns => new AdapterDnsInterceptor(blockIpv6OnBypass, disableSmhnr: true),
            InterceptionMode.SplitNrpt => new NrptSplitInterceptor(),
            InterceptionMode.WfpDivertPlugin => new WfpDivertInterceptor(AntiCheatGuard.DetectActiveAntiCheat),
            InterceptionMode.LocalProxyPacOnly => new LocalProxyPacInterceptor(pacUrl),
            _ => null
        };
    }

    private ServiceStatusSnapshot BuildPortableSnapshot(string? lastError)
    {
        bool connected = _localDnsServer is not null;
        return new ServiceStatusSnapshot
        {
            IsConnected = connected,
            IsHealthy = connected,
            ActiveMode = connected ? (_activeInterceptor?.Mode ?? InterceptionMode.LocalProxyPacOnly) : InterceptionMode.None,
            ActiveLoopbackIp = connected ? IPAddress.Loopback.ToString() : null,
            BoundDnsPort = _localDnsServer?.BoundPort ?? 0,
            BoundDoHPort = _localDohListener?.BoundPort ?? 0,
            BoundProxyPort = _localProxyServer?.BoundEndPoint?.Port ?? 0,
            BoundPacPort = _localPacServer?.BoundEndPoint?.Port ?? 0,
            CacheHitRatePercent = _cache.HitRatePercent,
            QueriesPerMinute = _dnsEngine.Telemetry.QueriesPerMinute,
            ActiveUpstreamsCount = _poolManager.Zone4Servers.Count,
            DirtyRecoveryPending = false,
            LastErrorMessage = lastError
        };
    }

    private void UpdateSnapshot(ServiceStatusSnapshot snapshot)
    {
        _currentStatus = snapshot;
        StatusChanged?.Invoke(this, new RuntimeStatusChangedEventArgs(snapshot));
    }

    private void OnEngineTelemetryRecorded(object? sender, DnsQueryTelemetryEventArgs e)
    {
        TelemetryReceived?.Invoke(this, e);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "IPC unavailability triggers seamless fallback to Portable Mode.")]
    private async Task<TResponse?> TrySendIpcAsync<TResponse>(
        string command,
        object? payload,
        CancellationToken cancellationToken)
        where TResponse : class
    {
        try
        {
            string? payloadJson = payload is null ? null : JsonSerializer.Serialize(payload, IpcJsonOptions);
            PipeRpcRequest request = new(
                Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                command,
                payloadJson);

            PipeRpcResponse response = await _ipcClient.SendAsync(request, IpcProbeTimeout, cancellationToken).ConfigureAwait(false);
            if (!response.Success || string.IsNullOrWhiteSpace(response.PayloadJson))
            {
                return null;
            }

            return JsonSerializer.Deserialize<TResponse>(response.PayloadJson, IpcJsonOptions);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Elevation probe safely assumes unprivileged when identity inspection fails.")]
    private static bool IsProcessElevated()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
