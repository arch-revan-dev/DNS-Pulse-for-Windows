using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Hosting;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Engine.Sidecar;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Recovery;
using Microsoft.Extensions.Logging.Abstractions;

namespace DnsPulse.Service;

/// <summary>
/// Coordinates PulseCore local listeners (<see cref="LocalDnsServer"/>, <see cref="LocalDohHttpListener"/>,
/// <see cref="TlsFragmentationProxyServer"/>, <see cref="AutoPacServer"/>), dynamic Windows
/// <see cref="IDnsInterceptor"/> activation/fallback, live routing/upstream pool updates,
/// and emergency network rollback.
/// </summary>
public sealed class DefaultPulseRuntimeBackend : IPulseRuntimeBackend, IConfigurablePulseRuntimeBackend, IAsyncDisposable, IDisposable
{
    private static readonly Action<ILogger, int, int, InterceptionMode, string?, Exception?> LogConnected =
        LoggerMessage.Define<int, int, InterceptionMode, string?>(
            LogLevel.Information,
            new EventId(1001, nameof(LogConnected)),
            "Pulse runtime connected (DNS port {DnsPort}, DoH port {DohPort}, Mode {Mode}, PAC {PacUrl}).");

    private static readonly Action<ILogger, Exception?> LogDisconnected =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(1002, nameof(LogDisconnected)),
            "Pulse runtime disconnected cleanly.");

    private static readonly Action<ILogger, bool, int, Exception?> LogEmergencyRestored =
        LoggerMessage.Define<bool, int>(
            LogLevel.Warning,
            new EventId(1003, nameof(LogEmergencyRestored)),
            "Emergency network restore executed (HadDirtyState={HadDirtyState}, AdaptersRestored={AdaptersRestored}).");

    private static readonly Action<ILogger, Exception> LogNonFatalTeardownError =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(1004, nameof(LogNonFatalTeardownError)),
            "Non-fatal error while tearing down interceptor or listener.");

    private static readonly Action<ILogger, InterceptionMode, string, Exception?> LogInterceptionFallback =
        LoggerMessage.Define<InterceptionMode, string>(
            LogLevel.Warning,
            new EventId(1005, nameof(LogInterceptionFallback)),
            "Requested interception mode {RequestedMode} fell back to LocalProxyPacOnly: {Reason}");

    private PulseServiceOptions _options;
    private readonly PulseCoreDnsEngine _dnsEngine;
    private readonly SplitNamespaceRouter? _router;
    private readonly OptimisticDnsCache? _cache;
    private readonly UpstreamPoolManager? _poolManager;
    private readonly IDnsInterceptor? _injectedInterceptor;
    private readonly Func<InterceptionMode, string?, bool, IDnsInterceptor?>? _interceptorFactory;
    private readonly LoopbackPortSelector _loopbackPortSelector;
    private readonly NetworkSnapshotJournal? _journal;
    private readonly Func<CancellationToken, Task<NetworkRestoredResult>>? _emergencyRollbackHandler;
    private readonly Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> _sidecarHostResolver;
    private readonly Func<IPEndPoint, CancellationToken, Task<bool>>? _healthProbeOverride;
    private readonly Func<string?>? _activeGeoUnlockUpstreamIdProvider;
    private readonly ILogger<DefaultPulseRuntimeBackend> _logger;
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);

    private PulseCoreEngineOptions _engineOptions = new();
    private SplitNamespaceRouterConfig? _lastRoutingConfig;
    private IReadOnlyList<string> _splitDomains;
    private LocalDnsServer? _dnsServer;
    private LocalDohHttpListener? _dohListener;
    private TlsFragmentationProxyServer? _proxyServer;
    private AutoPacServer? _pacServer;
    private IDnsInterceptor? _activeInterceptor;
    private InterceptionMode _activeMode;
    private IPAddress? _activeLoopbackIp;
    private string? _activePacUrl;
    private string? _interceptionStatusDetail;
    private string? _activeTrustedUpstreamId;
    private string? _activeGeoUnlockUpstreamId;
    private bool _interceptionActive;
    private bool _isConnected;
    private bool _isHealthy;
    private bool _dirtyRecoveryPending;
    private string? _lastErrorMessage;
    private int _configuredDnsPort;
    private int _disposed;

    public DefaultPulseRuntimeBackend(
        PulseServiceOptions options,
        PulseCoreDnsEngine dnsEngine,
        OptimisticDnsCache? cache = null,
        UpstreamPoolManager? poolManager = null,
        IDnsInterceptor? dnsInterceptor = null,
        Func<CancellationToken, Task<NetworkRestoredResult>>? emergencyRollbackHandler = null,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? sidecarHostResolver = null,
        IReadOnlyList<string>? initialSplitDomains = null,
        Func<IPEndPoint, CancellationToken, Task<bool>>? healthProbeOverride = null,
        ILogger<DefaultPulseRuntimeBackend>? logger = null,
        Func<string?>? activeGeoUnlockUpstreamIdProvider = null,
        SplitNamespaceRouter? router = null,
        LoopbackPortSelector? loopbackPortSelector = null,
        NetworkSnapshotJournal? journal = null,
        Func<InterceptionMode, string?, bool, IDnsInterceptor?>? interceptorFactory = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dnsEngine);

        _options = options;
        _configuredDnsPort = options.DnsPort;
        _dnsEngine = dnsEngine;
        _router = router;
        _cache = cache;
        _poolManager = poolManager;
        _injectedInterceptor = dnsInterceptor;
        _interceptorFactory = interceptorFactory;
        _loopbackPortSelector = loopbackPortSelector ?? new LoopbackPortSelector();
        _journal = journal;
        _emergencyRollbackHandler = emergencyRollbackHandler;
        _sidecarHostResolver = sidecarHostResolver ?? ResolveHostFallbackAsync;
        _splitDomains = initialSplitDomains ?? [];
        _healthProbeOverride = healthProbeOverride;
        _activeGeoUnlockUpstreamIdProvider = activeGeoUnlockUpstreamIdProvider;
        _activeTrustedUpstreamId = options.ActiveTrustedUpstreamId;
        _activeGeoUnlockUpstreamId = options.ActiveGeoUnlockUpstreamId;
        _logger = logger ?? NullLogger<DefaultPulseRuntimeBackend>.Instance;

        if (_journal is not null)
        {
            PrePulseNetworkSnapshot? existing = _journal.TryLoadVerifiedSnapshot(out _);
            _dirtyRecoveryPending = existing is { DirtyShutdown: true };
        }
    }

    /// <summary>
    /// Gets the currently configured local DNS port (<c>53</c>, <c>0</c> for auto, or custom port).
    /// </summary>
    public int ConfiguredDnsPort => Volatile.Read(ref _configuredDnsPort);

    /// <summary>
    /// Updates the active Zone 3 Geo-Unlock upstream identifier surfaced in <see cref="GetStatus"/>.
    /// </summary>
    public void SetActiveGeoUnlockUpstreamId(string? upstreamId)
    {
        string? normalized = string.IsNullOrWhiteSpace(upstreamId) ? null : upstreamId.Trim();
        Volatile.Write(ref _activeGeoUnlockUpstreamId, normalized);
    }

    /// <summary>
    /// Updates preferred local listener ports before connecting.
    /// </summary>
    public void ConfigurePorts(int? dnsPort, int? dohPort, int? proxyPort, int? pacPort)
    {
        int nextDns = dnsPort is >= 0 and <= 65535 ? dnsPort.Value : _options.DnsPort;
        int nextDoh = dohPort is >= 0 and <= 65535 ? dohPort.Value : _options.DohPort;
        int nextProxy = proxyPort is >= 0 and <= 65535 ? proxyPort.Value : _options.ProxyPort;
        int nextPac = pacPort is >= 0 and <= 65535 ? pacPort.Value : _options.PacPort;

        _options = _options with
        {
            DnsPort = nextDns,
            DohPort = nextDoh,
            ProxyPort = nextProxy,
            PacPort = nextPac
        };
        Volatile.Write(ref _configuredDnsPort, nextDns);
    }

    public ServiceStatusSnapshot GetStatus()
    {
        double? p50LatencyMs = _dnsEngine.Telemetry.Count > 0
            ? _dnsEngine.Telemetry.P50LatencyMs
            : null;
        string? activeGeoUpstreamId = Volatile.Read(ref _activeGeoUnlockUpstreamId)
            ?? _activeGeoUnlockUpstreamIdProvider?.Invoke();
        bool isConnected = Volatile.Read(ref _isConnected);
        InterceptionMode activeMode = isConnected ? _activeMode : InterceptionMode.None;
        bool interceptionActive = isConnected && Volatile.Read(ref _interceptionActive);
        int geoUnlockRulesCount = _router?.GeoUnlockRuleCount
            ?? Volatile.Read(ref _lastRoutingConfig)?.GeoUnlockRules.Count
            ?? 0;

        return new ServiceStatusSnapshot
        {
            IsConnected = isConnected,
            IsHealthy = Volatile.Read(ref _isHealthy),
            ActiveMode = activeMode,
            RequestedMode = _options.InterceptionMode,
            InterceptionActive = interceptionActive,
            PacUrl = isConnected ? Volatile.Read(ref _activePacUrl) : null,
            ActiveLoopbackIp = isConnected ? (_activeLoopbackIp ?? _options.PreferredLoopbackAddress).ToString() : null,
            BoundDnsPort = _dnsServer?.BoundPort ?? 0,
            BoundDoHPort = _dohListener?.BoundPort ?? 0,
            BoundProxyPort = _proxyServer?.BoundEndPoint?.Port ?? 0,
            BoundPacPort = _pacServer?.BoundEndPoint?.Port ?? 0,
            CacheHitRatePercent = _cache?.HitRatePercent ?? 0.0,
            QueriesPerMinute = _dnsEngine.Telemetry.QueriesPerMinute,
            ActiveUpstreamsCount = _poolManager?.Zone4Servers.Count ?? 0,
            ActiveTrustedUpstreamId = Volatile.Read(ref _activeTrustedUpstreamId),
            ActiveGeoUnlockUpstreamId = activeGeoUpstreamId,
            ActiveGeoUnlockRulesCount = geoUnlockRulesCount,
            DirtyRecoveryPending = Volatile.Read(ref _dirtyRecoveryPending),
            LastErrorMessage = Volatile.Read(ref _lastErrorMessage),
            LatencyP50Ms = p50LatencyMs,
            InterceptionStatusDetail = Volatile.Read(ref _interceptionStatusDetail)
        };
    }

    public async Task<ServiceStatusSnapshot> ApplyConnectConfigurationAsync(
        ServiceConnectRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            bool listenerOrModeChanged = ApplyFullConfigurationLocked(
                dnsPort: request.DnsPort,
                dohPort: request.DohPort,
                proxyPort: request.ProxyPort,
                pacPort: request.PacPort,
                interceptionMode: request.InterceptionMode,
                blockIpv6OnBypass: request.BlockIpv6OnBypass,
                enableSidecarProxy: request.EnableSidecarProxy,
                enableDohListener: request.EnableDohListener,
                autoFallbackToPacOnPort53Conflict: request.AutoFallbackToPacOnPort53Conflict,
                activeTrustedUpstreamId: request.ActiveTrustedUpstreamId,
                activeGeoUnlockUpstreamId: request.ActiveGeoUnlockUpstreamId,
                routingConfig: request.RoutingConfig,
                splitDomains: request.SplitDomains,
                zone4Servers: request.Zone4Servers,
                geoUnlockUpstreams: request.GeoUnlockUpstreams,
                localBypassUpstreams: request.LocalBypassUpstreams,
                zone1Strategy: request.Zone1Strategy,
                zone3Strategy: request.Zone3Strategy,
                zone4Strategy: request.Zone4Strategy,
                blockMode: request.BlockMode,
                allowCarrierAnycastExceptions: request.AllowCarrierAnycastExceptions,
                namedCarrierEndpointId: request.NamedCarrierEndpointId,
                clearCache: request.ClearCache);

            if (Volatile.Read(ref _isConnected) && listenerOrModeChanged)
            {
                await DisconnectCoreLockedAsync(cancellationToken).ConfigureAwait(false);
            }

            return GetStatus();
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> UpdateRoutingConfigAsync(
        ServiceRoutingConfigRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ApplyRoutingLocked(request.RoutingConfig, request.SplitDomains, request.ClearCache);
            await RefreshLiveInterceptorSplitDomainsLockedAsync(cancellationToken).ConfigureAwait(false);
            return GetStatus();
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> UpdatePoolAsync(
        ServicePoolUpdateRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ApplyPoolAndEngineLocked(
                activeTrustedUpstreamId: request.ActiveTrustedUpstreamId,
                activeGeoUnlockUpstreamId: request.ActiveGeoUnlockUpstreamId,
                zone4Servers: request.Zone4Servers,
                geoUnlockUpstreams: request.GeoUnlockUpstreams,
                localBypassUpstreams: request.LocalBypassUpstreams,
                zone1Strategy: request.Zone1Strategy,
                zone3Strategy: request.Zone3Strategy,
                zone4Strategy: request.Zone4Strategy,
                blockMode: null,
                allowCarrierAnycastExceptions: null,
                namedCarrierEndpointId: null,
                clearCache: request.ClearCache);

            return GetStatus();
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> ConfigureEngineAsync(
        ServiceEngineConfigRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            bool listenerOrModeChanged = ApplyFullConfigurationLocked(
                dnsPort: request.DnsPort,
                dohPort: request.DohPort,
                proxyPort: request.ProxyPort,
                pacPort: request.PacPort,
                interceptionMode: request.InterceptionMode,
                blockIpv6OnBypass: request.BlockIpv6OnBypass,
                enableSidecarProxy: request.EnableSidecarProxy,
                enableDohListener: request.EnableDohListener,
                autoFallbackToPacOnPort53Conflict: request.AutoFallbackToPacOnPort53Conflict,
                activeTrustedUpstreamId: request.ActiveTrustedUpstreamId,
                activeGeoUnlockUpstreamId: request.ActiveGeoUnlockUpstreamId,
                routingConfig: request.RoutingConfig,
                splitDomains: request.SplitDomains,
                zone4Servers: request.Zone4Servers,
                geoUnlockUpstreams: request.GeoUnlockUpstreams,
                localBypassUpstreams: request.LocalBypassUpstreams,
                zone1Strategy: request.Zone1Strategy,
                zone3Strategy: request.Zone3Strategy,
                zone4Strategy: request.Zone4Strategy,
                blockMode: request.BlockMode,
                allowCarrierAnycastExceptions: request.AllowCarrierAnycastExceptions,
                namedCarrierEndpointId: request.NamedCarrierEndpointId,
                clearCache: request.ClearCache);

            if (Volatile.Read(ref _isConnected))
            {
                if (request.ReconnectIfNeeded && listenerOrModeChanged)
                {
                    await DisconnectCoreLockedAsync(cancellationToken).ConfigureAwait(false);
                    return await ConnectCoreLockedAsync(cancellationToken).ConfigureAwait(false);
                }

                await RefreshLiveInterceptorSplitDomainsLockedAsync(cancellationToken).ConfigureAwait(false);
            }

            return GetStatus();
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> UpdateBlocklistAsync(
        ServiceBlocklistUpdateRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SplitNamespaceRouterConfig baseConfig = _lastRoutingConfig ?? new SplitNamespaceRouterConfig();
            SplitNamespaceRouterConfig updatedConfig = baseConfig with
            {
                BlockRules = request.BlockRules ?? baseConfig.BlockRules,
                AllowExceptionRules = request.AllowExceptionRules ?? baseConfig.AllowExceptionRules
            };

            ApplyRoutingLocked(updatedConfig, splitDomains: null, request.ClearCache);
            return GetStatus();
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> ConnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ConnectCoreLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<ServiceStatusSnapshot> DisconnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await DisconnectCoreLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task<NetworkRestoredResult> EmergencyRestoreAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await StopActiveListenersLockedAsync().ConfigureAwait(false);

            IDnsInterceptor? activeInterceptor = Interlocked.Exchange(ref _activeInterceptor, null) ?? _injectedInterceptor;
            if (activeInterceptor is not null)
            {
                await SafeDeactivateInterceptorAsync(activeInterceptor, cancellationToken).ConfigureAwait(false);
            }

            NetworkRestoredResult result = _emergencyRollbackHandler is not null
                ? await _emergencyRollbackHandler(cancellationToken).ConfigureAwait(false)
                : new NetworkRestoredResult(
                    HadDirtyState: false,
                    AdaptersRestored: 0,
                    PoliciesCleaned: true,
                    Summary: "Local listeners stopped; no platform rollback delegate configured.");

            if (_journal is not null)
            {
                await SafeMarkCleanShutdownAsync(cancellationToken).ConfigureAwait(false);
            }

            Volatile.Write(ref _isConnected, false);
            Volatile.Write(ref _isHealthy, false);
            Volatile.Write(ref _interceptionActive, false);
            _activeMode = InterceptionMode.None;
            _activeLoopbackIp = null;
            Volatile.Write(ref _activePacUrl, null);
            Volatile.Write(ref _interceptionStatusDetail, null);
            Volatile.Write(ref _dirtyRecoveryPending, false);
            Volatile.Write(
                ref _lastErrorMessage,
                string.Create(CultureInfo.InvariantCulture, $"Emergency network restore completed: {result.Summary}"));

            LogEmergencyRestored(_logger, result.HadDirtyState, result.AdaptersRestored, null);
            return result;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public IReadOnlyList<DnsQueryTelemetryEvent> GetRecentTelemetry(int maxCount = 100)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxCount);
        return _dnsEngine.Telemetry.GetRecentEvents(maxCount);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Health probe must return false on any transport failure so the dead-man's switch can act.")]
    public async Task<bool> ProbeListenerHealthAsync(CancellationToken cancellationToken = default)
    {
        if (!Volatile.Read(ref _isConnected))
        {
            Volatile.Write(ref _isHealthy, false);
            return false;
        }

        LocalDnsServer? dnsServer = _dnsServer;
        IPEndPoint? tcpEndPoint = dnsServer?.BoundTcpEndPoint;
        if (dnsServer is null || tcpEndPoint is null || dnsServer.BoundPort <= 0)
        {
            Volatile.Write(ref _isHealthy, false);
            return false;
        }

        if (_options.EnableDohListener && (_dohListener is null || _dohListener.BoundPort <= 0))
        {
            Volatile.Write(ref _isHealthy, false);
            return false;
        }

        bool healthy;
        try
        {
            if (_healthProbeOverride is not null)
            {
                healthy = await _healthProbeOverride(tcpEndPoint, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                using CancellationTokenSource probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                probeCts.CancelAfter(TimeSpan.FromSeconds(1));
                using TcpClient probeClient = new();
                await probeClient.ConnectAsync(tcpEndPoint.Address, tcpEndPoint.Port, probeCts.Token).ConfigureAwait(false);
                healthy = probeClient.Connected;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            healthy = false;
        }

        Volatile.Write(ref _isHealthy, healthy);
        return healthy;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _pacServer?.Dispose();
        _proxyServer?.Dispose();
        _dohListener?.Dispose();
        _dnsServer?.Dispose();
        _lifecycleLock.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await StopActiveListenersLockedAsync().ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Dispose();
        }
    }

    private async Task<ServiceStatusSnapshot> ConnectCoreLockedAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _isConnected))
        {
            return GetStatus();
        }

        LocalDnsServer? dnsServer = null;
        LocalDohHttpListener? dohListener = null;
        TlsFragmentationProxyServer? proxyServer = null;
        AutoPacServer? pacServer = null;
        IDnsInterceptor? activeInterceptor = null;
        bool interceptorActivated = false;

        InterceptionMode requestedMode = _options.InterceptionMode;
        InterceptionMode effectiveMode = requestedMode;
        string? statusDetail = null;

        try
        {
            (IPAddress listenIp, int targetDnsPort, effectiveMode, statusDetail) = ResolveDnsEndpointAndMode(requestedMode);

            dnsServer = new LocalDnsServer(
                _dnsEngine,
                new LocalDnsServerOptions
                {
                    ListenAddress = listenIp,
                    Port = targetDnsPort
                });
            await dnsServer.StartAsync(cancellationToken).ConfigureAwait(false);

            if (_options.EnableDohListener)
            {
                dohListener = new LocalDohHttpListener(
                    _dnsEngine,
                    new LocalDohServerOptions
                    {
                        ListenAddress = listenIp,
                        Port = _options.DohPort
                    });
                await dohListener.StartAsync(cancellationToken).ConfigureAwait(false);
            }

            bool needSidecar = _options.EnableSidecarProxy || effectiveMode == InterceptionMode.LocalProxyPacOnly;
            if (needSidecar)
            {
                proxyServer = new TlsFragmentationProxyServer(
                    new TlsFragmentationProxyOptions
                    {
                        BindAddress = _options.SidecarLoopbackAddress,
                        Port = _options.ProxyPort
                    },
                    ResolveSidecarHostAsync);
                await proxyServer.StartAsync(cancellationToken).ConfigureAwait(false);

                int activeProxyPort = proxyServer.BoundEndPoint?.Port ?? _options.ProxyPort;
                pacServer = new AutoPacServer(
                    new AutoPacServerOptions
                    {
                        BindAddress = _options.SidecarLoopbackAddress,
                        Port = _options.PacPort,
                        ProxyHost = _options.SidecarLoopbackAddress.ToString(),
                        ProxyPort = activeProxyPort > 0 ? activeProxyPort : 18753
                    },
                    _splitDomains);
                await pacServer.StartAsync(cancellationToken).ConfigureAwait(false);
            }

            (activeInterceptor, effectiveMode, interceptorActivated, statusDetail) = await ActivateEffectiveInterceptorAsync(
                requestedMode,
                effectiveMode,
                listenIp,
                dnsServer.BoundPort,
                pacServer?.PacUrl,
                statusDetail,
                cancellationToken).ConfigureAwait(false);

            _dnsServer = dnsServer;
            _dohListener = dohListener;
            _proxyServer = proxyServer;
            _pacServer = pacServer;
            _activeInterceptor = activeInterceptor;
            _activeMode = effectiveMode;
            _activeLoopbackIp = listenIp;
            Volatile.Write(ref _activePacUrl, pacServer?.PacUrl);
            Volatile.Write(ref _interceptionActive, interceptorActivated);
            Volatile.Write(ref _interceptionStatusDetail, statusDetail);

            dnsServer = null;
            dohListener = null;
            proxyServer = null;
            pacServer = null;
            activeInterceptor = null;

            Volatile.Write(ref _isConnected, true);
            Volatile.Write(ref _isHealthy, true);
            Volatile.Write(ref _dirtyRecoveryPending, false);
            Volatile.Write(ref _lastErrorMessage, null);

            LogConnected(_logger, _dnsServer.BoundPort, _dohListener?.BoundPort ?? 0, effectiveMode, _activePacUrl, null);
            return GetStatus();
        }
        catch (Exception ex)
        {
            Volatile.Write(ref _isConnected, false);
            Volatile.Write(ref _isHealthy, false);
            Volatile.Write(ref _interceptionActive, false);
            _activeMode = InterceptionMode.None;
            _activeLoopbackIp = null;
            Volatile.Write(ref _activePacUrl, null);
            Volatile.Write(ref _interceptionStatusDetail, ex.Message);
            Volatile.Write(ref _lastErrorMessage, ex.Message);

            if (interceptorActivated && activeInterceptor is not null)
            {
                await SafeDeactivateInterceptorAsync(activeInterceptor, CancellationToken.None).ConfigureAwait(false);
            }

            await DisposeListenersAsync(pacServer, proxyServer, dohListener, dnsServer).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<ServiceStatusSnapshot> DisconnectCoreLockedAsync(CancellationToken cancellationToken)
    {
        IDnsInterceptor? activeInterceptor = Interlocked.Exchange(ref _activeInterceptor, null) ?? _injectedInterceptor;
        if (activeInterceptor is not null)
        {
            await SafeDeactivateInterceptorAsync(activeInterceptor, cancellationToken).ConfigureAwait(false);
        }

        await StopActiveListenersLockedAsync().ConfigureAwait(false);

        if (_journal is not null)
        {
            await SafeMarkCleanShutdownAsync(cancellationToken).ConfigureAwait(false);
        }

        Volatile.Write(ref _isConnected, false);
        Volatile.Write(ref _isHealthy, false);
        Volatile.Write(ref _interceptionActive, false);
        _activeMode = InterceptionMode.None;
        _activeLoopbackIp = null;
        Volatile.Write(ref _activePacUrl, null);
        Volatile.Write(ref _interceptionStatusDetail, null);
        LogDisconnected(_logger, null);
        return GetStatus();
    }

    private (IPAddress ListenIp, int TargetDnsPort, InterceptionMode EffectiveMode, string? StatusDetail) ResolveDnsEndpointAndMode(
        InterceptionMode requestedMode)
    {
        int configuredPort = _options.DnsPort;
        bool requiresPort53 = requestedMode is InterceptionMode.AdapterDns
            or InterceptionMode.SplitNrpt
            or InterceptionMode.WfpDivertPlugin;

        if (requiresPort53)
        {
            if (configuredPort is 53 or 0)
            {
                if (_loopbackPortSelector.TrySelectAvailableDnsEndpoint(53, _options.PreferredLoopbackAddress, out IPAddress? selected53))
                {
                    return (selected53, 53, requestedMode, null);
                }

                if (_options.AutoFallbackToPacOnPort53Conflict)
                {
                    string reason = string.Create(
                        CultureInfo.InvariantCulture,
                        $"Port 53 is unavailable on all loopback candidates; {requestedMode} fell back to LocalProxyPacOnly.");
                    LogInterceptionFallback(_logger, requestedMode, reason, null);
                    return (_options.PreferredLoopbackAddress, 0, InterceptionMode.LocalProxyPacOnly, reason);
                }

                throw new InvalidOperationException(
                    string.Create(CultureInfo.InvariantCulture, $"Port 53 is occupied on all loopback candidates; {requestedMode} cannot activate."));
            }

            if (_options.AutoFallbackToPacOnPort53Conflict)
            {
                IPAddress selectedCustom = SelectEndpointOrPreferred(configuredPort);
                string reason = string.Create(
                    CultureInfo.InvariantCulture,
                    $"{requestedMode} requires DNS port 53 (configured port {configuredPort}); activated LocalProxyPacOnly.");
                LogInterceptionFallback(_logger, requestedMode, reason, null);
                return (selectedCustom, configuredPort, InterceptionMode.LocalProxyPacOnly, reason);
            }

            throw new NotSupportedException(
                string.Create(CultureInfo.InvariantCulture, $"{requestedMode} interception requires DNS port 53, but port {configuredPort} was configured."));
        }

        if (configuredPort == 0)
        {
            return (_options.PreferredLoopbackAddress, 0, requestedMode, null);
        }

        if (configuredPort == 53 && !_loopbackPortSelector.TrySelectAvailableDnsEndpoint(53, _options.PreferredLoopbackAddress, out IPAddress? port53Ip))
        {
            string detail = string.Create(
                CultureInfo.InvariantCulture,
                $"Port 53 is occupied; {requestedMode} bound ephemeral local DNS port.");
            return (_options.PreferredLoopbackAddress, 0, requestedMode, detail);
        }

        IPAddress endpoint = configuredPort == 53
            ? _loopbackPortSelector.SelectAvailableDnsEndpoint(53)
            : SelectEndpointOrPreferred(configuredPort);
        return (endpoint, configuredPort, requestedMode, null);
    }

    private IPAddress SelectEndpointOrPreferred(int port)
    {
        return _loopbackPortSelector.TrySelectAvailableDnsEndpoint(port, _options.PreferredLoopbackAddress, out IPAddress? selected)
            ? selected
            : _options.PreferredLoopbackAddress;
    }

    private async Task<(IDnsInterceptor? Interceptor, InterceptionMode EffectiveMode, bool Activated, string? StatusDetail)> ActivateEffectiveInterceptorAsync(
        InterceptionMode requestedMode,
        InterceptionMode effectiveMode,
        IPAddress listenIp,
        int boundDnsPort,
        string? pacUrl,
        string? statusDetail,
        CancellationToken cancellationToken)
    {
        IDnsInterceptor? interceptor = ResolveInterceptorForMode(effectiveMode, pacUrl);
        if (interceptor is null)
        {
            return (null, InterceptionMode.None, false, statusDetail);
        }

        if (interceptor is LocalProxyPacInterceptor pacInterceptor && !string.IsNullOrWhiteSpace(pacUrl))
        {
            pacInterceptor.UpdatePacUrl(pacUrl);
        }

        if (_journal is not null && effectiveMode is InterceptionMode.AdapterDns or InterceptionMode.SplitNrpt)
        {
            IReadOnlyList<AdapterDnsConfiguration> adapters = Win32NetworkInterop.GetActivePhysicalAdapters();
            await _journal.BeginTransactionAsync(
                effectiveMode,
                listenIp,
                adapters,
                SmhnrPolicyManager.IsSmhnrDisabled(),
                NrptPolicyManager.GetPulseNrptRuleNames(),
                cancellationToken).ConfigureAwait(false);
        }

        try
        {
            await interceptor.ActivateAsync(listenIp, boundDnsPort, _splitDomains, cancellationToken).ConfigureAwait(false);
            string? effectiveDetail = statusDetail ?? (effectiveMode == InterceptionMode.LocalProxyPacOnly && !string.IsNullOrWhiteSpace(pacUrl)
                ? string.Create(CultureInfo.InvariantCulture, $"WinINet AutoConfigURL active: {pacUrl}")
                : null);
            return (interceptor, effectiveMode, true, effectiveDetail);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (effectiveMode != InterceptionMode.LocalProxyPacOnly
            && _options.AutoFallbackToPacOnPort53Conflict
            && !string.IsNullOrWhiteSpace(pacUrl))
        {
            await SafeDeactivateInterceptorAsync(interceptor, CancellationToken.None).ConfigureAwait(false);

            string reason = string.Create(
                CultureInfo.InvariantCulture,
                $"{requestedMode} activation failed ({ex.Message}); fell back to LocalProxyPacOnly ({pacUrl}).");
            LogInterceptionFallback(_logger, requestedMode, reason, ex);

            IDnsInterceptor fallbackInterceptor = ResolveInterceptorForMode(InterceptionMode.LocalProxyPacOnly, pacUrl)
                ?? new LocalProxyPacInterceptor(pacUrl);
            if (fallbackInterceptor is LocalProxyPacInterceptor fallbackPac)
            {
                fallbackPac.UpdatePacUrl(pacUrl);
            }

            await fallbackInterceptor.ActivateAsync(listenIp, boundDnsPort, _splitDomains, cancellationToken).ConfigureAwait(false);
            return (fallbackInterceptor, InterceptionMode.LocalProxyPacOnly, true, reason);
        }
    }

    private IDnsInterceptor? ResolveInterceptorForMode(InterceptionMode mode, string? pacUrl)
    {
        if (mode == InterceptionMode.None)
        {
            return null;
        }

        if (_interceptorFactory is not null)
        {
            return _interceptorFactory(mode, pacUrl, _options.BlockIpv6OnBypass);
        }

        if (_injectedInterceptor is not null && _injectedInterceptor.Mode == mode)
        {
            return _injectedInterceptor;
        }

        return mode switch
        {
            InterceptionMode.AdapterDns => new AdapterDnsInterceptor(_options.BlockIpv6OnBypass, disableSmhnr: true),
            InterceptionMode.SplitNrpt => new NrptSplitInterceptor(),
            InterceptionMode.LocalProxyPacOnly => new LocalProxyPacInterceptor(pacUrl),
            InterceptionMode.WfpDivertPlugin => new WfpDivertInterceptor(AntiCheatGuard.DetectActiveAntiCheat),
            _ => null
        };
    }

    private bool ApplyFullConfigurationLocked(
        int? dnsPort,
        int? dohPort,
        int? proxyPort,
        int? pacPort,
        InterceptionMode? interceptionMode,
        bool? blockIpv6OnBypass,
        bool? enableSidecarProxy,
        bool? enableDohListener,
        bool? autoFallbackToPacOnPort53Conflict,
        string? activeTrustedUpstreamId,
        string? activeGeoUnlockUpstreamId,
        SplitNamespaceRouterConfig? routingConfig,
        IReadOnlyList<string>? splitDomains,
        IReadOnlyList<DnsServerEntry>? zone4Servers,
        IReadOnlyList<DnsServerEntry>? geoUnlockUpstreams,
        IReadOnlyList<DnsServerEntry>? localBypassUpstreams,
        PoolSelectionStrategy? zone1Strategy,
        PoolSelectionStrategy? zone3Strategy,
        PoolSelectionStrategy? zone4Strategy,
        BlockResponseMode? blockMode,
        bool? allowCarrierAnycastExceptions,
        string? namedCarrierEndpointId,
        bool clearCache)
    {
        PulseServiceOptions previousOptions = _options;

        int nextDns = dnsPort is >= 0 and <= 65535 ? dnsPort.Value : previousOptions.DnsPort;
        int nextDoh = dohPort is >= 0 and <= 65535 ? dohPort.Value : previousOptions.DohPort;
        int nextProxy = proxyPort is >= 0 and <= 65535 ? proxyPort.Value : previousOptions.ProxyPort;
        int nextPac = pacPort is >= 0 and <= 65535 ? pacPort.Value : previousOptions.PacPort;
        InterceptionMode nextMode = interceptionMode.HasValue && Enum.IsDefined(interceptionMode.Value)
            ? interceptionMode.Value
            : previousOptions.InterceptionMode;
        bool nextBlockIpv6 = blockIpv6OnBypass ?? previousOptions.BlockIpv6OnBypass;
        bool nextEnableSidecar = enableSidecarProxy ?? previousOptions.EnableSidecarProxy;
        bool nextEnableDoh = enableDohListener ?? previousOptions.EnableDohListener;
        bool nextAutoFallback = autoFallbackToPacOnPort53Conflict ?? previousOptions.AutoFallbackToPacOnPort53Conflict;

        _options = previousOptions with
        {
            DnsPort = nextDns,
            DohPort = nextDoh,
            ProxyPort = nextProxy,
            PacPort = nextPac,
            InterceptionMode = nextMode,
            BlockIpv6OnBypass = nextBlockIpv6,
            EnableSidecarProxy = nextEnableSidecar,
            EnableDohListener = nextEnableDoh,
            AutoFallbackToPacOnPort53Conflict = nextAutoFallback,
            ActiveTrustedUpstreamId = activeTrustedUpstreamId is not null
                ? (string.IsNullOrWhiteSpace(activeTrustedUpstreamId) ? null : activeTrustedUpstreamId.Trim())
                : previousOptions.ActiveTrustedUpstreamId,
            ActiveGeoUnlockUpstreamId = activeGeoUnlockUpstreamId is not null
                ? (string.IsNullOrWhiteSpace(activeGeoUnlockUpstreamId) ? null : activeGeoUnlockUpstreamId.Trim())
                : previousOptions.ActiveGeoUnlockUpstreamId
        };
        Volatile.Write(ref _configuredDnsPort, nextDns);

        bool routingApplied = routingConfig is not null || splitDomains is not null;
        if (routingApplied)
        {
            ApplyRoutingLocked(routingConfig, splitDomains, clearCache: false);
        }

        ApplyPoolAndEngineLocked(
            activeTrustedUpstreamId,
            activeGeoUnlockUpstreamId,
            zone4Servers,
            geoUnlockUpstreams,
            localBypassUpstreams,
            zone1Strategy,
            zone3Strategy,
            zone4Strategy,
            blockMode,
            allowCarrierAnycastExceptions,
            namedCarrierEndpointId,
            clearCache);

        bool listenerOrModeChanged =
            previousOptions.DnsPort != nextDns ||
            previousOptions.DohPort != nextDoh ||
            previousOptions.ProxyPort != nextProxy ||
            previousOptions.PacPort != nextPac ||
            previousOptions.InterceptionMode != nextMode ||
            previousOptions.BlockIpv6OnBypass != nextBlockIpv6 ||
            previousOptions.EnableSidecarProxy != nextEnableSidecar ||
            previousOptions.EnableDohListener != nextEnableDoh;

        if (!listenerOrModeChanged && Volatile.Read(ref _isConnected))
        {
            int boundDns = _dnsServer?.BoundPort ?? 0;
            int boundDoh = _dohListener?.BoundPort ?? 0;
            int boundProxy = _proxyServer?.BoundEndPoint?.Port ?? 0;
            int boundPac = _pacServer?.BoundEndPoint?.Port ?? 0;

            listenerOrModeChanged =
                (nextDns > 0 && boundDns != nextDns) ||
                (nextDoh > 0 && boundDoh != nextDoh) ||
                (nextProxy > 0 && boundProxy != nextProxy) ||
                (nextPac > 0 && boundPac != nextPac);
        }

        return listenerOrModeChanged;
    }

    private void ApplyRoutingLocked(
        SplitNamespaceRouterConfig? routingConfig,
        IReadOnlyList<string>? splitDomains,
        bool clearCache)
    {
        if (routingConfig is not null)
        {
            Volatile.Write(ref _lastRoutingConfig, routingConfig);
            _router?.UpdateConfiguration(routingConfig);
        }

        if (splitDomains is not null)
        {
            _splitDomains = NormalizeSplitDomains(splitDomains);
        }
        else if (routingConfig is not null)
        {
            _splitDomains = ExtractSplitDomainsFromConfig(routingConfig);
        }

        _pacServer?.UpdateSplitDomains(_splitDomains);

        if (clearCache)
        {
            _cache?.Clear();
        }
    }

    private void ApplyPoolAndEngineLocked(
        string? activeTrustedUpstreamId,
        string? activeGeoUnlockUpstreamId,
        IReadOnlyList<DnsServerEntry>? zone4Servers,
        IReadOnlyList<DnsServerEntry>? geoUnlockUpstreams,
        IReadOnlyList<DnsServerEntry>? localBypassUpstreams,
        PoolSelectionStrategy? zone1Strategy,
        PoolSelectionStrategy? zone3Strategy,
        PoolSelectionStrategy? zone4Strategy,
        BlockResponseMode? blockMode,
        bool? allowCarrierAnycastExceptions,
        string? namedCarrierEndpointId,
        bool clearCache)
    {
        if (zone4Servers is not null)
        {
            _poolManager?.UpdateZone4Pool(zone4Servers);
            if (activeTrustedUpstreamId is null && zone4Servers.Count > 0)
            {
                activeTrustedUpstreamId = zone4Servers[0].Id;
            }
        }

        if (activeTrustedUpstreamId is not null)
        {
            string? normalizedTrusted = string.IsNullOrWhiteSpace(activeTrustedUpstreamId)
                ? null
                : activeTrustedUpstreamId.Trim();
            Volatile.Write(ref _activeTrustedUpstreamId, normalizedTrusted);
        }

        if (activeGeoUnlockUpstreamId is not null)
        {
            SetActiveGeoUnlockUpstreamId(activeGeoUnlockUpstreamId);
        }
        else if (geoUnlockUpstreams is { Count: > 0 } && Volatile.Read(ref _activeGeoUnlockUpstreamId) is null)
        {
            SetActiveGeoUnlockUpstreamId(geoUnlockUpstreams[0].Id);
        }

        PulseCoreEngineOptions updatedEngineOptions = _engineOptions with
        {
            LocalBypassUpstreams = localBypassUpstreams ?? _engineOptions.LocalBypassUpstreams,
            GeoUnlockUpstreams = geoUnlockUpstreams ?? _engineOptions.GeoUnlockUpstreams,
            Zone1Strategy = zone1Strategy ?? _engineOptions.Zone1Strategy,
            Zone3Strategy = zone3Strategy ?? _engineOptions.Zone3Strategy,
            Zone4Strategy = zone4Strategy ?? _engineOptions.Zone4Strategy,
            BlockMode = blockMode ?? _engineOptions.BlockMode,
            AllowCarrierAnycastExceptions = allowCarrierAnycastExceptions ?? _engineOptions.AllowCarrierAnycastExceptions,
            NamedCarrierEndpointId = namedCarrierEndpointId ?? _engineOptions.NamedCarrierEndpointId
        };

        _engineOptions = updatedEngineOptions;
        _dnsEngine.UpdateOptions(updatedEngineOptions);

        if (clearCache)
        {
            _cache?.Clear();
        }
    }

    private async Task RefreshLiveInterceptorSplitDomainsLockedAsync(CancellationToken cancellationToken)
    {
        if (!Volatile.Read(ref _isConnected)
            || _activeInterceptor is null
            || _activeInterceptor.Mode != InterceptionMode.SplitNrpt
            || _activeLoopbackIp is null
            || _dnsServer is null
            || _dnsServer.BoundPort != 53)
        {
            return;
        }

        await _activeInterceptor.ActivateAsync(
            _activeLoopbackIp,
            _dnsServer.BoundPort,
            _splitDomains,
            cancellationToken).ConfigureAwait(false);
    }

    private static string[] ExtractSplitDomainsFromConfig(SplitNamespaceRouterConfig config)
    {
        List<string> raw = new(config.GeoUnlockRules.Count);
        foreach (GeoUnlockRule rule in config.GeoUnlockRules)
        {
            if (rule is null || string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            if (RuleParsers.TryParseGeoSiteLine(rule.Pattern.AsSpan().Trim(), out GeoSiteRule? geoSite) && geoSite is not null)
            {
                raw.Add(geoSite.Domain);
            }
            else
            {
                raw.Add(rule.Pattern.Trim().TrimStart('*').TrimStart('.'));
            }
        }

        return NormalizeSplitDomains(raw);
    }

    private static string[] NormalizeSplitDomains(IEnumerable<string> domains)
    {
        HashSet<string> unique = new(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in domains)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            string candidate = raw.Trim();
            if (candidate.StartsWith("*.", StringComparison.Ordinal))
            {
                candidate = candidate[2..];
            }

            candidate = candidate.Trim('.');
            if (candidate.Length > 0)
            {
                unique.Add(candidate);
            }
        }

        return [.. unique];
    }

    private async Task StopActiveListenersLockedAsync()
    {
        AutoPacServer? pac = Interlocked.Exchange(ref _pacServer, null);
        TlsFragmentationProxyServer? proxy = Interlocked.Exchange(ref _proxyServer, null);
        LocalDohHttpListener? doh = Interlocked.Exchange(ref _dohListener, null);
        LocalDnsServer? dns = Interlocked.Exchange(ref _dnsServer, null);

        await DisposeListenersAsync(pac, proxy, doh, dns).ConfigureAwait(false);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Shutdown/rollback must continue disposing remaining listeners even if one throws.")]
    private async Task DisposeListenersAsync(
        AutoPacServer? pacServer,
        TlsFragmentationProxyServer? proxyServer,
        LocalDohHttpListener? dohListener,
        LocalDnsServer? dnsServer)
    {
        if (pacServer is not null)
        {
            try
            {
                await pacServer.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogNonFatalTeardownError(_logger, ex);
            }
        }

        if (proxyServer is not null)
        {
            try
            {
                await proxyServer.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogNonFatalTeardownError(_logger, ex);
            }
        }

        if (dohListener is not null)
        {
            try
            {
                await dohListener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogNonFatalTeardownError(_logger, ex);
            }
        }

        if (dnsServer is not null)
        {
            try
            {
                await dnsServer.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogNonFatalTeardownError(_logger, ex);
            }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Interceptor deactivation errors must not prevent emergency network restoration.")]
    private async Task SafeDeactivateInterceptorAsync(IDnsInterceptor interceptor, CancellationToken cancellationToken)
    {
        try
        {
            await interceptor.DeactivateAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogNonFatalTeardownError(_logger, ex);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Clean shutdown journal update must not fail disconnect.")]
    private async Task SafeMarkCleanShutdownAsync(CancellationToken cancellationToken)
    {
        if (_journal is null)
        {
            return;
        }

        try
        {
            await _journal.MarkCleanShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogNonFatalTeardownError(_logger, ex);
        }
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveSidecarHostAsync(
        string host,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return [];
        }

        return await _dnsEngine.ResolveHostAddressesForProxyAsync(
            host,
            _sidecarHostResolver,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<IPAddress>> ResolveHostFallbackAsync(
        string host,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        return addresses;
    }
}
