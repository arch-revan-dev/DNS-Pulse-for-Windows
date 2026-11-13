using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Engine.Cache;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Hosting;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Engine.Sidecar;
using DnsPulse.Platform.Windows.Contracts;
using Microsoft.Extensions.Logging.Abstractions;

namespace DnsPulse.Service;

/// <summary>
/// Coordinates PulseCore local listeners (<see cref="LocalDnsServer"/>, <see cref="LocalDohHttpListener"/>,
/// <see cref="TlsFragmentationProxyServer"/>, <see cref="AutoPacServer"/>), an optional Windows
/// <see cref="IDnsInterceptor"/>, and an emergency network rollback delegate.
/// </summary>
public sealed class DefaultPulseRuntimeBackend : IPulseRuntimeBackend, IAsyncDisposable, IDisposable
{
    private static readonly Action<ILogger, int, int, Exception?> LogConnected =
        LoggerMessage.Define<int, int>(
            LogLevel.Information,
            new EventId(1001, nameof(LogConnected)),
            "Pulse runtime connected (DNS port {DnsPort}, DoH port {DohPort}).");

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

    private readonly PulseServiceOptions _options;
    private readonly PulseCoreDnsEngine _dnsEngine;
    private readonly OptimisticDnsCache? _cache;
    private readonly UpstreamPoolManager? _poolManager;
    private readonly IDnsInterceptor? _dnsInterceptor;
    private readonly Func<CancellationToken, Task<NetworkRestoredResult>>? _emergencyRollbackHandler;
    private readonly Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> _sidecarHostResolver;
    private readonly IReadOnlyList<string> _splitDomains;
    private readonly Func<IPEndPoint, CancellationToken, Task<bool>>? _healthProbeOverride;
    private readonly ILogger<DefaultPulseRuntimeBackend> _logger;
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);

    private LocalDnsServer? _dnsServer;
    private LocalDohHttpListener? _dohListener;
    private TlsFragmentationProxyServer? _proxyServer;
    private AutoPacServer? _pacServer;
    private bool _isConnected;
    private bool _isHealthy;
    private bool _dirtyRecoveryPending;
    private string? _lastErrorMessage;
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
        ILogger<DefaultPulseRuntimeBackend>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dnsEngine);

        _options = options;
        _dnsEngine = dnsEngine;
        _cache = cache;
        _poolManager = poolManager;
        _dnsInterceptor = dnsInterceptor;
        _emergencyRollbackHandler = emergencyRollbackHandler;
        _sidecarHostResolver = sidecarHostResolver ?? ResolveHostFallbackAsync;
        _splitDomains = initialSplitDomains ?? [];
        _healthProbeOverride = healthProbeOverride;
        _logger = logger ?? NullLogger<DefaultPulseRuntimeBackend>.Instance;
    }

    public ServiceStatusSnapshot GetStatus()
    {
        return new ServiceStatusSnapshot
        {
            IsConnected = Volatile.Read(ref _isConnected),
            IsHealthy = Volatile.Read(ref _isHealthy),
            ActiveMode = _dnsInterceptor?.Mode ?? (_isConnected ? _options.InterceptionMode : InterceptionMode.None),
            ActiveLoopbackIp = Volatile.Read(ref _isConnected) ? _options.PreferredLoopbackAddress.ToString() : null,
            BoundDnsPort = _dnsServer?.BoundPort ?? 0,
            BoundDoHPort = _dohListener?.BoundPort ?? 0,
            BoundProxyPort = _proxyServer?.BoundEndPoint?.Port ?? 0,
            BoundPacPort = _pacServer?.BoundEndPoint?.Port ?? 0,
            CacheHitRatePercent = _cache?.HitRatePercent ?? 0.0,
            QueriesPerMinute = _dnsEngine.Telemetry.QueriesPerMinute,
            ActiveUpstreamsCount = _poolManager?.Zone4Servers.Count ?? 0,
            DirtyRecoveryPending = Volatile.Read(ref _dirtyRecoveryPending),
            LastErrorMessage = Volatile.Read(ref _lastErrorMessage)
        };
    }

    public async Task<ServiceStatusSnapshot> ConnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _isConnected))
            {
                return GetStatus();
            }

            LocalDnsServer? dnsServer = null;
            LocalDohHttpListener? dohListener = null;
            TlsFragmentationProxyServer? proxyServer = null;
            AutoPacServer? pacServer = null;
            bool interceptorActivated = false;

            try
            {
                dnsServer = new LocalDnsServer(
                    _dnsEngine,
                    new LocalDnsServerOptions
                    {
                        ListenAddress = _options.PreferredLoopbackAddress,
                        Port = _options.DnsPort
                    });
                await dnsServer.StartAsync(cancellationToken).ConfigureAwait(false);

                if (_options.EnableDohListener)
                {
                    dohListener = new LocalDohHttpListener(
                        _dnsEngine,
                        new LocalDohServerOptions
                        {
                            ListenAddress = _options.PreferredLoopbackAddress,
                            Port = _options.DohPort
                        });
                    await dohListener.StartAsync(cancellationToken).ConfigureAwait(false);
                }

                if (_options.EnableSidecarProxy)
                {
                    proxyServer = new TlsFragmentationProxyServer(
                        new TlsFragmentationProxyOptions
                        {
                            BindAddress = _options.SidecarLoopbackAddress,
                            Port = _options.ProxyPort
                        },
                        _sidecarHostResolver);
                    await proxyServer.StartAsync(cancellationToken).ConfigureAwait(false);

                    int activeProxyPort = proxyServer.BoundEndPoint?.Port ?? _options.ProxyPort;
                    pacServer = new AutoPacServer(
                        new AutoPacServerOptions
                        {
                            BindAddress = _options.SidecarLoopbackAddress,
                            Port = _options.PacPort,
                            ProxyHost = _options.SidecarLoopbackAddress.ToString(),
                            ProxyPort = activeProxyPort > 0 ? activeProxyPort : 10808
                        },
                        _splitDomains);
                    await pacServer.StartAsync(cancellationToken).ConfigureAwait(false);
                }

                if (_dnsInterceptor is not null)
                {
                    await _dnsInterceptor.ActivateAsync(
                        _options.PreferredLoopbackAddress,
                        dnsServer.BoundPort,
                        _splitDomains,
                        cancellationToken).ConfigureAwait(false);
                    interceptorActivated = true;
                }

                _dnsServer = dnsServer;
                _dohListener = dohListener;
                _proxyServer = proxyServer;
                _pacServer = pacServer;
                dnsServer = null;
                dohListener = null;
                proxyServer = null;
                pacServer = null;

                Volatile.Write(ref _isConnected, true);
                Volatile.Write(ref _isHealthy, true);
                Volatile.Write(ref _dirtyRecoveryPending, false);
                Volatile.Write(ref _lastErrorMessage, null);

                LogConnected(_logger, _dnsServer.BoundPort, _dohListener?.BoundPort ?? 0, null);
                return GetStatus();
            }
            catch (Exception ex)
            {
                Volatile.Write(ref _isConnected, false);
                Volatile.Write(ref _isHealthy, false);
                Volatile.Write(ref _lastErrorMessage, ex.Message);

                if (interceptorActivated && _dnsInterceptor is not null)
                {
                    await SafeDeactivateInterceptorAsync(CancellationToken.None).ConfigureAwait(false);
                }

                await DisposeListenersAsync(pacServer, proxyServer, dohListener, dnsServer).ConfigureAwait(false);
                throw;
            }
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
            if (_dnsInterceptor is not null)
            {
                await SafeDeactivateInterceptorAsync(cancellationToken).ConfigureAwait(false);
            }

            await StopActiveListenersLockedAsync().ConfigureAwait(false);
            Volatile.Write(ref _isConnected, false);
            Volatile.Write(ref _isHealthy, false);
            LogDisconnected(_logger, null);
            return GetStatus();
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

            if (_dnsInterceptor is not null)
            {
                await SafeDeactivateInterceptorAsync(cancellationToken).ConfigureAwait(false);
            }

            NetworkRestoredResult result = _emergencyRollbackHandler is not null
                ? await _emergencyRollbackHandler(cancellationToken).ConfigureAwait(false)
                : new NetworkRestoredResult(
                    HadDirtyState: false,
                    AdaptersRestored: 0,
                    PoliciesCleaned: true,
                    Summary: "Local listeners stopped; no platform rollback delegate configured.");

            Volatile.Write(ref _isConnected, false);
            Volatile.Write(ref _isHealthy, false);
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
    private async Task SafeDeactivateInterceptorAsync(CancellationToken cancellationToken)
    {
        if (_dnsInterceptor is null)
        {
            return;
        }

        try
        {
            await _dnsInterceptor.DeactivateAsync(cancellationToken).ConfigureAwait(false);
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

    private static async Task<IReadOnlyList<IPAddress>> ResolveHostFallbackAsync(
        string host,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        return addresses;
    }
}
