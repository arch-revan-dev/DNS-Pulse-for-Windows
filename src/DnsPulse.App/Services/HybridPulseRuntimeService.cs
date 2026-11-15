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
    private IPEndPoint? _localDnsEndPoint;
    private LocalDohHttpListener? _localDohListener;
    private TlsFragmentationProxyServer? _localProxyServer;
    private AutoPacServer? _localPacServer;
    private IDnsInterceptor? _activeInterceptor;
    private LocalProxyPacInterceptor? _sessionPacInterceptor;
    private string? _sessionPacUrl;
    private string? _activeInterceptionStatusDetail;
    private ServiceStatusSnapshot _currentStatus = new();
    private DnsServerEntry? _activeTrustedUpstream;
    private DnsServerEntry? _activeGeoUnlockUpstream;
    private IReadOnlyList<DnsServerEntry> _geoUnlockUpstreams = [];
    private IReadOnlyList<DnsServerEntry> _catalogSnapshot = BuiltInCatalogPresets.BuildFlagshipServers();
    private SplitNamespaceRouterConfig _routingConfig = new();
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
        _hostHealthProvider = hostHealthProvider ?? new HostNetworkHealthProvider(
            enableOsProbes: true,
            desiredDnsPortProvider: () => _lastSettings.LocalDnsPort);
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

    public void SetCatalogSnapshot(IReadOnlyList<DnsServerEntry> catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        _catalogSnapshot = [.. catalog];
    }

    public async Task<DiagnosticReport> ResolveEffectiveQuickProbeAsync(
        DnsServerEntry upstream,
        string targetDomain,
        DiagnosticProbeOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDomain);
        ObjectDisposedException.ThrowIf(_disposed, this);

        SixLayerDiagnosticEngine engine = CreateDiagnosticEngine();
        DiagnosticProbeOptions effectiveOptions = options ?? new DiagnosticProbeOptions
        {
            TransportProbeSamples = 2,
            ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(_lastSettings.ProbeTimeoutMs, 1200, 6000)),
            IncludeTlsAndApplicationProbes = true,
            ProbeCompanionDomains = true
        };

        DiagnosticReport report = await engine.DiagnoseAsync(targetDomain.Trim(), upstream, effectiveOptions, cancellationToken).ConfigureAwait(false);
        string layerIssues = string.Join("; ", report.Layers
            .Where(static l => l.Status is DiagnosticLayerStatus.Warning or DiagnosticLayerStatus.Failed)
            .Select(static l => $"L{l.LayerNumber}:{l.Status}({l.Summary})"));
        Log.Information(
            "QuickProbe finished: Upstream={UpstreamId} ({Protocol}), Verdict={Verdict}, P50={LatencyMs}ms, TlsOk={TlsOk}, Http={HttpStatus}, Companion={Companion}, Issues=[{Issues}]",
            upstream.Id,
            upstream.Protocol,
            report.Verdict,
            report.LatencyP50Ms?.ToString("F1", CultureInfo.InvariantCulture) ?? "n/a",
            report.TlsHandshakeSucceeded,
            report.HttpStatusCode?.ToString(CultureInfo.InvariantCulture) ?? "n/a",
            report.CompanionPassed?.ToString() ?? "n/a",
            layerIssues);

        return report;
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
            await SyncSessionPacInterceptorAsync(ipcStatus, cancellationToken).ConfigureAwait(false);
            UpdateSnapshot(ipcStatus);
            return ipcStatus;
        }

        _isServiceMode = false;
        await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);
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

            Log.Information(
                "Connect requested (Trusted={TrustedId}, GeoUnlock={GeoId}, Mode={Mode}, RequestedPorts=[DNS:{DnsPort}, DoH:{DohPort}, Proxy:{ProxyPort}, PAC:{PacPort}], Elevated={Elevated})",
                _activeTrustedUpstream?.Id ?? "none",
                _activeGeoUnlockUpstream?.Id ?? "none",
                effectiveSettings.InterceptionMode,
                effectiveSettings.LocalDnsPort,
                effectiveSettings.LocalDohPort,
                effectiveSettings.LocalProxyPort,
                effectiveSettings.LocalPacPort,
                IsElevated);

            ServiceConnectRequest connectRequest = BuildConnectRequest(effectiveSettings);

            ServiceStatusSnapshot? ipcStatus = await TrySendIpcAsync<ServiceStatusSnapshot>(
                PipeCommandNames.Connect,
                payload: connectRequest,
                cancellationToken).ConfigureAwait(false);

            if (ipcStatus is not null)
            {
                _isServiceMode = true;
                await SyncSessionPacInterceptorAsync(ipcStatus, cancellationToken).ConfigureAwait(false);
                UpdateSnapshot(ipcStatus);
                Log.Information(
                    "Connected via DnsPulseService IPC (Mode={Mode}, Active={Active}, DNS:{DnsPort}, DoH:{DohPort}, Proxy:{ProxyPort}, PAC:{PacPort})",
                    ipcStatus.ActiveMode,
                    ipcStatus.InterceptionActive,
                    ipcStatus.BoundDnsPort,
                    ipcStatus.BoundDoHPort,
                    ipcStatus.BoundProxyPort,
                    ipcStatus.BoundPacPort);
                return ipcStatus;
            }

            _isServiceMode = false;
            await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);
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

                await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);

                if (ipcStatus is not null)
                {
                    UpdateSnapshot(ipcStatus);
                    return ipcStatus;
                }
            }

            await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);
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

        if (_currentStatus.IsConnected && _isServiceMode)
        {
            await TrySendIpcAsync<ServiceStatusSnapshot>(
                PipeCommandNames.UpdatePool,
                BuildPoolUpdateRequest(_lastSettings),
                cancellationToken).ConfigureAwait(false);
        }
        else if (_currentStatus.IsConnected && !_isServiceMode)
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
            await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);

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
                        InterceptionActive = false,
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

    public async Task UpdateRoutingConfigAsync(
        SplitNamespaceRouterConfig config,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        _routingConfig = config;
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

        if (_isServiceMode)
        {
            ServiceStatusSnapshot? ipcStatus = await TrySendIpcAsync<ServiceStatusSnapshot>(
                PipeCommandNames.UpdateRoutingConfig,
                new ServiceRoutingConfigRequest(
                    RoutingConfig: _routingConfig,
                    SplitDomains: [.. _activeSplitDomains],
                    ClearCache: true),
                cancellationToken).ConfigureAwait(false);

            if (ipcStatus is not null)
            {
                await SyncSessionPacInterceptorAsync(ipcStatus, cancellationToken).ConfigureAwait(false);
                UpdateSnapshot(ipcStatus);
            }
        }
    }

    public async Task UpdateEngineOptionsAsync(
        PulseAppSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        PulseAppSettings previousSettings = _lastSettings;
        _lastSettings = settings.Clone();
        ConfigureEngineUpstreams(_activeTrustedUpstream, _activeGeoUnlockUpstream, fallbackPool: null, settings);

        bool listenersActive = _currentStatus.IsConnected &&
            (previousSettings.LocalDnsPort != settings.LocalDnsPort ||
             previousSettings.LocalDohPort != settings.LocalDohPort ||
             previousSettings.LocalProxyPort != settings.LocalProxyPort ||
             previousSettings.LocalPacPort != settings.LocalPacPort ||
             previousSettings.InterceptionMode != settings.InterceptionMode);

        if (_isServiceMode)
        {
            ServiceStatusSnapshot? ipcStatus = await TrySendIpcAsync<ServiceStatusSnapshot>(
                PipeCommandNames.ConfigureEngine,
                BuildEngineConfigRequest(settings, reconnectIfNeeded: listenersActive),
                cancellationToken).ConfigureAwait(false);

            if (ipcStatus is not null)
            {
                await SyncSessionPacInterceptorAsync(ipcStatus, cancellationToken).ConfigureAwait(false);
                UpdateSnapshot(ipcStatus);
                return;
            }
        }

        if (listenersActive)
        {
            Log.Information(
                "Port or interception settings changed while connected (Ports [{OldDns},{OldDoh},{OldProxy},{OldPac}] -> [{NewDns},{NewDoh},{NewProxy},{NewPac}], Mode {OldMode} -> {NewMode}); reconnecting.",
                previousSettings.LocalDnsPort,
                previousSettings.LocalDohPort,
                previousSettings.LocalProxyPort,
                previousSettings.LocalPacPort,
                settings.LocalDnsPort,
                settings.LocalDohPort,
                settings.LocalProxyPort,
                settings.LocalPacPort,
                previousSettings.InterceptionMode,
                settings.InterceptionMode);

            await DisconnectAsync(cancellationToken).ConfigureAwait(false);
            await ConnectAsync(_activeTrustedUpstream, _activeGeoUnlockUpstream, null, settings, cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<HostNetworkHealthSnapshot> InspectHostHealthAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _hostHealthProvider.InspectAsync(cancellationToken);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Dispose must remain exception-safe when tearing down session WinINet PAC state.")]
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dnsEngine.Telemetry.EventRecorded -= OnEngineTelemetryRecorded;

        try
        {
            _sessionPacInterceptor?.DeactivateAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception)
        {
        }

        _sessionPacInterceptor = null;
        _sessionPacUrl = null;

        _localPacServer?.Dispose();
        _localProxyServer?.Dispose();
        _localDohListener?.Dispose();
        _localDnsServer?.Dispose();
        _localPacServer = null;
        _localProxyServer = null;
        _localDohListener = null;
        _localDnsServer = null;
        _localDnsEndPoint = null;

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

        await ClearSessionPacInterceptorAsync(CancellationToken.None).ConfigureAwait(false);
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

        List<DnsServerEntry> geoList = [];
        if (_activeGeoUnlockUpstream is not null)
        {
            geoList.Add(_activeGeoUnlockUpstream);
        }

        bool aiBypassActive = _activeSplitDomains.Any(ServerCategoryClassifier.IsAiDomain)
            || (_activeGeoUnlockUpstream is not null && ServerCategoryClassifier.SupportsAiDomain(_activeGeoUnlockUpstream));

        IEnumerable<DnsServerEntry> poolSource = fallbackPool is not null
            ? fallbackPool.Concat(_catalogSnapshot)
            : _catalogSnapshot;

        IEnumerable<DnsServerEntry> geoFallbacks = poolSource
            .Where(candidate =>
                candidate is not null
                && TrustTierPolicy.CanServeGeoUnlock(candidate.TrustTier)
                && (!aiBypassActive || ServerCategoryClassifier.SupportsAiDomain(candidate))
                && !geoList.Any(existing => string.Equals(existing.Id, candidate.Id, StringComparison.OrdinalIgnoreCase)))
            .GroupBy(static candidate => candidate.Id, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderBy(static candidate => candidate.Verdict switch
            {
                DiagnosticVerdict.Healthy => 0,
                DiagnosticVerdict.TlsSniDpiReset => 1,
                DiagnosticVerdict.Unknown => 2,
                _ => 3
            })
            .ThenBy(static candidate => candidate.CompanionPassed == true ? 0 : 1)
            .ThenBy(static candidate => candidate.IsEncrypted ? 0 : 1)
            .ThenBy(candidate => aiBypassActive && ServerCategoryClassifier.HasExplicitAiTag(candidate) ? 0 : 1)
            .ThenBy(static candidate => candidate.IsFavorite ? 0 : 1)
            .ThenBy(static candidate => candidate.LatencyP50Ms ?? candidate.LastLatencyMs ?? double.MaxValue)
            .Take(4);

        geoList.AddRange(geoFallbacks);
        _geoUnlockUpstreams = [.. geoList];

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
        bool wantsSystemDns = elevated
            && settings.LocalDnsPort == 53
            && settings.InterceptionMode is InterceptionMode.AdapterDns or InterceptionMode.SplitNrpt or InterceptionMode.WfpDivertPlugin;

        try
        {
            IPAddress loopbackIp = IPAddress.Loopback;
            int desiredDnsPort = 0;

            if (settings.LocalDnsPort == 0)
            {
                desiredDnsPort = 0;
            }
            else if (settings.LocalDnsPort == 53)
            {
                if (wantsSystemDns)
                {
                    try
                    {
                        loopbackIp = _portSelector.SelectAvailableDnsEndpoint(53);
                        desiredDnsPort = 53;
                    }
                    catch (InvalidOperationException ex)
                    {
                        Log.Warning(ex, "Loopback port 53 is unavailable; falling back to auto ephemeral port and LocalProxyPacOnly.");
                        loopbackIp = IPAddress.Loopback;
                        desiredDnsPort = 0;
                    }
                }
                else
                {
                    Log.Information("Using auto ephemeral DNS port because mode={Mode}, elevated={Elevated}.", settings.InterceptionMode, elevated);
                    desiredDnsPort = 0;
                }
            }
            else
            {
                desiredDnsPort = settings.LocalDnsPort;
                try
                {
                    loopbackIp = _portSelector.SelectAvailableDnsEndpoint(desiredDnsPort);
                }
                catch (InvalidOperationException ex)
                {
                    Log.Warning(ex, "Configured custom DNS port {DnsPort} could not pre-bind all fallback loopbacks; attempting direct bind on {Loopback}.", desiredDnsPort, loopbackIp);
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
                    Port = settings.LocalDohPort
                });
            await dohListener.StartAsync(cancellationToken).ConfigureAwait(false);

            proxyServer = new TlsFragmentationProxyServer(
                new TlsFragmentationProxyOptions
                {
                    BindAddress = IPAddress.Loopback,
                    Port = settings.LocalProxyPort
                },
                ResolveSidecarHostAsync);
            await proxyServer.StartAsync(cancellationToken).ConfigureAwait(false);

            int proxyPort = proxyServer.BoundEndPoint?.Port ?? (settings.LocalProxyPort > 0 ? settings.LocalProxyPort : 10808);
            pacServer = new AutoPacServer(
                new AutoPacServerOptions
                {
                    BindAddress = IPAddress.Loopback,
                    Port = settings.LocalPacPort,
                    ProxyHost = IPAddress.Loopback.ToString(),
                    ProxyPort = proxyPort
                },
                _activeSplitDomains);
            await pacServer.StartAsync(cancellationToken).ConfigureAwait(false);

            _activeInterceptionStatusDetail = null;

            InterceptionMode effectiveMode = elevated ? settings.InterceptionMode : InterceptionMode.LocalProxyPacOnly;
            if (dnsServer.BoundPort != 53 && effectiveMode is InterceptionMode.AdapterDns or InterceptionMode.SplitNrpt or InterceptionMode.WfpDivertPlugin)
            {
                effectiveMode = InterceptionMode.LocalProxyPacOnly;
            }

            if (effectiveMode != settings.InterceptionMode)
            {
                _activeInterceptionStatusDetail = string.Create(
                    CultureInfo.InvariantCulture,
                    $"Fallback to {effectiveMode} (DNS port {dnsServer.BoundPort}, Elevated={elevated}).");
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

                try
                {
                    await interceptor.ActivateAsync(
                        loopbackIp,
                        dnsServer.BoundPort,
                        _activeSplitDomains,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException && effectiveMode != InterceptionMode.LocalProxyPacOnly)
                {
                    Log.Warning(ex, "Portable mode {Mode} activation failed; falling back to LocalProxyPacOnly.", effectiveMode);
                    try
                    {
                        await interceptor.DeactivateAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                    }

                    _activeInterceptionStatusDetail = string.Create(
                        CultureInfo.InvariantCulture,
                        $"Fallback to LocalProxyPacOnly after {effectiveMode} failed: {ex.Message}");
                    interceptor = CreatePortableInterceptor(InterceptionMode.LocalProxyPacOnly, pacUrl, settings.BlockIpv6OnBypass)!;
                    await interceptor.ActivateAsync(
                        loopbackIp,
                        dnsServer.BoundPort,
                        _activeSplitDomains,
                        cancellationToken).ConfigureAwait(false);
                }
            }

            _localDnsServer = dnsServer;
            _localDnsEndPoint = dnsServer.BoundTcpEndPoint ?? dnsServer.BoundUdpEndPoint ?? new IPEndPoint(loopbackIp, dnsServer.BoundPort);
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
            Log.Error(ex, "Portable mode connect failed (RequestedPorts=[DNS:{DnsPort}, DoH:{DohPort}, Proxy:{ProxyPort}, PAC:{PacPort}]).",
                settings.LocalDnsPort,
                settings.LocalDohPort,
                settings.LocalProxyPort,
                settings.LocalPacPort);
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
        _localDnsEndPoint = null;

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
        InterceptionMode activeMode = connected && _activeInterceptor is not null
            ? _activeInterceptor.Mode
            : InterceptionMode.None;
        bool interceptionActive = connected && _activeInterceptor is not null && activeMode != InterceptionMode.None;

        return new ServiceStatusSnapshot
        {
            IsConnected = connected,
            IsHealthy = connected && interceptionActive,
            ActiveMode = activeMode,
            RequestedMode = _lastSettings.InterceptionMode,
            InterceptionActive = interceptionActive,
            PacUrl = connected ? _localPacServer?.PacUrl : null,
            ActiveLoopbackIp = connected ? (_localDnsEndPoint?.Address.ToString() ?? IPAddress.Loopback.ToString()) : null,
            BoundDnsPort = _localDnsServer?.BoundPort ?? 0,
            BoundDoHPort = _localDohListener?.BoundPort ?? 0,
            BoundProxyPort = _localProxyServer?.BoundEndPoint?.Port ?? 0,
            BoundPacPort = _localPacServer?.BoundEndPoint?.Port ?? 0,
            CacheHitRatePercent = _cache.HitRatePercent,
            QueriesPerMinute = _dnsEngine.Telemetry.QueriesPerMinute,
            ActiveUpstreamsCount = _poolManager.Zone4Servers.Count,
            DirtyRecoveryPending = false,
            LastErrorMessage = lastError,
            LatencyP50Ms = _dnsEngine.Telemetry.Count > 0 ? _dnsEngine.Telemetry.P50LatencyMs : null,
            ActiveTrustedUpstreamId = _activeTrustedUpstream?.Id,
            ActiveGeoUnlockUpstreamId = _activeGeoUnlockUpstream?.Id,
            ActiveGeoUnlockRulesCount = _routingConfig.GeoUnlockRules.Count,
            InterceptionStatusDetail = connected ? _activeInterceptionStatusDetail : null
        };
    }

    private Task<IReadOnlyList<IPAddress>> ResolveSidecarHostAsync(
        string host,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return Task.FromResult<IReadOnlyList<IPAddress>>([]);
        }

        return _dnsEngine.ResolveHostAddressesForProxyAsync(
            host,
            (h, ct) => _bootstrapResolver.ResolveHostAsync(h, ct),
            cancellationToken);
    }

    private ServiceConnectRequest BuildConnectRequest(PulseAppSettings settings) => new(
        DnsPort: settings.LocalDnsPort,
        DohPort: settings.LocalDohPort,
        ProxyPort: settings.LocalProxyPort,
        PacPort: settings.LocalPacPort,
        InterceptionMode: settings.InterceptionMode,
        BlockIpv6OnBypass: settings.BlockIpv6OnBypass,
        EnableSidecarProxy: settings.EnableLocalTlsSplitPac,
        EnableDohListener: settings.UseLocalDohEndpoint,
        AutoFallbackToPacOnPort53Conflict: true,
        StrategyProfile: settings.StrategyProfile,
        ActiveTrustedUpstreamId: _activeTrustedUpstream?.Id,
        ActiveGeoUnlockUpstreamId: _activeGeoUnlockUpstream?.Id,
        RoutingConfig: _routingConfig,
        SplitDomains: [.. _activeSplitDomains],
        Zone4Servers: [.. _poolManager.Zone4Servers],
        GeoUnlockUpstreams: [.. _geoUnlockUpstreams],
        Zone1Strategy: PoolSelectionStrategy.Fastest,
        Zone3Strategy: PoolSelectionStrategy.Failover,
        Zone4Strategy: settings.PoolStrategy,
        ClearCache: true);

    private ServiceEngineConfigRequest BuildEngineConfigRequest(PulseAppSettings settings, bool reconnectIfNeeded) => new(
        DnsPort: settings.LocalDnsPort,
        DohPort: settings.LocalDohPort,
        ProxyPort: settings.LocalProxyPort,
        PacPort: settings.LocalPacPort,
        InterceptionMode: settings.InterceptionMode,
        BlockIpv6OnBypass: settings.BlockIpv6OnBypass,
        EnableSidecarProxy: settings.EnableLocalTlsSplitPac,
        EnableDohListener: settings.UseLocalDohEndpoint,
        AutoFallbackToPacOnPort53Conflict: true,
        StrategyProfile: settings.StrategyProfile,
        ActiveTrustedUpstreamId: _activeTrustedUpstream?.Id,
        ActiveGeoUnlockUpstreamId: _activeGeoUnlockUpstream?.Id,
        RoutingConfig: _routingConfig,
        SplitDomains: [.. _activeSplitDomains],
        Zone4Servers: [.. _poolManager.Zone4Servers],
        GeoUnlockUpstreams: [.. _geoUnlockUpstreams],
        Zone1Strategy: PoolSelectionStrategy.Fastest,
        Zone3Strategy: PoolSelectionStrategy.Failover,
        Zone4Strategy: settings.PoolStrategy,
        ClearCache: true,
        ReconnectIfNeeded: reconnectIfNeeded);

    private ServicePoolUpdateRequest BuildPoolUpdateRequest(PulseAppSettings settings) => new(
        Zone4Servers: [.. _poolManager.Zone4Servers],
        GeoUnlockUpstreams: [.. _geoUnlockUpstreams],
        ActiveTrustedUpstreamId: _activeTrustedUpstream?.Id,
        ActiveGeoUnlockUpstreamId: _activeGeoUnlockUpstream?.Id,
        Zone1Strategy: PoolSelectionStrategy.Fastest,
        Zone3Strategy: PoolSelectionStrategy.Failover,
        Zone4Strategy: settings.PoolStrategy,
        ClearCache: true);

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Session WinINet PAC sync is best-effort and must not fail IPC status handling.")]
    private async Task SyncSessionPacInterceptorAsync(ServiceStatusSnapshot snapshot, CancellationToken cancellationToken)
    {
        bool wantsSessionPac = _isServiceMode
            && snapshot.IsConnected
            && snapshot.ActiveMode == InterceptionMode.LocalProxyPacOnly
            && !string.IsNullOrWhiteSpace(snapshot.PacUrl);

        if (!wantsSessionPac)
        {
            await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        if (_sessionPacInterceptor is not null &&
            string.Equals(_sessionPacUrl, snapshot.PacUrl, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        await ClearSessionPacInterceptorAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            LocalProxyPacInterceptor interceptor = new(snapshot.PacUrl!);
            IPAddress loopback = IPAddress.TryParse(snapshot.ActiveLoopbackIp, out IPAddress? parsed)
                ? parsed
                : IPAddress.Loopback;
            await interceptor.ActivateAsync(
                loopback,
                snapshot.BoundDnsPort,
                _activeSplitDomains,
                cancellationToken).ConfigureAwait(false);
            _sessionPacInterceptor = interceptor;
            _sessionPacUrl = snapshot.PacUrl;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Session WinINet PAC mirror skipped for {PacUrl}.", snapshot.PacUrl);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Session WinINet PAC cleanup must remain resilient on teardown.")]
    private async Task ClearSessionPacInterceptorAsync(CancellationToken cancellationToken)
    {
        LocalProxyPacInterceptor? existing = _sessionPacInterceptor;
        _sessionPacInterceptor = null;
        _sessionPacUrl = null;

        if (existing is null)
        {
            return;
        }

        try
        {
            await existing.DeactivateAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Session WinINet PAC teardown ignored error.");
        }
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

            TimeSpan effectiveTimeout = _isServiceMode
                && !string.Equals(command, PipeCommandNames.GetStatus, StringComparison.Ordinal)
                ? _ipcClient.DefaultConnectAndCallTimeout
                : IpcProbeTimeout;

            PipeRpcResponse response = await _ipcClient.SendAsync(request, effectiveTimeout, cancellationToken).ConfigureAwait(false);
            if (!response.Success || string.IsNullOrWhiteSpace(response.PayloadJson))
            {
                Log.Debug("IPC command {Command} returned unsuccessful or empty response (Success={Success}, ErrorCode={ErrorCode}, Error={Error}).",
                    command, response.Success, response.ErrorCode, response.ErrorMessage);
                return null;
            }

            return JsonSerializer.Deserialize<TResponse>(response.PayloadJson, IpcJsonOptions);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException ex)
        {
            Log.Debug(ex, "IPC probe timed out for command {Command}; using Portable Mode.", command);
            return null;
        }
        catch (IOException ex)
        {
            Log.Debug(ex, "IPC pipe unavailable for command {Command}; using Portable Mode.", command);
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            Log.Warning(ex, "IPC pipe access denied for command {Command}; falling back to Portable Mode.", command);
            return null;
        }
        catch (JsonException ex)
        {
            Log.Warning(ex, "IPC response JSON invalid for command {Command}.", command);
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
