using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Ipc;
using Microsoft.Extensions.Logging.Abstractions;

namespace DnsPulse.Service;

/// <summary>
/// Windows background service hosting the ACL-hardened Named Pipe IPC server and running the
/// Dead-Man's Switch watchdog to automatically restore host DNS settings if local listeners fail.
/// </summary>
public sealed class DnsPulseWorkerService : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private static readonly Action<ILogger, string, string, Exception?> LogServiceStarted =
        LoggerMessage.Define<string, string>(
            LogLevel.Information,
            new EventId(2001, nameof(LogServiceStarted)),
            "{Product} Windows Service worker started on pipe '{PipeName}'.");

    private static readonly Action<ILogger, double, Exception?> LogWatchdogTriggered =
        LoggerMessage.Define<double>(
            LogLevel.Error,
            new EventId(2002, nameof(LogWatchdogTriggered)),
            "Dead-man's switch triggered after {UnhealthySeconds:F2}s of continuous listener failure. Executing EmergencyRestore.");

    private static readonly Action<ILogger, Exception> LogWatchdogRollbackFailed =
        LoggerMessage.Define(
            LogLevel.Critical,
            new EventId(2003, nameof(LogWatchdogRollbackFailed)),
            "EmergencyRestore failed during dead-man's switch rollback.");

    private static readonly Action<ILogger, Exception> LogShutdownFallback =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(2004, nameof(LogShutdownFallback)),
            "Clean disconnect failed during service stop/shutdown; falling back to EmergencyRestore.");

    private readonly IPulseRuntimeBackend _backend;
    private readonly PulseServiceOptions _options;
    private readonly ILogger<DnsPulseWorkerService> _logger;
    private readonly IHostApplicationLifetime? _lifetime;
    private readonly Func<PipeRpcRequest, CancellationToken, Task<PipeRpcResponse>>? _extensionHandler;
    private readonly Lock _statusGate = new();

    private PulsePipeIpcServer? _ipcServer;
    private bool _watchdogTriggered;
    private string? _lastWatchdogErrorMessage;

    public DnsPulseWorkerService(
        IPulseRuntimeBackend backend,
        PulseServiceOptions? options = null,
        ILogger<DnsPulseWorkerService>? logger = null,
        IHostApplicationLifetime? lifetime = null,
        Func<PipeRpcRequest, CancellationToken, Task<PipeRpcResponse>>? extensionHandler = null)
    {
        ArgumentNullException.ThrowIfNull(backend);

        _backend = backend;
        _options = options ?? new PulseServiceOptions();
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(_options.HealthCheckInterval, TimeSpan.Zero, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(_options.UnhealthyRollbackThreshold, TimeSpan.Zero, nameof(options));

        _logger = logger ?? NullLogger<DnsPulseWorkerService>.Instance;
        _lifetime = lifetime;
        _extensionHandler = extensionHandler;
    }

    public string PipeName => _options.PipeName;

    public bool IsIpcRunning => _ipcServer?.IsRunning ?? false;

    /// <summary>
    /// Returns the effective service status, including any Dead-Man's Switch rollback diagnostics.
    /// </summary>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate", Justification = "Mirrors IPulseRuntimeBackend.GetStatus RPC snapshot semantics.")]
    public ServiceStatusSnapshot GetStatus()
    {
        ServiceStatusSnapshot status = _backend.GetStatus();
        lock (_statusGate)
        {
            if (_watchdogTriggered && !status.IsConnected)
            {
                return status with
                {
                    DirtyRecoveryPending = false,
                    LastErrorMessage = string.IsNullOrWhiteSpace(status.LastErrorMessage)
                        ? _lastWatchdogErrorMessage
                        : status.LastErrorMessage
                };
            }
        }

        return status;
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        PulsePipeIpcServer ipcServer = new(
            HandlePipeRequestAsync,
            _options.PipeName);
        bool ownershipTransferred = false;
        try
        {
            await ipcServer.StartAsync(cancellationToken).ConfigureAwait(false);
            _ipcServer = ipcServer;
            ownershipTransferred = true;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                await ipcServer.DisposeAsync().ConfigureAwait(false);
            }
        }

        LogServiceStarted(_logger, WindowsPlatformInfo.Product, _options.PipeName, null);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeProvider timeProvider = _options.TimeProvider;
        DateTimeOffset? unhealthySinceUtc = null;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                ServiceStatusSnapshot status = _backend.GetStatus();
                if (!status.IsConnected)
                {
                    unhealthySinceUtc = null;
                }
                else
                {
                    bool healthy = await ProbeSafeAsync(stoppingToken).ConfigureAwait(false);
                    if (healthy)
                    {
                        unhealthySinceUtc = null;
                    }
                    else
                    {
                        DateTimeOffset now = timeProvider.GetUtcNow();
                        unhealthySinceUtc ??= now;
                        TimeSpan unhealthyDuration = now - unhealthySinceUtc.Value;

                        if (unhealthyDuration >= _options.UnhealthyRollbackThreshold)
                        {
                            await TriggerDeadMansRollbackAsync(unhealthyDuration, stoppingToken).ConfigureAwait(false);
                            unhealthySinceUtc = null;
                        }
                    }
                }

                await Task.Delay(_options.HealthCheckInterval, timeProvider, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        using CancellationTokenSource shutdownCts = new(_options.ShutdownOperationTimeout);
        await SafeRollbackOnShutdownAsync(shutdownCts.Token).ConfigureAwait(false);

        PulsePipeIpcServer? server = Interlocked.Exchange(ref _ipcServer, null);
        if (server is not null)
        {
            await server.DisposeAsync().ConfigureAwait(false);
        }
    }

    public override void Dispose()
    {
        _ipcServer?.Dispose();
        _ipcServer = null;
        base.Dispose();
    }

    private async Task<PipeRpcResponse> HandlePipeRequestAsync(
        PipeRpcRequest request,
        CancellationToken cancellationToken)
    {
        switch (request.Command)
        {
            case PipeCommandNames.GetStatus:
                return CreateSuccessResponse(request.RequestId, GetStatus());

            case PipeCommandNames.Connect:
                return await HandleConnectAsync(request.RequestId, cancellationToken).ConfigureAwait(false);

            case PipeCommandNames.Disconnect:
                ServiceStatusSnapshot disconnectedStatus = await _backend.DisconnectAsync(cancellationToken).ConfigureAwait(false);
                return CreateSuccessResponse(request.RequestId, disconnectedStatus);

            case PipeCommandNames.EmergencyRestore:
                return await HandleEmergencyRestoreAsync(request.RequestId, cancellationToken).ConfigureAwait(false);

            case PipeCommandNames.GetRecentTelemetry:
                int maxCount = ParseMaxTelemetryCount(request.PayloadJson);
                IReadOnlyList<DnsQueryTelemetryEvent> events = _backend.GetRecentTelemetry(maxCount);
                return CreateSuccessResponse(request.RequestId, events);

            case PipeCommandNames.ShutdownService:
                if (_lifetime is not null)
                {
                    _ = Task.Run(
                        () => _lifetime.StopApplication(),
                        CancellationToken.None);
                }

                return new PipeRpcResponse(request.RequestId, true);

            case PipeCommandNames.ApplyProfile:
            case PipeCommandNames.RunDiagnostics:
            case PipeCommandNames.UpdateBlocklist:
            case PipeCommandNames.ExportBundle:
                if (_extensionHandler is not null)
                {
                    return await _extensionHandler(request, cancellationToken).ConfigureAwait(false);
                }

                return new PipeRpcResponse(
                    request.RequestId,
                    false,
                    "NotSupported",
                    string.Create(CultureInfo.InvariantCulture, $"Command '{request.Command}' is not wired in this backend."));

            default:
                return new PipeRpcResponse(
                    request.RequestId,
                    false,
                    "UnknownCommand",
                    string.Create(CultureInfo.InvariantCulture, $"Unknown command '{request.Command}'."));
        }
    }

    private async Task<PipeRpcResponse> HandleConnectAsync(
        string requestId,
        CancellationToken cancellationToken)
    {
        ServiceStatusSnapshot status = await _backend.ConnectAsync(cancellationToken).ConfigureAwait(false);
        lock (_statusGate)
        {
            _watchdogTriggered = false;
            _lastWatchdogErrorMessage = null;
        }

        return CreateSuccessResponse(requestId, status);
    }

    private async Task<PipeRpcResponse> HandleEmergencyRestoreAsync(
        string requestId,
        CancellationToken cancellationToken)
    {
        NetworkRestoredResult restored = await _backend.EmergencyRestoreAsync(cancellationToken).ConfigureAwait(false);
        lock (_statusGate)
        {
            _watchdogTriggered = false;
        }

        return CreateSuccessResponse(requestId, restored);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Health probe errors must be treated as unhealthy listener state.")]
    private async Task<bool> ProbeSafeAsync(CancellationToken stoppingToken)
    {
        try
        {
            return await _backend.ProbeListenerHealthAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return false;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Watchdog must survive rollback exceptions and update failure diagnostics.")]
    private async Task TriggerDeadMansRollbackAsync(TimeSpan unhealthyDuration, CancellationToken stoppingToken)
    {
        LogWatchdogTriggered(_logger, unhealthyDuration.TotalSeconds, null);

        string summary;
        try
        {
            NetworkRestoredResult result = await _backend.EmergencyRestoreAsync(stoppingToken).ConfigureAwait(false);
            summary = result.Summary;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogWatchdogRollbackFailed(_logger, ex);
            summary = ex.Message;
        }

        lock (_statusGate)
        {
            _watchdogTriggered = true;
            _lastWatchdogErrorMessage = string.Create(
                CultureInfo.InvariantCulture,
                $"Dead-man's switch triggered after {unhealthyDuration.TotalSeconds:F1}s of unhealthy local DNS listener state. {summary}");
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Service shutdown must attempt EmergencyRestore if clean DisconnectAsync fails.")]
    private async Task SafeRollbackOnShutdownAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_backend.GetStatus().IsConnected)
            {
                await _backend.DisconnectAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            LogShutdownFallback(_logger, ex);
            try
            {
                await _backend.EmergencyRestoreAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception restoreEx)
            {
                LogWatchdogRollbackFailed(_logger, restoreEx);
            }
        }
    }

    private static PipeRpcResponse CreateSuccessResponse<TPayload>(string requestId, TPayload payload)
    {
        string payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
        return new PipeRpcResponse(requestId, true, PayloadJson: payloadJson);
    }

    private static int ParseMaxTelemetryCount(string? payloadJson)
    {
        if (string.IsNullOrWhiteSpace(payloadJson))
        {
            return 100;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Number
                && doc.RootElement.TryGetInt32(out int directCount))
            {
                return Math.Max(0, directCount);
            }

            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("maxCount", out JsonElement maxCountElem)
                && maxCountElem.TryGetInt32(out int objectCount))
            {
                return Math.Max(0, objectCount);
            }
        }
        catch (JsonException)
        {
            // Fall back to default count on malformed telemetry count payload.
        }

        return 100;
    }
}
