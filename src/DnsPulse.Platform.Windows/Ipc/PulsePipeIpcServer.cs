using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Pipes;
using System.Text.Json;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.Platform.Windows.Ipc;

/// <summary>
/// ACL-hardened Windows Named Pipe JSON-RPC server using strict 4-byte length-prefixed framing,
/// a 1 MiB maximum frame limit, command allowlist enforcement, and concurrent client dispatch.
/// </summary>
public sealed class PulsePipeIpcServer : IAsyncDisposable, IDisposable
{
    public const int DefaultMaxMessageBytes = PipeFrameCodec.MaxMessageBytes;
    public const int DefaultMaxConcurrentClients = 16;

    private static readonly HashSet<string> AllowedCommands = new(StringComparer.Ordinal)
    {
        PipeCommandNames.GetStatus,
        PipeCommandNames.Connect,
        PipeCommandNames.Disconnect,
        PipeCommandNames.EmergencyRestore,
        PipeCommandNames.ApplyProfile,
        PipeCommandNames.RunDiagnostics,
        PipeCommandNames.UpdateBlocklist,
        PipeCommandNames.GetRecentTelemetry,
        PipeCommandNames.ExportBundle,
        PipeCommandNames.ShutdownService
    };

    private readonly Func<PipeRpcRequest, CancellationToken, Task<PipeRpcResponse>> _requestHandler;
    private readonly string _pipeName;
    private readonly PipeSecurity _pipeSecurity;
    private readonly int _maxMessageBytes;
    private readonly SemaphoreSlim _concurrencyGate;
    private readonly ConcurrentDictionary<long, Task> _activeClientTasks = new();
    private readonly Lock _lifecycleLock = new();

    private CancellationTokenSource? _serverCts;
    private Task? _acceptLoopTask;
    private long _nextClientId;
    private int _running;
    private int _disposed;

    public PulsePipeIpcServer(
        Func<PipeRpcRequest, CancellationToken, Task<PipeRpcResponse>> requestHandler,
        string pipeName = PipeSecurityBuilder.DefaultPipeName,
        PipeSecurity? pipeSecurity = null,
        int maxConcurrentClients = DefaultMaxConcurrentClients,
        int maxMessageBytes = DefaultMaxMessageBytes)
    {
        ArgumentNullException.ThrowIfNull(requestHandler);
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConcurrentClients, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxMessageBytes, 64);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxMessageBytes, DefaultMaxMessageBytes);

        PipeSecurity effectiveSecurity = pipeSecurity ?? PipeSecurityBuilder.CreateRestrictedPipeSecurity();
        if (PipeSecurityBuilder.IsPublicOrAnonymousAccessPresent(effectiveSecurity))
        {
            throw new ArgumentException(
                "PipeSecurity must not grant access to public, guest, or anonymous SIDs.",
                nameof(pipeSecurity));
        }

        _requestHandler = requestHandler;
        _pipeName = pipeName;
        _pipeSecurity = effectiveSecurity;
        _maxMessageBytes = maxMessageBytes;
        _concurrencyGate = new SemaphoreSlim(maxConcurrentClients, maxConcurrentClients);
    }

    public string PipeName => _pipeName;

    public int MaxMessageBytes => _maxMessageBytes;

    public bool IsRunning => Volatile.Read(ref _running) != 0;

    /// <summary>
    /// Validates whether <paramref name="command"/> is present in the canonical <see cref="PipeCommandNames"/> allowlist.
    /// </summary>
    public static bool IsCommandAllowed(string? command)
    {
        return !string.IsNullOrEmpty(command) && AllowedCommands.Contains(command);
    }

    /// <summary>
    /// Creates the initial ACL-protected listening pipe instance and starts accepting concurrent clients.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();

        StartCore();
        return Task.CompletedTask;
    }

    private void StartCore()
    {
        lock (_lifecycleLock)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (Volatile.Read(ref _running) != 0)
            {
                return;
            }

            NamedPipeServerStream? initialStream = CreateServerStream();
            CancellationTokenSource? cts = null;
            try
            {
                cts = new CancellationTokenSource();
                _serverCts = cts;
                Volatile.Write(ref _running, 1);

                NamedPipeServerStream capturedStream = initialStream;
                CancellationToken token = cts.Token;
                _acceptLoopTask = Task.Run(() => RunAcceptLoopAsync(capturedStream, token), CancellationToken.None);

                initialStream = null;
                cts = null;
            }
            finally
            {
                initialStream?.Dispose();
                cts?.Dispose();
            }
        }
    }

    /// <summary>
    /// Stops accepting new clients and awaits active IPC requests to finish.
    /// </summary>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        Task? acceptLoop;
        CancellationTokenSource? cts;

        lock (_lifecycleLock)
        {
            if (Interlocked.Exchange(ref _running, 0) == 0)
            {
                return;
            }

            acceptLoop = _acceptLoopTask;
            cts = _serverCts;
            _acceptLoopTask = null;
            _serverCts = null;
        }

        if (cts is not null)
        {
            await cts.CancelAsync().ConfigureAwait(false);
            cts.Dispose();
        }

        if (acceptLoop is not null)
        {
            await acceptLoop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        Task[] remainingClients = [.. _activeClientTasks.Values];
        if (remainingClients.Length > 0)
        {
            await Task.WhenAll(remainingClients).WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _running, 0);
        CancellationTokenSource? cts = Interlocked.Exchange(ref _serverCts, null);
        if (cts is not null)
        {
            cts.Cancel();
            cts.Dispose();
        }

        _concurrencyGate.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await StopAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _concurrencyGate.Dispose();
        }
    }

    private NamedPipeServerStream CreateServerStream()
    {
        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            _pipeSecurity);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Pipe accept loop must remain resilient against transient client/pipe errors until stopped.")]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Stream ownership is transferred to HandleClientAsync and disposed inside it or in the finally fallback.")]
    private async Task RunAcceptLoopAsync(NamedPipeServerStream initialStream, CancellationToken cancellationToken)
    {
        NamedPipeServerStream? pendingStream = initialStream;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                bool acquiredGate = false;
                NamedPipeServerStream? stream = pendingStream;
                pendingStream = null;
                bool ownershipTransferred = false;

                try
                {
                    await _concurrencyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                    acquiredGate = true;

                    stream ??= CreateServerStream();
                    await stream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                    long clientId = Interlocked.Increment(ref _nextClientId);
                    Task clientTask = HandleClientAsync(stream, clientId, cancellationToken);
                    ownershipTransferred = true;
                    acquiredGate = false;

                    _activeClientTasks[clientId] = clientTask;
                    _ = clientTask.ContinueWith(
                        static (completed, state) =>
                        {
                            (PulsePipeIpcServer server, long id) = ((PulsePipeIpcServer, long))state!;
                            server._activeClientTasks.TryRemove(id, out _);
                        },
                        (this, clientId),
                        CancellationToken.None,
                        TaskContinuationOptions.ExecuteSynchronously,
                        TaskScheduler.Default);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception)
                {
                    // Transient pipe error; clean up stream/slot in finally and continue listening.
                }
                finally
                {
                    if (!ownershipTransferred && stream is not null)
                    {
                        await stream.DisposeAsync().ConfigureAwait(false);
                    }

                    if (acquiredGate)
                    {
                        TryReleaseConcurrencyGate();
                    }
                }
            }
        }
        finally
        {
            if (pendingStream is not null)
            {
                await pendingStream.DisposeAsync().ConfigureAwait(false);
            }

            Interlocked.Exchange(ref _running, 0);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Client handler isolates per-connection failures and translates request handler exceptions into structured RPC error responses.")]
    private async Task HandleClientAsync(
        NamedPipeServerStream stream,
        long clientId,
        CancellationToken cancellationToken)
    {
        _ = clientId;
        try
        {
            await using NamedPipeServerStream ownedStream = stream;
            while (!cancellationToken.IsCancellationRequested && ownedStream.IsConnected)
            {
                byte[]? frameBytes;
                try
                {
                    frameBytes = await PipeFrameCodec.ReadFrameAsync(ownedStream, _maxMessageBytes, cancellationToken).ConfigureAwait(false);
                }
                catch (InvalidDataException ex)
                {
                    await TrySendResponseAsync(
                        ownedStream,
                        new PipeRpcResponse(string.Empty, false, "FrameTooLarge", ex.Message),
                        cancellationToken).ConfigureAwait(false);
                    break;
                }
                catch (EndOfStreamException)
                {
                    break;
                }
                catch (IOException)
                {
                    break;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                if (frameBytes is null)
                {
                    break;
                }

                PipeRpcResponse response = await ProcessRequestBytesAsync(frameBytes, cancellationToken).ConfigureAwait(false);
                bool sent = await TrySendResponseAsync(ownedStream, response, cancellationToken).ConfigureAwait(false);
                if (!sent)
                {
                    break;
                }
            }
        }
        finally
        {
            TryReleaseConcurrencyGate();
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Handler exceptions must be returned as RPC failures rather than crashing the pipe server.")]
    private async Task<PipeRpcResponse> ProcessRequestBytesAsync(
        byte[] frameBytes,
        CancellationToken cancellationToken)
    {
        PipeRpcRequest? request;
        try
        {
            request = PipeFrameCodec.Deserialize<PipeRpcRequest>(frameBytes);
        }
        catch (JsonException ex)
        {
            return new PipeRpcResponse(string.Empty, false, "InvalidJson", ex.Message);
        }

        if (request is null || string.IsNullOrWhiteSpace(request.RequestId))
        {
            return new PipeRpcResponse(
                request?.RequestId ?? string.Empty,
                false,
                "InvalidRequest",
                "IPC request must include a non-empty requestId.");
        }

        if (!IsCommandAllowed(request.Command))
        {
            return new PipeRpcResponse(
                request.RequestId,
                false,
                "UnknownCommand",
                string.Create(CultureInfo.InvariantCulture, $"Command '{request.Command}' is not permitted."));
        }

        try
        {
            return await _requestHandler(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new PipeRpcResponse(request.RequestId, false, "HandlerError", ex.Message);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Client disconnection during response write should terminate the client session cleanly.")]
    private async Task<bool> TrySendResponseAsync(
        NamedPipeServerStream stream,
        PipeRpcResponse response,
        CancellationToken cancellationToken)
    {
        try
        {
            byte[] responseBytes = PipeFrameCodec.Serialize(response);
            await PipeFrameCodec.WriteFrameAsync(stream, responseBytes, _maxMessageBytes, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void TryReleaseConcurrencyGate()
    {
        try
        {
            _concurrencyGate.Release();
        }
        catch (ObjectDisposedException)
        {
            // Server is already disposing.
        }
    }
}
