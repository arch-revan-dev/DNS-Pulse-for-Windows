using System.Globalization;
using System.IO.Pipes;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.Platform.Windows.Ipc;

/// <summary>
/// Async Windows Named Pipe client matching <see cref="PulsePipeIpcServer"/> length-prefixed JSON framing
/// and configurable connection/call timeouts.
/// </summary>
public sealed class PulsePipeIpcClient
{
    public const int DefaultMaxMessageBytes = PipeFrameCodec.MaxMessageBytes;
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    private readonly string _pipeName;
    private readonly TimeSpan _defaultTimeout;
    private readonly int _maxMessageBytes;

    public PulsePipeIpcClient(
        string pipeName = PipeSecurityBuilder.DefaultPipeName,
        TimeSpan? defaultTimeout = null,
        int maxMessageBytes = DefaultMaxMessageBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxMessageBytes, 64);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxMessageBytes, DefaultMaxMessageBytes);

        TimeSpan effectiveDefault = defaultTimeout ?? DefaultTimeout;
        ValidateTimeout(effectiveDefault, nameof(defaultTimeout));

        _pipeName = pipeName;
        _defaultTimeout = effectiveDefault;
        _maxMessageBytes = maxMessageBytes;
    }

    public string PipeName => _pipeName;

    public TimeSpan DefaultConnectAndCallTimeout => _defaultTimeout;

    /// <summary>
    /// Connects to the local Named Pipe server, sends <paramref name="request"/> using 4-byte length-prefixed
    /// UTF-8 JSON framing, and returns the decoded <see cref="PipeRpcResponse"/>.
    /// </summary>
    public async Task<PipeRpcResponse> SendAsync(
        PipeRpcRequest request,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        TimeSpan effectiveTimeout = timeout ?? _defaultTimeout;
        ValidateTimeout(effectiveTimeout, nameof(timeout));

        byte[] requestBytes = PipeFrameCodec.Serialize(request);
        if (requestBytes.Length > _maxMessageBytes)
        {
            throw new InvalidDataException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Serialized IPC request size {requestBytes.Length} bytes exceeds maximum allowed {_maxMessageBytes} bytes."));
        }

        using CancellationTokenSource timeoutCts = effectiveTimeout == Timeout.InfiniteTimeSpan
            ? new CancellationTokenSource()
            : new CancellationTokenSource(effectiveTimeout);
        using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeoutCts.Token);

        await using NamedPipeClientStream client = new(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        try
        {
            await client.ConnectAsync(linkedCts.Token).ConfigureAwait(false);
            await PipeFrameCodec.WriteFrameAsync(client, requestBytes, _maxMessageBytes, linkedCts.Token).ConfigureAwait(false);

            byte[]? responseBytes = await PipeFrameCodec.ReadFrameAsync(client, _maxMessageBytes, linkedCts.Token).ConfigureAwait(false);
            if (responseBytes is null)
            {
                throw new EndOfStreamException("Named pipe server closed the connection before sending a response.");
            }

            PipeRpcResponse? response = PipeFrameCodec.Deserialize<PipeRpcResponse>(responseBytes);
            return response ?? throw new InvalidDataException("Named pipe server returned a null JSON-RPC response.");
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Named pipe IPC request '{request.Command}' to '{_pipeName}' timed out after {effectiveTimeout}."),
                ex);
        }
    }

    private static void ValidateTimeout(TimeSpan timeout, string paramName)
    {
        if (timeout != Timeout.InfiniteTimeSpan && timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                timeout,
                "Timeout must be greater than TimeSpan.Zero or equal to Timeout.InfiniteTimeSpan.");
        }
    }
}
