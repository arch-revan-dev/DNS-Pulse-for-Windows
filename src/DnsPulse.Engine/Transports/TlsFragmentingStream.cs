using System.Net.Sockets;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// A <see cref="Stream"/> wrapper over a connected TCP <see cref="Socket"/> that intercepts the first
/// outbound TLS <c>ClientHello</c> record (<c>0x16 0x03 ... 0x01</c>) and splits it across small TCP writes
/// with <see cref="Socket.NoDelay"/> enabled to bypass SNI-inspecting DPI middleboxes.
/// </summary>
public sealed class TlsFragmentingStream : Stream
{
    public const int DefaultChunkSize = 40;

    private readonly Socket _socket;
    private readonly NetworkStream _inner;
    private readonly int _chunkSize;
    private readonly TimeSpan? _interChunkDelay;
    private readonly List<int> _clientHelloChunkSizes = [];
    private bool _firstOutboundWriteProcessed;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="TlsFragmentingStream"/> wrapping a connected <see cref="Socket"/>.
    /// </summary>
    public TlsFragmentingStream(
        Socket socket,
        int chunkSize = DefaultChunkSize,
        bool ownsSocket = true,
        TimeSpan? interChunkDelay = null)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentOutOfRangeException.ThrowIfLessThan(chunkSize, 1);

        _socket = socket;
        _socket.NoDelay = true;
        _inner = new NetworkStream(socket, ownsSocket);
        _chunkSize = chunkSize;
        _interChunkDelay = interChunkDelay;
    }

    /// <summary>Gets whether an outbound TLS <c>ClientHello</c> record was intercepted and fragmented.</summary>
    public bool WasClientHelloFragmented { get; private set; }

    /// <summary>Gets the sizes of each TCP write chunk produced for the intercepted <c>ClientHello</c>.</summary>
    public IReadOnlyList<int> ClientHelloChunkSizes => _clientHelloChunkSizes;

    /// <inheritdoc />
    public override bool CanRead => _inner.CanRead;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => _inner.CanWrite;

    /// <inheritdoc />
    public override bool CanTimeout => _inner.CanTimeout;

    /// <inheritdoc />
    public override long Length => _inner.Length;

    /// <inheritdoc />
    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    /// <inheritdoc />
    public override int ReadTimeout
    {
        get => _inner.ReadTimeout;
        set => _inner.ReadTimeout = value;
    }

    /// <inheritdoc />
    public override int WriteTimeout
    {
        get => _inner.WriteTimeout;
        set => _inner.WriteTimeout = value;
    }

    /// <inheritdoc />
    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _inner.Flush();
    }

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inner.FlushAsync(cancellationToken);
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inner.Read(buffer, offset, count);
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inner.Read(buffer);
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inner.ReadAsync(buffer, offset, count, cancellationToken);
    }

    /// <inheritdoc />
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inner.ReadAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException("TLS stream does not support seeking.");
    }

    /// <inheritdoc />
    public override void SetLength(long value)
    {
        throw new NotSupportedException("TLS stream does not support setting length.");
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        Write(buffer.AsSpan(offset, count));
    }

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_firstOutboundWriteProcessed)
        {
            _firstOutboundWriteProcessed = true;
            if (IsTlsClientHello(buffer))
            {
                SendFragmentedSync(buffer);
                return;
            }
        }

        _inner.Write(buffer);
    }

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_firstOutboundWriteProcessed)
        {
            _firstOutboundWriteProcessed = true;
            if (IsTlsClientHello(buffer.Span))
            {
                return SendFragmentedAsync(buffer, cancellationToken);
            }
        }

        return _inner.WriteAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            if (disposing)
            {
                _inner.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            await _inner.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Detects a TLS Handshake record (<c>0x16 0x03 ..</c>) carrying a <c>ClientHello</c> (<c>0x01</c>).
    /// </summary>
    public static bool IsTlsClientHello(ReadOnlySpan<byte> buffer)
    {
        return buffer.Length >= 6
            && buffer[0] == 0x16
            && buffer[1] == 0x03
            && buffer[5] == 0x01;
    }

    private void SendFragmentedSync(ReadOnlySpan<byte> buffer)
    {
        WasClientHelloFragmented = true;
        int offset = 0;
        while (offset < buffer.Length)
        {
            int len = Math.Min(_chunkSize, buffer.Length - offset);
            ReadOnlySpan<byte> chunk = buffer.Slice(offset, len);
            int sentTotal = 0;
            while (sentTotal < chunk.Length)
            {
                int sent = _socket.Send(chunk[sentTotal..], SocketFlags.None);
                if (sent <= 0)
                {
                    throw new IOException("Socket closed while sending fragmented TLS ClientHello.");
                }

                sentTotal += sent;
            }

            _clientHelloChunkSizes.Add(len);
            offset += len;

            if (offset < buffer.Length && _interChunkDelay is { TotalMilliseconds: > 0 } delay)
            {
                Thread.Sleep(delay);
            }
        }
    }

    private async ValueTask SendFragmentedAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        WasClientHelloFragmented = true;
        int offset = 0;
        while (offset < buffer.Length)
        {
            int len = Math.Min(_chunkSize, buffer.Length - offset);
            ReadOnlyMemory<byte> chunk = buffer.Slice(offset, len);
            int sentTotal = 0;
            while (sentTotal < chunk.Length)
            {
                int sent = await _socket.SendAsync(chunk[sentTotal..], SocketFlags.None, cancellationToken).ConfigureAwait(false);
                if (sent <= 0)
                {
                    throw new IOException("Socket closed while sending fragmented TLS ClientHello.");
                }

                sentTotal += sent;
            }

            _clientHelloChunkSizes.Add(len);
            offset += len;

            if (offset < buffer.Length && _interChunkDelay is { TotalMilliseconds: > 0 } delay)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
