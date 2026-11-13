using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Hosting;

/// <summary>
/// High-concurrency async local DNS server listening on UDP and TCP with RFC 1035/EDNS0
/// truncation (<c>TC=1</c>) and RFC 7766 2-byte TCP length framing.
/// </summary>
public sealed class LocalDnsServer : IAsyncDisposable, IDisposable
{
    private const int MaxUdpReceiveBufferBytes = 4096;
    private const int DefaultRfc1035UdpPayloadBytes = 512;
    private const int SioUdpConnReset = -1744830452;

    private readonly IPulseDnsResolver _resolver;
    private readonly LocalDnsServerOptions _options;
    private readonly SemaphoreSlim _concurrencyGate;
    private readonly CancellationTokenSource _disposeCts = new();

    private Socket? _udpSocket;
    private TcpListener? _tcpListener;
    private Task? _udpLoopTask;
    private Task? _tcpLoopTask;
    private int _started;
    private int _disposed;

    public LocalDnsServer(IPulseDnsResolver resolver, LocalDnsServerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        _options = options ?? new LocalDnsServerOptions();

        ArgumentNullException.ThrowIfNull(_options.ListenAddress);
        ArgumentOutOfRangeException.ThrowIfNegative(_options.Port, nameof(options));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(_options.Port, 65535, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.MaxConcurrentRequests, 1, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(_options.TcpIdleTimeout, TimeSpan.Zero, nameof(options));

        _resolver = resolver;
        _concurrencyGate = new SemaphoreSlim(_options.MaxConcurrentRequests, _options.MaxConcurrentRequests);
    }

    public IPEndPoint? BoundUdpEndPoint { get; private set; }

    public IPEndPoint? BoundTcpEndPoint { get; private set; }

    public int BoundPort => BoundTcpEndPoint?.Port ?? BoundUdpEndPoint?.Port ?? 0;

    /// <summary>
    /// Binds UDP and TCP listeners and starts processing incoming DNS queries.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("LocalDnsServer has already been started.");
        }

        BindListeners(_options.ListenAddress, _options.Port, out Socket udpSocket, out TcpListener tcpListener);
        _udpSocket = udpSocket;
        _tcpListener = tcpListener;

        BoundUdpEndPoint = (IPEndPoint?)udpSocket.LocalEndPoint;
        BoundTcpEndPoint = (IPEndPoint?)tcpListener.LocalEndpoint;

        _udpLoopTask = Task.Run(() => RunUdpReceiveLoopAsync(udpSocket, _disposeCts.Token));
        _tcpLoopTask = Task.Run(() => RunTcpAcceptLoopAsync(tcpListener, _disposeCts.Token));
    }

    /// <summary>
    /// Starts the local DNS server asynchronously.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Start();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();
        CloseSockets();
        _concurrencyGate.Dispose();
        _disposeCts.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _disposeCts.CancelAsync().ConfigureAwait(false);
        CloseSockets();

        if (_udpLoopTask is not null)
        {
            await AwaitQuietlyAsync(_udpLoopTask).ConfigureAwait(false);
        }

        if (_tcpLoopTask is not null)
        {
            await AwaitQuietlyAsync(_tcpLoopTask).ConfigureAwait(false);
        }

        _concurrencyGate.Dispose();
        _disposeCts.Dispose();
    }

    private static void BindListeners(
        IPAddress address,
        int requestedPort,
        out Socket udpSocket,
        out TcpListener tcpListener)
    {
        int maxAttempts = requestedPort == 0 ? 5 : 1;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            TcpListener candidateTcp = new(address, requestedPort);
            Socket? candidateUdp = null;
            bool bound = false;
            try
            {
                candidateTcp.Start();
                int actualPort = ((IPEndPoint)candidateTcp.LocalEndpoint).Port;

                candidateUdp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                DisableWindowsUdpConnReset(candidateUdp);
                candidateUdp.Bind(new IPEndPoint(address, actualPort));

                udpSocket = candidateUdp;
                tcpListener = candidateTcp;
                bound = true;
                return;
            }
            catch (SocketException) when (requestedPort == 0 && attempt < maxAttempts - 1)
            {
                // Retry another ephemeral port if UDP bind collided.
            }
            finally
            {
                if (!bound)
                {
                    candidateUdp?.Dispose();
                    candidateTcp.Stop();
                }
            }
        }

        throw new InvalidOperationException("Failed to bind matching UDP and TCP ephemeral ports.");
    }

    private static void DisableWindowsUdpConnReset(Socket udpSocket)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            byte[] optionIn = [0, 0, 0, 0];
            udpSocket.IOControl(SioUdpConnReset, optionIn, null);
        }
        catch (SocketException)
        {
            // Ignore if unsupported by socket provider.
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "UDP receive loop must stay alive on transient socket errors until server disposal.")]
    private async Task RunUdpReceiveLoopAsync(Socket udpSocket, CancellationToken cancellationToken)
    {
        byte[] receiveBuffer = GC.AllocateUninitializedArray<byte>(MaxUdpReceiveBufferBytes);
        EndPoint anyEndpoint = new IPEndPoint(
            udpSocket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any,
            0);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                SocketReceiveFromResult received = await udpSocket.ReceiveFromAsync(
                    receiveBuffer,
                    SocketFlags.None,
                    anyEndpoint,
                    cancellationToken).ConfigureAwait(false);

                if (received.ReceivedBytes <= 0)
                {
                    continue;
                }

                await _concurrencyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                byte[] packetCopy = ArrayPool<byte>.Shared.Rent(received.ReceivedBytes);
                Buffer.BlockCopy(receiveBuffer, 0, packetCopy, 0, received.ReceivedBytes);
                _ = HandleUdpPacketAsync(udpSocket, packetCopy, received.ReceivedBytes, received.RemoteEndPoint, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                // Continue receiving subsequent datagrams.
            }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Per-datagram handler must isolate resolution and socket errors and always release pooled buffers and concurrency slots.")]
    private async Task HandleUdpPacketAsync(
        Socket udpSocket,
        byte[] rentedPacket,
        int packetLength,
        EndPoint remoteEndPoint,
        CancellationToken cancellationToken)
    {
        try
        {
            ReadOnlySpan<byte> requestSpan = rentedPacket.AsSpan(0, packetLength);
            if (!DnsWireCodec.TryParse(requestSpan, out DnsMessage? query))
            {
                return;
            }

            DnsMessage response = await _resolver.ResolveAsync(query, cancellationToken).ConfigureAwait(false);
            int maxUdpBytes = query.EdnsUdpPayloadSize is { } ednsSize
                ? Math.Clamp((int)ednsSize, DefaultRfc1035UdpPayloadBytes, MaxUdpReceiveBufferBytes)
                : DefaultRfc1035UdpPayloadBytes;

            using PooledDnsPacket serialized = SerializeWithUdpTruncation(response, maxUdpBytes);
            await udpSocket.SendToAsync(
                serialized.Memory,
                SocketFlags.None,
                remoteEndPoint,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Isolated per-request failure.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedPacket);
            TryReleaseConcurrencySlot();
        }
    }

    private static PooledDnsPacket SerializeWithUdpTruncation(DnsMessage response, int maxUdpBytes)
    {
        PooledDnsPacket full = DnsWireCodec.SerializePooled(response);
        if (full.Length <= maxUdpBytes)
        {
            return full;
        }

        full.Dispose();

        // Strip Additionals and Authorities first with TC=1.
        DnsMessage stripped = response with
        {
            Header = response.Header with
            {
                Truncated = true,
                AuthorityCount = 0,
                AdditionalCount = 0
            },
            Authorities = [],
            Additionals = []
        };

        PooledDnsPacket strippedPacket = DnsWireCodec.SerializePooled(stripped);
        if (strippedPacket.Length <= maxUdpBytes)
        {
            return strippedPacket;
        }

        strippedPacket.Dispose();

        // Progressively trim answers until the truncated packet fits within maxUdpBytes.
        List<DnsResourceRecord> answers = [.. response.Answers];
        while (answers.Count > 0)
        {
            answers.RemoveAt(answers.Count - 1);
            DnsMessage candidate = stripped with
            {
                Header = stripped.Header with { AnswerCount = (ushort)answers.Count },
                Answers = answers
            };

            PooledDnsPacket candidatePacket = DnsWireCodec.SerializePooled(candidate);
            if (candidatePacket.Length <= maxUdpBytes || answers.Count == 0)
            {
                return candidatePacket;
            }

            candidatePacket.Dispose();
        }

        DnsMessage headerOnly = stripped with
        {
            Header = stripped.Header with { AnswerCount = 0 },
            Answers = []
        };

        return DnsWireCodec.SerializePooled(headerOnly);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "TCP accept loop must isolate transient accept errors until shutdown.")]
    private async Task RunTcpAcceptLoopAsync(TcpListener tcpListener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            bool acquired = false;
            try
            {
                await _concurrencyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;

                TcpClient client = await tcpListener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                acquired = false; // Ownership of slot transferred to HandleTcpClientAsync.
                _ = HandleTcpClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                if (acquired)
                {
                    TryReleaseConcurrencySlot();
                }

                break;
            }
            catch (ObjectDisposedException)
            {
                if (acquired)
                {
                    TryReleaseConcurrencySlot();
                }

                break;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                if (acquired)
                {
                    TryReleaseConcurrencySlot();
                }

                break;
            }
            catch (Exception)
            {
                if (acquired)
                {
                    TryReleaseConcurrencySlot();
                }
            }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Per-connection TCP loop must isolate client disconnect and framing errors.")]
    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            using (client)
            {
                client.NoDelay = true;
                using NetworkStream stream = client.GetStream();
                byte[] lengthPrefix = new byte[2];

                while (!cancellationToken.IsCancellationRequested)
                {
                    using CancellationTokenSource idleCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    idleCts.CancelAfter(_options.TcpIdleTimeout);

                    bool hasPrefix = await ReadExactAsync(stream, lengthPrefix, idleCts.Token).ConfigureAwait(false);
                    if (!hasPrefix)
                    {
                        break;
                    }

                    ushort messageLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);
                    if (messageLength == 0)
                    {
                        break;
                    }

                    byte[] queryBuffer = ArrayPool<byte>.Shared.Rent(messageLength);
                    try
                    {
                        bool hasBody = await ReadExactAsync(
                            stream,
                            queryBuffer.AsMemory(0, messageLength),
                            idleCts.Token).ConfigureAwait(false);
                        if (!hasBody)
                        {
                            break;
                        }

                        if (!DnsWireCodec.TryParse(queryBuffer.AsSpan(0, messageLength), out DnsMessage? query))
                        {
                            break;
                        }

                        DnsMessage response = await _resolver.ResolveAsync(query, cancellationToken).ConfigureAwait(false);
                        using PooledDnsPacket serialized = DnsWireCodec.SerializePooled(response);

                        int frameLength = 2 + serialized.Length;
                        byte[] frameBuffer = ArrayPool<byte>.Shared.Rent(frameLength);
                        try
                        {
                            BinaryPrimitives.WriteUInt16BigEndian(frameBuffer.AsSpan(0, 2), (ushort)serialized.Length);
                            serialized.Span.CopyTo(frameBuffer.AsSpan(2));

                            await stream.WriteAsync(frameBuffer.AsMemory(0, frameLength), cancellationToken).ConfigureAwait(false);
                            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(frameBuffer);
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(queryBuffer);
                    }
                }
            }
        }
        catch (Exception)
        {
            // Isolated per-connection failure/EOF.
        }
        finally
        {
            TryReleaseConcurrencySlot();
        }
    }

    private static async Task<bool> ReadExactAsync(
        NetworkStream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < destination.Length)
        {
            int read = await stream.ReadAsync(destination[totalRead..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            totalRead += read;
        }

        return true;
    }

    private void TryReleaseConcurrencySlot()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            _concurrencyGate.Release();
        }
        catch (ObjectDisposedException)
        {
            // Server disposed during unwinding.
        }
    }

    private void CloseSockets()
    {
        try
        {
            _udpSocket?.Dispose();
        }
        catch (SocketException)
        {
        }

        try
        {
            _tcpListener?.Stop();
            _tcpListener?.Dispose();
        }
        catch (SocketException)
        {
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Shutdown awaiting ignores background loop termination exceptions.")]
    private static async Task AwaitQuietlyAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Ignored on shutdown.
        }
    }
}
