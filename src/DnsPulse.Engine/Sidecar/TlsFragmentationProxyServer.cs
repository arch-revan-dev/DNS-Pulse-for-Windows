using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsPulse.Core.Security;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Sidecar;

/// <summary>
/// Driverless multi-protocol local proxy supporting HTTP <c>CONNECT</c>, plain HTTP proxy requests,
/// and SOCKS5 (RFC 1928 <c>NO AUTH</c> / <c>CONNECT</c> IPv4/Domain/IPv6) with SNI-boundary TLS
/// <c>ClientHello</c> fragmentation and SSRF protection.
/// </summary>
public sealed class TlsFragmentationProxyServer : IAsyncDisposable, IDisposable
{
    private const byte SocksVersion5 = 0x05;
    private const byte SocksAuthNoAuth = 0x00;
    private const byte SocksAuthNoAcceptable = 0xFF;
    private const byte SocksCmdConnect = 0x01;
    private const byte SocksAtypIpv4 = 0x01;
    private const byte SocksAtypDomain = 0x03;
    private const byte SocksAtypIpv6 = 0x04;

    private const byte SocksReplySucceeded = 0x00;
    private const byte SocksReplyGeneralFailure = 0x01;
    private const byte SocksReplyNotAllowedByRuleset = 0x02;
    private const byte SocksReplyHostUnreachable = 0x04;
    private const byte SocksReplyConnectionRefused = 0x05;
    private const byte SocksReplyCommandNotSupported = 0x07;
    private const byte SocksReplyAddressTypeNotSupported = 0x08;

    private const int RelayBufferSize = 16 * 1024;
    private static readonly byte[] HeaderTerminator = "\r\n\r\n"u8.ToArray();

    private readonly TlsFragmentationProxyOptions _options;
    private readonly Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> _hostResolver;
    private readonly ConcurrentDictionary<long, Task> _activeConnections = new();
    private readonly SemaphoreSlim _connectionLimiter;
    private readonly Lock _lifecycleLock = new();

    private Socket? _listenerSocket;
    private CancellationTokenSource? _serverCts;
    private Task? _acceptLoopTask;
    private long _nextConnectionId;
    private long _totalConnectionsAccepted;
    private long _blockedSsrfsCount;
    private long _fragmentedClientHellosCount;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="TlsFragmentationProxyServer"/> using an injected DNS resolver delegate.
    /// </summary>
    public TlsFragmentationProxyServer(
        TlsFragmentationProxyOptions options,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> hostResolver)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(hostResolver);
        ValidateOptions(options);

        _options = options;
        _hostResolver = hostResolver;
        _connectionLimiter = new SemaphoreSlim(options.MaxConcurrentConnections, options.MaxConcurrentConnections);
    }

    /// <summary>
    /// Initializes a new <see cref="TlsFragmentationProxyServer"/> backed by an <see cref="IBootstrapResolver"/>.
    /// </summary>
    public TlsFragmentationProxyServer(
        TlsFragmentationProxyOptions options,
        IBootstrapResolver bootstrapResolver)
        : this(
            options,
            (host, ct) =>
            {
                ArgumentNullException.ThrowIfNull(bootstrapResolver);
                return bootstrapResolver.ResolveHostAsync(host, ct);
            })
    {
        ArgumentNullException.ThrowIfNull(bootstrapResolver);
    }

    /// <summary>
    /// Gets the bound local endpoint once started, or <c>null</c> when stopped.
    /// </summary>
    public IPEndPoint? BoundEndPoint { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the proxy listener is currently active.
    /// </summary>
    public bool IsRunning => _listenerSocket is not null && _serverCts is { IsCancellationRequested: false };

    /// <summary>
    /// Gets the total number of TCP connections accepted by this server instance.
    /// </summary>
    public long TotalConnectionsAccepted => Interlocked.Read(ref _totalConnectionsAccepted);

    /// <summary>
    /// Gets the total number of connection attempts rejected by the SSRF private/bogon IP guard.
    /// </summary>
    public long BlockedSsrfsCount => Interlocked.Read(ref _blockedSsrfsCount);

    /// <summary>
    /// Gets the total number of TLS <c>ClientHello</c> payloads fragmented across multiple TCP sends.
    /// </summary>
    public long FragmentedClientHellosCount => Interlocked.Read(ref _fragmentedClientHellosCount);

    /// <summary>
    /// Starts listening for incoming proxy connections.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_lifecycleLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_listenerSocket is not null)
            {
                return Task.CompletedTask;
            }

            Socket listener = CreateBoundTcpListener(_options.BindAddress, _options.Port, backlog: 512);
            _listenerSocket = listener;
            BoundEndPoint = (IPEndPoint?)listener.LocalEndPoint;
            _serverCts = new CancellationTokenSource();
            _acceptLoopTask = RunAcceptLoopAsync(listener, _serverCts.Token);
        }

        return Task.CompletedTask;
    }

    internal static Socket CreateBoundTcpListener(IPAddress bindAddress, int port, int backlog)
    {
        Socket listener = new(bindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            listener.NoDelay = true;
            listener.Bind(new IPEndPoint(bindAddress, port));
            listener.Listen(backlog);
            return listener;
        }
        catch
        {
            listener.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Stops accepting new connections and waits for active tunnels to close.
    /// </summary>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        Socket? listener;
        CancellationTokenSource? cts;
        Task? acceptTask;

        lock (_lifecycleLock)
        {
            listener = _listenerSocket;
            cts = _serverCts;
            acceptTask = _acceptLoopTask;

            _listenerSocket = null;
            _serverCts = null;
            _acceptLoopTask = null;
            BoundEndPoint = null;
        }

        if (cts is not null)
        {
            await cts.CancelAsync().ConfigureAwait(false);
        }

        if (listener is not null)
        {
            try
            {
                listener.Dispose();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        if (acceptTask is not null)
        {
            try
            {
                await acceptTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
        }

        Task[] pendingConnections = [.. _activeConnections.Values];
        if (pendingConnections.Length > 0)
        {
            try
            {
                await Task.WhenAll(pendingConnections).WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
        }

        cts?.Dispose();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        _connectionLimiter.Dispose();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        _connectionLimiter.Dispose();
    }

    /// <summary>
    /// Computes byte ranges for splitting an initial payload across the SNI boundary and/or fixed chunk size.
    /// </summary>
    public static IReadOnlyList<(int Offset, int Length)> ComputeFragmentRanges(
        int payloadLength,
        TlsClientHelloInspection inspection,
        bool splitAtSni,
        int fragmentChunkSize)
    {
        if (payloadLength <= 0)
        {
            return [];
        }

        List<(int Offset, int Length)> ranges = [];

        if (splitAtSni && inspection.IsTlsClientHello && inspection.HasSni)
        {
            int sniMid = inspection.ServerNameOffset >= 0 && inspection.ServerNameLength > 1
                ? inspection.ServerNameOffset + (inspection.ServerNameLength / 2)
                : inspection.SniExtensionOffset + (inspection.SniExtensionLength / 2);

            if (sniMid > 0 && sniMid < payloadLength)
            {
                AppendChunkedRange(ranges, 0, sniMid, fragmentChunkSize);
                AppendChunkedRange(ranges, sniMid, payloadLength - sniMid, fragmentChunkSize);
                return ranges;
            }
        }

        AppendChunkedRange(ranges, 0, payloadLength, fragmentChunkSize);
        return ranges;
    }

    private static void AppendChunkedRange(
        List<(int Offset, int Length)> ranges,
        int startOffset,
        int length,
        int chunkSize)
    {
        if (chunkSize <= 0 || length <= chunkSize)
        {
            ranges.Add((startOffset, length));
            return;
        }

        int offset = startOffset;
        int remaining = length;
        while (remaining > 0)
        {
            int take = Math.Min(chunkSize, remaining);
            ranges.Add((offset, take));
            offset += take;
            remaining -= take;
        }
    }

    private static void ValidateOptions(TlsFragmentationProxyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options.BindAddress);
        ArgumentOutOfRangeException.ThrowIfNegative(options.Port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Port, 65535);
        ArgumentOutOfRangeException.ThrowIfNegative(options.FragmentChunkSize);
        ArgumentOutOfRangeException.ThrowIfNegative(options.InterFragmentDelayMs);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.MaxConcurrentConnections, 0);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaxInitialPayloadBytes, 512);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.NormalizedHostHeaderName);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Accept loop must remain resilient against transient per-socket errors.")]
    private async Task RunAcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket? accepted;
            try
            {
                accepted = await AcceptWithinLimitAsync(listener, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                continue;
            }
            catch (Exception)
            {
                continue;
            }

            if (accepted is null)
            {
                continue;
            }

            long connectionId = Interlocked.Increment(ref _nextConnectionId);
            Interlocked.Increment(ref _totalConnectionsAccepted);

            Task connectionTask = HandleClientConnectionAsync(connectionId, accepted, cancellationToken);
            _activeConnections.TryAdd(connectionId, connectionTask);
        }
    }

    private async Task<Socket?> AcceptWithinLimitAsync(Socket listener, CancellationToken cancellationToken)
    {
        Socket incoming = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (await _connectionLimiter.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            {
                return incoming;
            }

            incoming.Dispose();
            return null;
        }
        catch
        {
            incoming.Dispose();
            throw;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Per-connection isolation ensures one malformed client cannot crash the proxy listener.")]
    private async Task HandleClientConnectionAsync(long connectionId, Socket clientSocket, CancellationToken cancellationToken)
    {
        try
        {
            using (clientSocket)
            {
                clientSocket.NoDelay = true;

                byte[] initialBuffer = ArrayPool<byte>.Shared.Rent(_options.MaxInitialPayloadBytes);
                try
                {
                    int initialRead = await clientSocket.ReceiveAsync(
                        initialBuffer.AsMemory(0, _options.MaxInitialPayloadBytes),
                        SocketFlags.None,
                        cancellationToken).ConfigureAwait(false);

                    if (initialRead <= 0)
                    {
                        return;
                    }

                    if (initialBuffer[0] == SocksVersion5)
                    {
                        await HandleSocks5ConnectionAsync(clientSocket, initialBuffer, initialRead, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await HandleHttpConnectionAsync(clientSocket, initialBuffer, initialRead, cancellationToken).ConfigureAwait(false);
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(initialBuffer);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception)
        {
        }
        finally
        {
            _activeConnections.TryRemove(connectionId, out _);
            _connectionLimiter.Release();
        }
    }

    private async Task HandleSocks5ConnectionAsync(
        Socket clientSocket,
        byte[] buffer,
        int initialRead,
        CancellationToken cancellationToken)
    {
        int totalRead = initialRead;
        while (totalRead < 2)
        {
            int n = await clientSocket.ReceiveAsync(
                buffer.AsMemory(totalRead, _options.MaxInitialPayloadBytes - totalRead),
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                return;
            }

            totalRead += n;
        }

        int nMethods = buffer[1];
        int greetingLength = 2 + nMethods;
        if (greetingLength > _options.MaxInitialPayloadBytes)
        {
            return;
        }

        while (totalRead < greetingLength)
        {
            int n = await clientSocket.ReceiveAsync(
                buffer.AsMemory(totalRead, _options.MaxInitialPayloadBytes - totalRead),
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                return;
            }

            totalRead += n;
        }

        bool supportsNoAuth = false;
        for (int i = 2; i < greetingLength; i++)
        {
            if (buffer[i] == SocksAuthNoAuth)
            {
                supportsNoAuth = true;
                break;
            }
        }

        if (!supportsNoAuth)
        {
            byte[] rejectAuth = [SocksVersion5, SocksAuthNoAcceptable];
            await SendAllAsync(clientSocket, rejectAuth, cancellationToken).ConfigureAwait(false);
            return;
        }

        byte[] acceptAuth = [SocksVersion5, SocksAuthNoAuth];
        await SendAllAsync(clientSocket, acceptAuth, cancellationToken).ConfigureAwait(false);

        // Shift any pipelined bytes after the greeting down to index 0
        int bufferedAfterGreeting = totalRead - greetingLength;
        if (bufferedAfterGreeting > 0)
        {
            Buffer.BlockCopy(buffer, greetingLength, buffer, 0, bufferedAfterGreeting);
        }

        totalRead = bufferedAfterGreeting;
        while (totalRead < 4)
        {
            int n = await clientSocket.ReceiveAsync(
                buffer.AsMemory(totalRead, _options.MaxInitialPayloadBytes - totalRead),
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                return;
            }

            totalRead += n;
        }

        if (buffer[0] != SocksVersion5)
        {
            return;
        }

        byte command = buffer[1];
        if (command != SocksCmdConnect)
        {
            await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyCommandNotSupported, cancellationToken).ConfigureAwait(false);
            return;
        }

        byte atyp = buffer[3];
        int requiredRequestLength;
        switch (atyp)
        {
            case SocksAtypIpv4:
                requiredRequestLength = 4 + 4 + 2;
                break;
            case SocksAtypIpv6:
                requiredRequestLength = 4 + 16 + 2;
                break;
            case SocksAtypDomain:
                while (totalRead < 5)
                {
                    int n = await clientSocket.ReceiveAsync(
                        buffer.AsMemory(totalRead, _options.MaxInitialPayloadBytes - totalRead),
                        SocketFlags.None,
                        cancellationToken).ConfigureAwait(false);
                    if (n <= 0)
                    {
                        return;
                    }

                    totalRead += n;
                }

                requiredRequestLength = 4 + 1 + buffer[4] + 2;
                break;
            default:
                await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyAddressTypeNotSupported, cancellationToken).ConfigureAwait(false);
                return;
        }

        if (requiredRequestLength > _options.MaxInitialPayloadBytes)
        {
            await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyGeneralFailure, cancellationToken).ConfigureAwait(false);
            return;
        }

        while (totalRead < requiredRequestLength)
        {
            int n = await clientSocket.ReceiveAsync(
                buffer.AsMemory(totalRead, _options.MaxInitialPayloadBytes - totalRead),
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                return;
            }

            totalRead += n;
        }

        string? targetHost = null;
        IPAddress? targetIp = null;
        int targetPort;

        switch (atyp)
        {
            case SocksAtypIpv4:
                targetIp = new IPAddress(buffer.AsSpan(4, 4));
                targetPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(8, 2));
                break;
            case SocksAtypIpv6:
                targetIp = new IPAddress(buffer.AsSpan(4, 16));
                targetPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(20, 2));
                break;
            case SocksAtypDomain:
                int domainLength = buffer[4];
                if (domainLength == 0)
                {
                    await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyGeneralFailure, cancellationToken).ConfigureAwait(false);
                    return;
                }

                targetHost = Encoding.UTF8.GetString(buffer, 5, domainLength);
                targetPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(5 + domainLength, 2));
                break;
            default:
                return;
        }

        if (targetPort <= 0)
        {
            await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyGeneralFailure, cancellationToken).ConfigureAwait(false);
            return;
        }

        TargetResolutionResult resolution = await ResolveTargetAddressesAsync(targetHost, targetIp, cancellationToken).ConfigureAwait(false);
        if (resolution.Status == TargetResolutionStatus.BlockedBySsrf)
        {
            await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyNotAllowedByRuleset, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (resolution.Status != TargetResolutionStatus.Success || resolution.Addresses.Count == 0)
        {
            await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyHostUnreachable, cancellationToken).ConfigureAwait(false);
            return;
        }

        using Socket? upstreamSocket = await ConnectUpstreamAsync(resolution.Addresses, targetPort, cancellationToken).ConfigureAwait(false);
        if (upstreamSocket is null)
        {
            await SendSocks5ErrorReplyAsync(clientSocket, SocksReplyConnectionRefused, cancellationToken).ConfigureAwait(false);
            return;
        }

        await SendSocks5SuccessReplyAsync(clientSocket, upstreamSocket.LocalEndPoint as IPEndPoint, cancellationToken).ConfigureAwait(false);

        int leftoverLength = totalRead - requiredRequestLength;
        ReadOnlyMemory<byte> initialPayload = leftoverLength > 0
            ? buffer.AsMemory(requiredRequestLength, leftoverLength)
            : ReadOnlyMemory<byte>.Empty;

        await FragmentFirstPayloadAndRelayAsync(clientSocket, upstreamSocket, initialPayload, cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleHttpConnectionAsync(
        Socket clientSocket,
        byte[] buffer,
        int initialRead,
        CancellationToken cancellationToken)
    {
        int totalRead = initialRead;
        int headerEndIndex = IndexOfHeaderTerminator(buffer.AsSpan(0, totalRead));

        while (headerEndIndex < 0)
        {
            if (totalRead >= _options.MaxInitialPayloadBytes)
            {
                await SendHttpErrorAsync(clientSocket, "431 Request Header Fields Too Large", cancellationToken).ConfigureAwait(false);
                return;
            }

            int n = await clientSocket.ReceiveAsync(
                buffer.AsMemory(totalRead, _options.MaxInitialPayloadBytes - totalRead),
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                return;
            }

            totalRead += n;
            headerEndIndex = IndexOfHeaderTerminator(buffer.AsSpan(0, totalRead));
        }

        int headerByteLength = headerEndIndex + HeaderTerminator.Length;
        string rawHeaders = Encoding.ASCII.GetString(buffer, 0, headerEndIndex);
        string[] lines = rawHeaders.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0)
        {
            await SendHttpErrorAsync(clientSocket, "400 Bad Request", cancellationToken).ConfigureAwait(false);
            return;
        }

        string[] requestLineParts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (requestLineParts.Length < 3)
        {
            await SendHttpErrorAsync(clientSocket, "400 Bad Request", cancellationToken).ConfigureAwait(false);
            return;
        }

        string method = requestLineParts[0];
        string requestTarget = requestLineParts[1];
        string httpVersion = requestLineParts[2];

        int leftoverLength = totalRead - headerByteLength;
        ReadOnlyMemory<byte> leftoverPayload = leftoverLength > 0
            ? buffer.AsMemory(headerByteLength, leftoverLength)
            : ReadOnlyMemory<byte>.Empty;

        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryParseAuthority(requestTarget, defaultPort: 443, out string? host, out int port))
            {
                await SendHttpErrorAsync(clientSocket, "400 Bad Request", cancellationToken).ConfigureAwait(false);
                return;
            }

            TargetResolutionResult resolution = await ResolveTargetAddressesAsync(host, explicitIp: null, cancellationToken).ConfigureAwait(false);
            if (resolution.Status == TargetResolutionStatus.BlockedBySsrf)
            {
                await SendHttpErrorAsync(clientSocket, "403 Forbidden", cancellationToken).ConfigureAwait(false);
                return;
            }

            if (resolution.Status != TargetResolutionStatus.Success || resolution.Addresses.Count == 0)
            {
                await SendHttpErrorAsync(clientSocket, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
                return;
            }

            using Socket? upstreamSocket = await ConnectUpstreamAsync(resolution.Addresses, port, cancellationToken).ConfigureAwait(false);
            if (upstreamSocket is null)
            {
                await SendHttpErrorAsync(clientSocket, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
                return;
            }

            byte[] established = Encoding.ASCII.GetBytes($"{httpVersion} 200 Connection Established\r\n\r\n");
            await SendAllAsync(clientSocket, established, cancellationToken).ConfigureAwait(false);

            await FragmentFirstPayloadAndRelayAsync(clientSocket, upstreamSocket, leftoverPayload, cancellationToken).ConfigureAwait(false);
            return;
        }

        // Plain HTTP proxy request
        if (!TryResolvePlainHttpTarget(requestTarget, lines, out string? plainHost, out int plainPort, out string originRequestTarget))
        {
            await SendHttpErrorAsync(clientSocket, "400 Bad Request", cancellationToken).ConfigureAwait(false);
            return;
        }

        TargetResolutionResult plainResolution = await ResolveTargetAddressesAsync(plainHost, explicitIp: null, cancellationToken).ConfigureAwait(false);
        if (plainResolution.Status == TargetResolutionStatus.BlockedBySsrf)
        {
            await SendHttpErrorAsync(clientSocket, "403 Forbidden", cancellationToken).ConfigureAwait(false);
            return;
        }

        if (plainResolution.Status != TargetResolutionStatus.Success || plainResolution.Addresses.Count == 0)
        {
            await SendHttpErrorAsync(clientSocket, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
            return;
        }

        using Socket? plainUpstream = await ConnectUpstreamAsync(plainResolution.Addresses, plainPort, cancellationToken).ConfigureAwait(false);
        if (plainUpstream is null)
        {
            await SendHttpErrorAsync(clientSocket, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
            return;
        }

        byte[] rewrittenHeaders = RewritePlainHttpRequestHeaders(
            method,
            originRequestTarget,
            httpVersion,
            lines,
            _options.NormalizePlainHttpHostHeader ? _options.NormalizedHostHeaderName : null);

        await SendAllAsync(plainUpstream, rewrittenHeaders, cancellationToken).ConfigureAwait(false);
        if (!leftoverPayload.IsEmpty)
        {
            await SendAllAsync(plainUpstream, leftoverPayload, cancellationToken).ConfigureAwait(false);
        }

        await RelayBidirectionalAsync(clientSocket, plainUpstream, cancellationToken).ConfigureAwait(false);
    }

    private async Task FragmentFirstPayloadAndRelayAsync(
        Socket clientSocket,
        Socket upstreamSocket,
        ReadOnlyMemory<byte> initialLeftover,
        CancellationToken cancellationToken)
    {
        byte[]? rentedBuffer = null;
        try
        {
            ReadOnlyMemory<byte> firstPayload;
            if (!initialLeftover.IsEmpty)
            {
                firstPayload = initialLeftover;
            }
            else
            {
                rentedBuffer = ArrayPool<byte>.Shared.Rent(_options.MaxInitialPayloadBytes);
                int read = await clientSocket.ReceiveAsync(
                    rentedBuffer.AsMemory(0, _options.MaxInitialPayloadBytes),
                    SocketFlags.None,
                    cancellationToken).ConfigureAwait(false);

                if (read <= 0)
                {
                    return;
                }

                // If the client started a TLS record and delivered only part of the record in the first read,
                // try assembling the full record (with a short non-blocking grace window) before SNI splitting.
                if (rentedBuffer[0] == 0x16 && read >= 5)
                {
                    int declaredTotal = 5 + BinaryPrimitives.ReadUInt16BigEndian(rentedBuffer.AsSpan(3, 2));
                    if (declaredTotal <= _options.MaxInitialPayloadBytes && read < declaredTotal)
                    {
                        using CancellationTokenSource readMoreCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        readMoreCts.CancelAfter(TimeSpan.FromMilliseconds(150));
                        while (read < declaredTotal)
                        {
                            try
                            {
                                int more = await clientSocket.ReceiveAsync(
                                    rentedBuffer.AsMemory(read, declaredTotal - read),
                                    SocketFlags.None,
                                    readMoreCts.Token).ConfigureAwait(false);
                                if (more <= 0)
                                {
                                    break;
                                }

                                read += more;
                            }
                            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                            {
                                break;
                            }
                        }
                    }
                }

                firstPayload = rentedBuffer.AsMemory(0, read);
            }

            TlsClientHelloInspection inspection = TlsClientHelloInspector.Inspect(firstPayload.Span);
            IReadOnlyList<(int Offset, int Length)> ranges = ComputeFragmentRanges(
                firstPayload.Length,
                inspection,
                _options.SplitAtSni,
                _options.FragmentChunkSize);

            if (inspection.IsTlsClientHello && ranges.Count > 1)
            {
                Interlocked.Increment(ref _fragmentedClientHellosCount);
            }

            for (int i = 0; i < ranges.Count; i++)
            {
                if (i > 0 && _options.InterFragmentDelayMs > 0)
                {
                    await Task.Delay(_options.InterFragmentDelayMs, cancellationToken).ConfigureAwait(false);
                }

                (int offset, int length) = ranges[i];
                await SendAllAsync(upstreamSocket, firstPayload.Slice(offset, length), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            if (rentedBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedBuffer);
            }
        }

        await RelayBidirectionalAsync(clientSocket, upstreamSocket, cancellationToken).ConfigureAwait(false);
    }

    private static async Task RelayBidirectionalAsync(Socket clientSocket, Socket upstreamSocket, CancellationToken cancellationToken)
    {
        Task clientToUpstream = PumpDirectionAsync(clientSocket, upstreamSocket, cancellationToken);
        Task upstreamToClient = PumpDirectionAsync(upstreamSocket, clientSocket, cancellationToken);
        await Task.WhenAll(clientToUpstream, upstreamToClient).ConfigureAwait(false);
    }

    private static async Task PumpDirectionAsync(Socket source, Socket destination, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(RelayBufferSize);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int bytesRead = await source.ReceiveAsync(buffer.AsMemory(0, RelayBufferSize), SocketFlags.None, cancellationToken).ConfigureAwait(false);
                if (bytesRead <= 0)
                {
                    break;
                }

                await SendAllAsync(destination, buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            try
            {
                destination.Shutdown(SocketShutdown.Send);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    private async Task<TargetResolutionResult> ResolveTargetAddressesAsync(
        string? host,
        IPAddress? explicitIp,
        CancellationToken cancellationToken)
    {
        if (explicitIp is not null)
        {
            if (_options.BlockPrivateDestinationIps && IpSafetyInspector.IsPrivateOrBogon(explicitIp))
            {
                Interlocked.Increment(ref _blockedSsrfsCount);
                return new TargetResolutionResult(TargetResolutionStatus.BlockedBySsrf, []);
            }

            return new TargetResolutionResult(TargetResolutionStatus.Success, [explicitIp]);
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            return new TargetResolutionResult(TargetResolutionStatus.ResolutionFailed, []);
        }

        string trimmedHost = host.Trim();
        if (trimmedHost.Length >= 2 && trimmedHost[0] == '[' && trimmedHost[^1] == ']')
        {
            trimmedHost = trimmedHost[1..^1];
        }

        if (IPAddress.TryParse(trimmedHost, out IPAddress? parsedLiteral))
        {
            if (_options.BlockPrivateDestinationIps && IpSafetyInspector.IsPrivateOrBogon(parsedLiteral))
            {
                Interlocked.Increment(ref _blockedSsrfsCount);
                return new TargetResolutionResult(TargetResolutionStatus.BlockedBySsrf, []);
            }

            return new TargetResolutionResult(TargetResolutionStatus.Success, [parsedLiteral]);
        }

        IReadOnlyList<IPAddress> resolved = await _hostResolver(trimmedHost, cancellationToken).ConfigureAwait(false);
        if (resolved is null || resolved.Count == 0)
        {
            return new TargetResolutionResult(TargetResolutionStatus.ResolutionFailed, []);
        }

        if (!_options.BlockPrivateDestinationIps)
        {
            return new TargetResolutionResult(TargetResolutionStatus.Success, resolved);
        }

        List<IPAddress> allowed = [];
        bool anyBlocked = false;
        for (int i = 0; i < resolved.Count; i++)
        {
            IPAddress candidate = resolved[i];
            if (IpSafetyInspector.IsPrivateOrBogon(candidate))
            {
                anyBlocked = true;
            }
            else
            {
                allowed.Add(candidate);
            }
        }

        if (allowed.Count == 0)
        {
            if (anyBlocked)
            {
                Interlocked.Increment(ref _blockedSsrfsCount);
                return new TargetResolutionResult(TargetResolutionStatus.BlockedBySsrf, []);
            }

            return new TargetResolutionResult(TargetResolutionStatus.ResolutionFailed, []);
        }

        return new TargetResolutionResult(TargetResolutionStatus.Success, allowed);
    }

    private async Task<Socket?> ConnectUpstreamAsync(
        IReadOnlyList<IPAddress> addresses,
        int port,
        CancellationToken cancellationToken)
    {
        for (int i = 0; i < addresses.Count; i++)
        {
            IPAddress address = addresses[i];
            Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            try
            {
                using CancellationTokenSource connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(_options.ConnectTimeout);
                await socket.ConnectAsync(new IPEndPoint(address, port), connectCts.Token).ConfigureAwait(false);
                return socket;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                socket.Dispose();
            }
            catch (SocketException)
            {
                socket.Dispose();
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        return null;
    }

    private static async Task SendAllAsync(Socket socket, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            int sent = await socket.SendAsync(payload.Slice(offset), SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (sent <= 0)
            {
                throw new SocketException((int)SocketError.ConnectionReset);
            }

            offset += sent;
        }
    }

    private static async Task SendSocks5ErrorReplyAsync(Socket clientSocket, byte replyCode, CancellationToken cancellationToken)
    {
        byte[] reply = [SocksVersion5, replyCode, 0x00, SocksAtypIpv4, 0, 0, 0, 0, 0, 0];
        await SendAllAsync(clientSocket, reply, cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendSocks5SuccessReplyAsync(Socket clientSocket, IPEndPoint? localEndPoint, CancellationToken cancellationToken)
    {
        if (localEndPoint is not null && localEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] replyV6 = new byte[4 + 16 + 2];
            replyV6[0] = SocksVersion5;
            replyV6[1] = SocksReplySucceeded;
            replyV6[2] = 0x00;
            replyV6[3] = SocksAtypIpv6;
            localEndPoint.Address.TryWriteBytes(replyV6.AsSpan(4, 16), out _);
            BinaryPrimitives.WriteUInt16BigEndian(replyV6.AsSpan(20, 2), (ushort)localEndPoint.Port);
            await SendAllAsync(clientSocket, replyV6, cancellationToken).ConfigureAwait(false);
            return;
        }

        byte[] replyV4 = new byte[4 + 4 + 2];
        replyV4[0] = SocksVersion5;
        replyV4[1] = SocksReplySucceeded;
        replyV4[2] = 0x00;
        replyV4[3] = SocksAtypIpv4;
        if (localEndPoint is not null && localEndPoint.AddressFamily == AddressFamily.InterNetwork)
        {
            localEndPoint.Address.TryWriteBytes(replyV4.AsSpan(4, 4), out _);
            BinaryPrimitives.WriteUInt16BigEndian(replyV4.AsSpan(8, 2), (ushort)localEndPoint.Port);
        }

        await SendAllAsync(clientSocket, replyV4, cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendHttpErrorAsync(Socket clientSocket, string statusLine, CancellationToken cancellationToken)
    {
        byte[] response = Encoding.ASCII.GetBytes($"HTTP/1.1 {statusLine}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await SendAllAsync(clientSocket, response, cancellationToken).ConfigureAwait(false);
    }

    private static int IndexOfHeaderTerminator(ReadOnlySpan<byte> span)
    {
        return span.IndexOf(HeaderTerminator);
    }

    private static bool TryParseAuthority(string authority, int defaultPort, [NotNullWhen(true)] out string? host, out int port)
    {
        host = null;
        port = 0;

        if (string.IsNullOrWhiteSpace(authority))
        {
            return false;
        }

        string trimmed = authority.Trim();
        if (trimmed[0] == '[')
        {
            int closeBracket = trimmed.IndexOf(']', StringComparison.Ordinal);
            if (closeBracket <= 1)
            {
                return false;
            }

            host = trimmed[1..closeBracket];
            if (closeBracket + 1 == trimmed.Length)
            {
                port = defaultPort;
                return port is > 0 and <= 65535;
            }

            if (trimmed[closeBracket + 1] != ':')
            {
                return false;
            }

            return int.TryParse(trimmed.AsSpan(closeBracket + 2), NumberStyles.None, CultureInfo.InvariantCulture, out port)
                && port is > 0 and <= 65535;
        }

        int colonIndex = trimmed.LastIndexOf(':');
        if (colonIndex < 0)
        {
            host = trimmed;
            port = defaultPort;
            return port is > 0 and <= 65535;
        }

        if (colonIndex == 0 || colonIndex == trimmed.Length - 1)
        {
            return false;
        }

        // Unbracketed IPv6 literal without explicit port
        if (trimmed.IndexOf(':', StringComparison.Ordinal) != colonIndex)
        {
            if (IPAddress.TryParse(trimmed, out _))
            {
                host = trimmed;
                port = defaultPort;
                return port is > 0 and <= 65535;
            }

            return false;
        }

        host = trimmed[..colonIndex];
        return int.TryParse(trimmed.AsSpan(colonIndex + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port)
            && port is > 0 and <= 65535;
    }

    private static bool TryResolvePlainHttpTarget(
        string requestTarget,
        string[] lines,
        [NotNullWhen(true)] out string? host,
        out int port,
        out string originRequestTarget)
    {
        host = null;
        port = 80;
        originRequestTarget = "/";

        if (requestTarget.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            Uri.TryCreate(requestTarget, UriKind.Absolute, out Uri? absoluteUri) &&
            string.Equals(absoluteUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            host = absoluteUri.Host;
            port = absoluteUri.Port;
            originRequestTarget = string.IsNullOrEmpty(absoluteUri.PathAndQuery) ? "/" : absoluteUri.PathAndQuery;
            return !string.IsNullOrWhiteSpace(host) && port is > 0 and <= 65535;
        }

        if (!requestTarget.StartsWith('/') && !string.Equals(requestTarget, "*", StringComparison.Ordinal))
        {
            return false;
        }

        originRequestTarget = requestTarget;
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            ReadOnlySpan<char> name = line.AsSpan(0, colon).Trim();
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                string hostValue = line[(colon + 1)..].Trim();
                return TryParseAuthority(hostValue, defaultPort: 80, out host, out port);
            }
        }

        return false;
    }

    private static byte[] RewritePlainHttpRequestHeaders(
        string method,
        string originRequestTarget,
        string httpVersion,
        string[] lines,
        string? normalizedHostHeaderName)
    {
        StringBuilder sb = new(256);
        sb.Append(method).Append(' ').Append(originRequestTarget).Append(' ').Append(httpVersion).Append("\r\n");

        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            if (string.IsNullOrEmpty(line))
            {
                continue;
            }

            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            ReadOnlySpan<char> headerName = line.AsSpan(0, colon).Trim();
            if (headerName.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
                headerName.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (normalizedHostHeaderName is not null && headerName.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                ReadOnlySpan<char> headerValue = line.AsSpan(colon + 1).TrimStart();
                sb.Append(normalizedHostHeaderName).Append(": ").Append(headerValue).Append("\r\n");
            }
            else
            {
                sb.Append(line).Append("\r\n");
            }
        }

        sb.Append("\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private enum TargetResolutionStatus
    {
        Success = 0,
        BlockedBySsrf = 1,
        ResolutionFailed = 2
    }

    private readonly record struct TargetResolutionResult(
        TargetResolutionStatus Status,
        IReadOnlyList<IPAddress> Addresses);
}
