using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// RFC 7858 DNS-over-TLS (DoT) upstream client with persistent connection reuse, strict X.509 chain &amp; SAN
/// validation, optional <c>SpkiPinSha256</c> verification, and optional <see cref="TlsFragmentingStream"/>.
/// </summary>
public sealed class DotDnsClient : IDnsUpstreamClient, IAsyncDisposable, IDisposable
{
    private const int DefaultDotPort = 853;

    private readonly IBootstrapResolver? _bootstrapResolver;
    private readonly TransportOptions _options;
    private readonly ConcurrentDictionary<DotConnectionKey, ConcurrentQueue<PooledDotConnection>> _pool = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="DotDnsClient"/>.
    /// </summary>
    public DotDnsClient(
        IBootstrapResolver? bootstrapResolver = null,
        TransportOptions? options = null)
    {
        _bootstrapResolver = bootstrapResolver;
        _options = options ?? new TransportOptions();
    }

    /// <inheritdoc />
    public DnsProtocol Protocol => DnsProtocol.DoT;

    /// <inheritdoc />
    public async Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        string? hostFromStamp = null;
        int? portFromStamp = null;
        if (EndpointResolutionHelper.TryGetParsedStamp(upstream, out DnsStamp? stamp) && stamp is not null)
        {
            if (!string.IsNullOrWhiteSpace(stamp.HostName))
            {
                hostFromStamp = stamp.HostName;
            }

            if (EndpointResolutionHelper.TryParseEndpointIp(stamp.ServerAddress, out _, out int? parsedStampPort))
            {
                portFromStamp = parsedStampPort;
            }
        }

        string? configuredHost = !string.IsNullOrWhiteSpace(upstream.DotHost)
            ? upstream.DotHost.Trim()
            : hostFromStamp;

        IReadOnlyList<IPAddress> targets = await EndpointResolutionHelper
            .ResolveTargetAddressesAsync(upstream, configuredHost, _bootstrapResolver, cancellationToken)
            .ConfigureAwait(false);

        if (targets.Count == 0)
        {
            throw new InvalidOperationException($"No IP address could be resolved for DoT upstream '{upstream.Name}'.");
        }

        int port = upstream.Port ?? portFromStamp ?? DefaultDotPort;
        bool useFragmentation = _options.EnableTlsFragmentation || EndpointResolutionHelper.HasTlsFragmentationTag(upstream);
        Exception? lastException = null;

        foreach (IPAddress targetIp in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string targetHost = !string.IsNullOrWhiteSpace(configuredHost) ? configuredHost : targetIp.ToString();

            try
            {
                return await QueryEndpointAsync(
                    query,
                    targetIp,
                    port,
                    targetHost,
                    upstream.SpkiPinSha256,
                    useFragmentation,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (AuthenticationException)
            {
                throw;
            }
            catch (SocketException ex)
            {
                lastException = ex;
            }
            catch (IOException ex)
            {
                lastException = ex;
            }
            catch (TimeoutException ex)
            {
                lastException = ex;
            }
            catch (InvalidDataException ex)
            {
                lastException = ex;
            }
            catch (FormatException ex)
            {
                lastException = ex;
            }
        }

        throw new IOException(
            $"All {targets.Count} DoT endpoint(s) failed for upstream '{upstream.Name}'.",
            lastException);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (KeyValuePair<DotConnectionKey, ConcurrentQueue<PooledDotConnection>> pair in _pool)
        {
            while (pair.Value.TryDequeue(out PooledDotConnection? conn))
            {
                conn.DisposeSynchronously();
            }
        }

        _pool.Clear();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (KeyValuePair<DotConnectionKey, ConcurrentQueue<PooledDotConnection>> pair in _pool)
        {
            while (pair.Value.TryDequeue(out PooledDotConnection? conn))
            {
                await conn.DisposeAsync().ConfigureAwait(false);
            }
        }

        _pool.Clear();
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership is transferred to AsyncDisposableLease<T> and disposed unless detached.")]
    private async Task<UpstreamQueryResult> QueryEndpointAsync(
        DnsMessage query,
        IPAddress targetIp,
        int port,
        string targetHost,
        string? spkiPinSha256,
        bool useFragmentation,
        CancellationToken cancellationToken)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string endpointLabel = EndpointResolutionHelper.FormatEndpoint(targetIp, port);
        DotConnectionKey key = new(targetIp, port, targetHost, spkiPinSha256 ?? string.Empty, useFragmentation);

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);
        CancellationToken effectiveToken = timeoutCts.Token;

        try
        {
            PooledDotConnection? rented = TryRentConnection(key);
            if (rented is not null)
            {
                await using AsyncDisposableLease<PooledDotConnection> pooledLease = new(rented);
                try
                {
                    DnsMessage response = await SendReceiveAsync(pooledLease.Resource.SslStream, query, effectiveToken).ConfigureAwait(false);
                    pooledLease.Resource.LastUsedUtc = DateTimeOffset.UtcNow;
                    ReturnConnection(key, pooledLease.Detach());
                    stopwatch.Stop();
                    return new UpstreamQueryResult(response, stopwatch.Elapsed, endpointLabel, DnsProtocol.DoT);
                }
                catch (IOException)
                {
                }
                catch (SocketException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            }

            await using AsyncDisposableLease<PooledDotConnection> freshLease = new(
                await CreateConnectionAsync(key, effectiveToken).ConfigureAwait(false));
            DnsMessage freshResponse = await SendReceiveAsync(freshLease.Resource.SslStream, query, effectiveToken).ConfigureAwait(false);
            freshLease.Resource.LastUsedUtc = DateTimeOffset.UtcNow;
            ReturnConnection(key, freshLease.Detach());
            stopwatch.Stop();
            return new UpstreamQueryResult(freshResponse, stopwatch.Elapsed, endpointLabel, DnsProtocol.DoT);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"DoT query to {endpointLabel} timed out after {_options.Timeout.TotalMilliseconds:F0} ms.", ex);
        }
    }

    private PooledDotConnection? TryRentConnection(DotConnectionKey key)
    {
        if (!_pool.TryGetValue(key, out ConcurrentQueue<PooledDotConnection>? queue))
        {
            return null;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        while (queue.TryDequeue(out PooledDotConnection? candidate))
        {
            if (now - candidate.LastUsedUtc <= _options.ConnectionIdleTimeout && candidate.IsUsable)
            {
                return candidate;
            }

            candidate.DisposeSynchronously();
        }

        return null;
    }

    private void ReturnConnection(DotConnectionKey key, PooledDotConnection connection)
    {
        if (_disposed || !connection.IsUsable)
        {
            connection.DisposeSynchronously();
            return;
        }

        ConcurrentQueue<PooledDotConnection> queue = _pool.GetOrAdd(key, static _ => new ConcurrentQueue<PooledDotConnection>());
        if (queue.Count >= _options.MaxIdleConnectionsPerEndpoint)
        {
            connection.DisposeSynchronously();
            return;
        }

        queue.Enqueue(connection);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership is transferred to AsyncDisposableLease<T> and disposed unless detached.")]
    private async Task<PooledDotConnection> CreateConnectionAsync(DotConnectionKey key, CancellationToken cancellationToken)
    {
        Socket socket = new(key.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        bool ownershipTransferred = false;

        try
        {
            socket.NoDelay = true;
            await socket.ConnectAsync(new IPEndPoint(key.Address, key.Port), cancellationToken).ConfigureAwait(false);
            await using AsyncDisposableLease<SslStream> sslLease = new(CreateWrappedSslStream(socket, key));
            ownershipTransferred = true;

            X509ChainPolicy? chainPolicy = TlsCertificateValidator.BuildCustomChainPolicy(_options.CustomTrustAnchors);
            SslClientAuthenticationOptions authOptions = new()
            {
                TargetHost = key.TargetHost,
                EnabledSslProtocols = _options.EnabledSslProtocols,
                ApplicationProtocols = [new SslApplicationProtocol("dot")],
                CertificateChainPolicy = chainPolicy
            };

            await sslLease.Resource.AuthenticateAsClientAsync(authOptions, cancellationToken).ConfigureAwait(false);
            return new PooledDotConnection(sslLease.Detach());
        }
        finally
        {
            if (!ownershipTransferred)
            {
                socket.Dispose();
            }
        }
    }

    private SslStream CreateWrappedSslStream(Socket socket, DotConnectionKey key)
    {
        Stream? transportStream = null;
        SslStream? sslStream = null;

        try
        {
            transportStream = key.UseTlsFragmentation
                ? new TlsFragmentingStream(socket, _options.TlsFragmentChunkSize, ownsSocket: true, _options.TlsFragmentInterChunkDelay)
                : new NetworkStream(socket, ownsSocket: true);

            string? expectedPin = string.IsNullOrEmpty(key.SpkiPinSha256) ? null : key.SpkiPinSha256;
            sslStream = new SslStream(
                transportStream,
                leaveInnerStreamOpen: false,
                (_, certificate, _, sslPolicyErrors) =>
                    TlsCertificateValidator.ValidateServerCertificate(certificate, sslPolicyErrors, expectedPin));
            transportStream = null;

            SslStream result = sslStream;
            sslStream = null;
            return result;
        }
        finally
        {
            sslStream?.Dispose();
            transportStream?.Dispose();
        }
    }

    private static async Task<DnsMessage> SendReceiveAsync(
        SslStream sslStream,
        DnsMessage query,
        CancellationToken cancellationToken)
    {
        using PooledDnsPacket packet = DnsWireCodec.SerializePooled(query);
        if (packet.Length > ushort.MaxValue)
        {
            throw new InvalidDataException("DNS query exceeds maximum DoT frame length.");
        }

        byte[] framed = new byte[2 + packet.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)packet.Length);
        packet.Span.CopyTo(framed.AsSpan(2));

        await sslStream.WriteAsync(framed.AsMemory(), cancellationToken).ConfigureAwait(false);
        await sslStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] lenBuffer = new byte[2];
        await sslStream.ReadExactlyAsync(lenBuffer.AsMemory(), cancellationToken).ConfigureAwait(false);
        int responseLength = BinaryPrimitives.ReadUInt16BigEndian(lenBuffer);
        if (responseLength < DnsHeader.WireSize)
        {
            throw new InvalidDataException($"Invalid DoT DNS response frame length: {responseLength}.");
        }

        byte[] responseBuffer = new byte[responseLength];
        await sslStream.ReadExactlyAsync(responseBuffer.AsMemory(), cancellationToken).ConfigureAwait(false);

        DnsMessage response = DnsWireCodec.Parse(responseBuffer);
        if (response.Header.Id != query.Header.Id)
        {
            throw new InvalidDataException(
                $"DoT DNS response ID mismatch (expected {query.Header.Id}, received {response.Header.Id}).");
        }

        return response;
    }

    private readonly record struct DotConnectionKey(
        IPAddress Address,
        int Port,
        string TargetHost,
        string SpkiPinSha256,
        bool UseTlsFragmentation);

    private sealed class PooledDotConnection(SslStream sslStream) : IAsyncDisposable
    {
        private bool _disposed;

        public SslStream SslStream { get; } = sslStream;

        public DateTimeOffset LastUsedUtc { get; set; } = DateTimeOffset.UtcNow;

        public bool IsUsable => !_disposed && SslStream.CanRead && SslStream.CanWrite;

        public void DisposeSynchronously()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            SslStream.Dispose();
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            await SslStream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed class AsyncDisposableLease<T>(T resource) : IAsyncDisposable, IDisposable
        where T : class, IAsyncDisposable
    {
        private T? _resource = resource;

        public T Resource
        {
            get
            {
                T? captured = _resource;
                ObjectDisposedException.ThrowIf(captured is null, typeof(T));
                return captured;
            }
        }

        public T Detach()
        {
            T? captured = Interlocked.Exchange(ref _resource, null);
            ObjectDisposedException.ThrowIf(captured is null, typeof(T));
            return captured;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _resource, null) is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        public ValueTask DisposeAsync()
        {
            T? captured = Interlocked.Exchange(ref _resource, null);
            return captured is not null ? captured.DisposeAsync() : ValueTask.CompletedTask;
        }
    }
}
