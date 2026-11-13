using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// RFC 9250 DNS-over-QUIC (DoQ) upstream client built on <see cref="QuicConnection"/> with <c>alpn="doq"</c>,
/// 2-byte length framing per bidirectional stream, explicit <see cref="SslClientAuthenticationOptions.TargetHost"/>,
/// and optional <c>SpkiPinSha256</c> validation.
/// </summary>
public sealed class DoqDnsClient : IDnsUpstreamClient, IAsyncDisposable, IDisposable
{
    private const int DefaultDoqPort = 853;

    private readonly IBootstrapResolver? _bootstrapResolver;
    private readonly TransportOptions _options;
    private readonly ConcurrentDictionary<DoqConnectionKey, PooledDoqConnection> _connections = new();
    private readonly SemaphoreSlim _connectLock = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="DoqDnsClient"/>.
    /// </summary>
    public DoqDnsClient(
        IBootstrapResolver? bootstrapResolver = null,
        TransportOptions? options = null)
    {
        _bootstrapResolver = bootstrapResolver;
        _options = options ?? new TransportOptions();
    }

    /// <inheritdoc />
    public DnsProtocol Protocol => DnsProtocol.DoQ;

    /// <summary>Gets whether QUIC transport is supported on the current host OS and runtime.</summary>
    public static bool IsQuicSupported => QuicConnection.IsSupported;

    /// <inheritdoc />
    public async Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            || !QuicConnection.IsSupported)
        {
            throw new PlatformNotSupportedException("DNS-over-QUIC is not supported on this platform (msquic/TLS 1.3 unavailable).");
        }

        string? hostFromStamp = null;
        int? portFromStamp = null;
        if (EndpointResolutionHelper.TryGetParsedStamp(upstream, out DnsStamp? stamp) && stamp is not null)
        {
            if (!string.IsNullOrWhiteSpace(stamp.HostName))
            {
                hostFromStamp = stamp.HostName;
            }

            if (EndpointResolutionHelper.TryParseEndpointIp(stamp.ServerAddress, out _, out int? stampPort))
            {
                portFromStamp = stampPort;
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
            throw new InvalidOperationException($"No IP address could be resolved for DoQ upstream '{upstream.Name}'.");
        }

        int port = upstream.Port ?? portFromStamp ?? DefaultDoqPort;
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
            catch (QuicException ex)
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
        }

        throw new IOException(
            $"All {targets.Count} DoQ endpoint(s) failed for upstream '{upstream.Name}'.",
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
        foreach (KeyValuePair<DoqConnectionKey, PooledDoqConnection> pair in _connections)
        {
            pair.Value.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        _connections.Clear();
        _connectLock.Dispose();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (KeyValuePair<DoqConnectionKey, PooledDoqConnection> pair in _connections)
        {
            await pair.Value.DisposeAsync().ConfigureAwait(false);
        }

        _connections.Clear();
        _connectLock.Dispose();
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private async Task<UpstreamQueryResult> QueryEndpointAsync(
        DnsMessage query,
        IPAddress targetIp,
        int port,
        string targetHost,
        string? spkiPinSha256,
        CancellationToken cancellationToken)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string endpointLabel = EndpointResolutionHelper.FormatEndpoint(targetIp, port);
        DoqConnectionKey key = new(targetIp, port, targetHost, spkiPinSha256 ?? string.Empty);

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);
        CancellationToken effectiveToken = timeoutCts.Token;

        try
        {
            if (_connections.TryGetValue(key, out PooledDoqConnection? cached))
            {
                try
                {
                    DnsMessage cachedResponse = await ExecuteQueryOnConnectionAsync((QuicConnection)cached.Connection, query, effectiveToken).ConfigureAwait(false);
                    cached.LastUsedUtc = DateTimeOffset.UtcNow;
                    stopwatch.Stop();
                    return new UpstreamQueryResult(cachedResponse, stopwatch.Elapsed, endpointLabel, DnsProtocol.DoQ);
                }
                catch (QuicException)
                {
                    if (_connections.TryRemove(key, out PooledDoqConnection? removed))
                    {
                        await removed.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch (IOException)
                {
                    if (_connections.TryRemove(key, out PooledDoqConnection? removed))
                    {
                        await removed.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch (ObjectDisposedException)
                {
                    if (_connections.TryRemove(key, out PooledDoqConnection? removed))
                    {
                        await removed.DisposeAsync().ConfigureAwait(false);
                    }
                }
            }

            PooledDoqConnection fresh = await GetOrCreateConnectionAsync(key, effectiveToken).ConfigureAwait(false);
            DnsMessage response = await ExecuteQueryOnConnectionAsync((QuicConnection)fresh.Connection, query, effectiveToken).ConfigureAwait(false);
            fresh.LastUsedUtc = DateTimeOffset.UtcNow;
            stopwatch.Stop();
            return new UpstreamQueryResult(response, stopwatch.Elapsed, endpointLabel, DnsProtocol.DoQ);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"DoQ query to {endpointLabel} timed out after {_options.Timeout.TotalMilliseconds:F0} ms.", ex);
        }
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private async Task<PooledDoqConnection> GetOrCreateConnectionAsync(DoqConnectionKey key, CancellationToken cancellationToken)
    {
        if (_connections.TryGetValue(key, out PooledDoqConnection? existing))
        {
            if (DateTimeOffset.UtcNow - existing.LastUsedUtc <= _options.ConnectionIdleTimeout)
            {
                return existing;
            }

            if (_connections.TryRemove(key, out PooledDoqConnection? stale))
            {
                await stale.DisposeAsync().ConfigureAwait(false);
            }
        }

        await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_connections.TryGetValue(key, out PooledDoqConnection? rechecked)
                && DateTimeOffset.UtcNow - rechecked.LastUsedUtc <= _options.ConnectionIdleTimeout)
            {
                return rechecked;
            }

            string? expectedPin = string.IsNullOrEmpty(key.SpkiPinSha256) ? null : key.SpkiPinSha256;
            X509ChainPolicy? chainPolicy = TlsCertificateValidator.BuildCustomChainPolicy(_options.CustomTrustAnchors);

            QuicClientConnectionOptions quicOptions = new()
            {
                RemoteEndPoint = new IPEndPoint(key.Address, key.Port),
                DefaultStreamErrorCode = 0,
                DefaultCloseErrorCode = 0,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = key.TargetHost,
                    EnabledSslProtocols = _options.EnabledSslProtocols,
                    ApplicationProtocols = [new SslApplicationProtocol("doq")],
                    CertificateChainPolicy = chainPolicy,
                    RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                        TlsCertificateValidator.ValidateServerCertificate(certificate, sslPolicyErrors, expectedPin)
                }
            };

            QuicConnection connection = await QuicConnection.ConnectAsync(quicOptions, cancellationToken).ConfigureAwait(false);
            PooledDoqConnection created = new(connection);
            _connections[key] = created;
            return created;
        }
        finally
        {
            _connectLock.Release();
        }
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private static async Task<DnsMessage> ExecuteQueryOnConnectionAsync(
        QuicConnection connection,
        DnsMessage query,
        CancellationToken cancellationToken)
    {
        // RFC 9250 Section 4.2.1 mandates DNS Message ID = 0 on the wire for DoQ.
        DnsMessage wireQuery = query.Header.Id == 0
            ? query
            : query with { Header = query.Header with { Id = 0 } };

        await using QuicStream stream = await connection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken)
            .ConfigureAwait(false);

        using PooledDnsPacket packet = DnsWireCodec.SerializePooled(wireQuery);
        if (packet.Length > ushort.MaxValue)
        {
            throw new InvalidDataException("DNS query exceeds maximum DoQ frame length.");
        }

        byte[] framed = new byte[2 + packet.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)packet.Length);
        packet.Span.CopyTo(framed.AsSpan(2));

        await stream.WriteAsync(framed.AsMemory(), completeWrites: true, cancellationToken).ConfigureAwait(false);

        byte[] lenBuffer = new byte[2];
        await stream.ReadExactlyAsync(lenBuffer.AsMemory(), cancellationToken).ConfigureAwait(false);
        int responseLength = BinaryPrimitives.ReadUInt16BigEndian(lenBuffer);
        if (responseLength < DnsHeader.WireSize)
        {
            throw new InvalidDataException($"Invalid DoQ DNS response frame length: {responseLength}.");
        }

        byte[] responseBuffer = new byte[responseLength];
        await stream.ReadExactlyAsync(responseBuffer.AsMemory(), cancellationToken).ConfigureAwait(false);

        DnsMessage parsed = DnsWireCodec.Parse(responseBuffer);
        if (query.Header.Id != 0 && parsed.Header.Id == 0)
        {
            parsed = parsed with { Header = parsed.Header with { Id = query.Header.Id } };
        }

        return parsed;
    }

    private readonly record struct DoqConnectionKey(
        IPAddress Address,
        int Port,
        string TargetHost,
        string SpkiPinSha256);

    private sealed class PooledDoqConnection(IAsyncDisposable connection) : IAsyncDisposable
    {
        public IAsyncDisposable Connection { get; } = connection;

        public DateTimeOffset LastUsedUtc { get; set; } = DateTimeOffset.UtcNow;

        public ValueTask DisposeAsync()
        {
            return Connection.DisposeAsync();
        }
    }
}
