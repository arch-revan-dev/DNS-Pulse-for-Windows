using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// RFC 1035 / RFC 7766 UDP and TCP DNS upstream client with automatic <c>TC=1</c> UDP-to-TCP fallback
/// and strict per-operation socket timeouts.
/// </summary>
public sealed class UdpTcpDnsClient : IDnsUpstreamClient
{
    private const int DefaultDnsPort = 53;
    private const int MaxUdpReceiveBufferSize = 4096;

    private readonly IBootstrapResolver? _bootstrapResolver;
    private readonly TransportOptions _options;

    /// <summary>
    /// Initializes a new <see cref="UdpTcpDnsClient"/>.
    /// </summary>
    public UdpTcpDnsClient(
        DnsProtocol protocol = DnsProtocol.Udp,
        IBootstrapResolver? bootstrapResolver = null,
        TransportOptions? options = null)
    {
        if (protocol is not DnsProtocol.Udp and not DnsProtocol.Tcp)
        {
            throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "UdpTcpDnsClient supports only Udp or Tcp.");
        }

        Protocol = protocol;
        _bootstrapResolver = bootstrapResolver;
        _options = options ?? new TransportOptions();
    }

    /// <inheritdoc />
    public DnsProtocol Protocol { get; }

    /// <inheritdoc />
    public async Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        IReadOnlyList<IPAddress> targets = await EndpointResolutionHelper
            .ResolveTargetAddressesAsync(upstream, upstream.DotHost, _bootstrapResolver, cancellationToken)
            .ConfigureAwait(false);

        if (targets.Count == 0)
        {
            throw new InvalidOperationException($"No IP address could be resolved for upstream '{upstream.Name}'.");
        }

        int port = upstream.Port ?? DefaultDnsPort;
        if (EndpointResolutionHelper.TryGetParsedStamp(upstream, out DnsPulse.Core.Stamps.DnsStamp? stamp)
            && stamp is not null
            && EndpointResolutionHelper.TryParseEndpointIp(stamp.ServerAddress, out _, out int? stampPort)
            && stampPort.HasValue
            && !upstream.Port.HasValue)
        {
            port = stampPort.Value;
        }

        bool preferTcp = upstream.Protocol == DnsProtocol.Tcp || (upstream.Protocol != DnsProtocol.Udp && Protocol == DnsProtocol.Tcp);
        Exception? lastException = null;

        foreach (IPAddress targetIp in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await QueryEndpointAsync(query, targetIp, port, preferTcp, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
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
            catch (FormatException ex)
            {
                lastException = ex;
            }
            catch (InvalidDataException ex)
            {
                lastException = ex;
            }
        }

        if (lastException is TimeoutException timeoutEx)
        {
            ExceptionDispatchInfo.Throw(timeoutEx);
        }

        throw new IOException(
            $"All {targets.Count} endpoint(s) failed for upstream '{upstream.Name}'.",
            lastException);
    }

    private async Task<UpstreamQueryResult> QueryEndpointAsync(
        DnsMessage query,
        IPAddress targetIp,
        int port,
        bool preferTcp,
        CancellationToken cancellationToken)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string endpointLabel = EndpointResolutionHelper.FormatEndpoint(targetIp, port);

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);
        CancellationToken effectiveToken = timeoutCts.Token;

        try
        {
            if (preferTcp)
            {
                DnsMessage tcpResponse = await QueryTcpCoreAsync(query, targetIp, port, effectiveToken).ConfigureAwait(false);
                stopwatch.Stop();
                return new UpstreamQueryResult(tcpResponse, stopwatch.Elapsed, endpointLabel, DnsProtocol.Tcp);
            }

            DnsMessage udpResponse = await QueryUdpCoreAsync(query, targetIp, port, effectiveToken).ConfigureAwait(false);
            if (udpResponse.IsTruncated)
            {
                DnsMessage tcpFallback = await QueryTcpCoreAsync(query, targetIp, port, effectiveToken).ConfigureAwait(false);
                stopwatch.Stop();
                return new UpstreamQueryResult(tcpFallback, stopwatch.Elapsed, endpointLabel, DnsProtocol.Tcp);
            }

            stopwatch.Stop();
            return new UpstreamQueryResult(udpResponse, stopwatch.Elapsed, endpointLabel, DnsProtocol.Udp);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"DNS query to {endpointLabel} timed out after {_options.Timeout.TotalMilliseconds:F0} ms.", ex);
        }
    }

    private static async Task<DnsMessage> QueryUdpCoreAsync(
        DnsMessage query,
        IPAddress targetIp,
        int port,
        CancellationToken cancellationToken)
    {
        using Socket socket = new(targetIp.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        IPEndPoint remoteEndPoint = new(targetIp, port);
        await socket.ConnectAsync(remoteEndPoint, cancellationToken).ConfigureAwait(false);

        using PooledDnsPacket packet = DnsWireCodec.SerializePooled(query);
        await socket.SendAsync(packet.Memory, SocketFlags.None, cancellationToken).ConfigureAwait(false);

        byte[] receiveBuffer = new byte[MaxUdpReceiveBufferSize];
        while (true)
        {
            int bytesRead = await socket.ReceiveAsync(receiveBuffer.AsMemory(), SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (bytesRead < DnsHeader.WireSize)
            {
                continue;
            }

            if (!DnsWireCodec.TryParse(receiveBuffer.AsSpan(0, bytesRead), out DnsMessage? response))
            {
                continue;
            }

            if (response.Header.Id != query.Header.Id || !response.Header.IsResponse)
            {
                continue;
            }

            return response;
        }
    }

    private static async Task<DnsMessage> QueryTcpCoreAsync(
        DnsMessage query,
        IPAddress targetIp,
        int port,
        CancellationToken cancellationToken)
    {
        using Socket socket = new(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.NoDelay = true;
        await socket.ConnectAsync(new IPEndPoint(targetIp, port), cancellationToken).ConfigureAwait(false);

        await using NetworkStream stream = new(socket, ownsSocket: false);
        using PooledDnsPacket packet = DnsWireCodec.SerializePooled(query);
        if (packet.Length > ushort.MaxValue)
        {
            throw new InvalidDataException("DNS query exceeds maximum TCP framing length.");
        }

        byte[] framed = new byte[2 + packet.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)packet.Length);
        packet.Span.CopyTo(framed.AsSpan(2));

        await stream.WriteAsync(framed.AsMemory(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] lenBuffer = new byte[2];
        await stream.ReadExactlyAsync(lenBuffer.AsMemory(), cancellationToken).ConfigureAwait(false);
        int responseLength = BinaryPrimitives.ReadUInt16BigEndian(lenBuffer);
        if (responseLength < DnsHeader.WireSize)
        {
            throw new InvalidDataException($"Invalid TCP DNS response frame length: {responseLength}.");
        }

        byte[] responseBuffer = new byte[responseLength];
        await stream.ReadExactlyAsync(responseBuffer.AsMemory(), cancellationToken).ConfigureAwait(false);

        DnsMessage response = DnsWireCodec.Parse(responseBuffer);
        if (response.Header.Id != query.Header.Id)
        {
            throw new InvalidDataException(
                $"DNS response ID mismatch (expected {query.Header.Id}, received {response.Header.Id}).");
        }

        return response;
    }
}
