using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// RFC 8484 DNS-over-HTTPS (DoH / DoH3) client supporting HTTP/2 and HTTP/3, <c>POST</c> and <c>GET</c>
/// (<c>application/dns-message</c>), bootstrap IP <c>ConnectCallback</c>, optional <see cref="TlsFragmentingStream"/>,
/// and optional <c>SpkiPinSha256</c> certificate pinning.
/// </summary>
public sealed class DohDnsClient : IDnsUpstreamClient, IDisposable
{
    private const string DnsMessageMediaType = "application/dns-message";

    private readonly IBootstrapResolver? _bootstrapResolver;
    private readonly TransportOptions _options;
    private readonly ConcurrentDictionary<DohInvokerKey, HttpMessageInvoker> _invokers = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="DohDnsClient"/>.
    /// </summary>
    public DohDnsClient(
        DnsProtocol protocol = DnsProtocol.DoH,
        IBootstrapResolver? bootstrapResolver = null,
        TransportOptions? options = null)
    {
        if (protocol is not DnsProtocol.DoH and not DnsProtocol.DoH3)
        {
            throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "DohDnsClient supports only DoH or DoH3.");
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
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        Uri requestUri = ResolveDohUri(upstream);
        IReadOnlyList<IPAddress> bootstrapIps = await ResolveBootstrapIpsAsync(upstream, requestUri, cancellationToken)
            .ConfigureAwait(false);

        bool useFragmentation = _options.EnableTlsFragmentation || EndpointResolutionHelper.HasTlsFragmentationTag(upstream);
        bool useHttp3 = upstream.Protocol == DnsProtocol.DoH3 || (upstream.Protocol != DnsProtocol.DoH && Protocol == DnsProtocol.DoH3);
        string bootstrapKey = string.Join(',', bootstrapIps.Select(static ip => ip.ToString()));
        DohInvokerKey key = new(
            requestUri.Host,
            requestUri.Port,
            bootstrapKey,
            upstream.SpkiPinSha256 ?? string.Empty,
            useFragmentation,
            useHttp3);

        HttpMessageInvoker invoker = _invokers.GetOrAdd(
            key,
            _ => CreateInvoker(bootstrapIps, upstream.SpkiPinSha256, useFragmentation, useHttp3));

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);
        CancellationToken effectiveToken = timeoutCts.Token;

        byte[] queryWire = DnsWireCodec.Serialize(query);
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            using HttpRequestMessage request = BuildRequest(requestUri, queryWire, useHttp3);
            using HttpResponseMessage response = await invoker.SendAsync(request, effectiveToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            byte[] responseWire = await response.Content.ReadAsByteArrayAsync(effectiveToken).ConfigureAwait(false);
            DnsMessage parsed = DnsWireCodec.Parse(responseWire);
            if (parsed.Header.Id != query.Header.Id && parsed.Header.Id == 0)
            {
                parsed = parsed with { Header = parsed.Header with { Id = query.Header.Id } };
            }

            stopwatch.Stop();
            DnsProtocol protocolUsed = response.Version.Major >= 3 ? DnsProtocol.DoH3 : DnsProtocol.DoH;
            string endpointUsed = bootstrapIps.Count > 0
                ? string.Create(CultureInfo.InvariantCulture, $"{requestUri} ({bootstrapIps[0]})")
                : requestUri.ToString();

            return new UpstreamQueryResult(parsed, stopwatch.Elapsed, endpointUsed, protocolUsed);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"DoH query to {requestUri} timed out after {_options.Timeout.TotalMilliseconds:F0} ms.", ex);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (KeyValuePair<DohInvokerKey, HttpMessageInvoker> pair in _invokers)
        {
            pair.Value.Dispose();
        }

        _invokers.Clear();
    }

    internal static Uri ResolveDohUri(DnsServerEntry upstream)
    {
        if (!string.IsNullOrWhiteSpace(upstream.DohUrl))
        {
            return new Uri(upstream.DohUrl.Trim(), UriKind.Absolute);
        }

        if (EndpointResolutionHelper.TryGetParsedStamp(upstream, out DnsStamp? stamp)
            && stamp is not null
            && !string.IsNullOrWhiteSpace(stamp.HostName))
        {
            string host = stamp.HostName.Trim();
            string path = string.IsNullOrWhiteSpace(stamp.Path) ? "/dns-query" : stamp.Path;
            if (!path.StartsWith('/'))
            {
                path = string.Concat("/", path);
            }

            return new Uri(string.Concat("https://", host, path), UriKind.Absolute);
        }

        if (!string.IsNullOrWhiteSpace(upstream.DotHost))
        {
            string portSuffix = upstream.Port is > 0 and not 443
                ? string.Create(CultureInfo.InvariantCulture, $":{upstream.Port.Value}")
                : string.Empty;
            return new Uri(string.Concat("https://", upstream.DotHost.Trim(), portSuffix, "/dns-query"), UriKind.Absolute);
        }

        if (!string.IsNullOrWhiteSpace(upstream.PrimaryIp))
        {
            string formattedHost = upstream.PrimaryIp.Contains(':', StringComparison.Ordinal) && !upstream.PrimaryIp.StartsWith('[')
                ? string.Concat("[", upstream.PrimaryIp.Trim(), "]")
                : upstream.PrimaryIp.Trim();
            string portSuffix = upstream.Port is > 0 and not 443
                ? string.Create(CultureInfo.InvariantCulture, $":{upstream.Port.Value}")
                : string.Empty;
            return new Uri(string.Concat("https://", formattedHost, portSuffix, "/dns-query"), UriKind.Absolute);
        }

        throw new InvalidOperationException($"DoH upstream '{upstream.Name}' does not specify a DohUrl, HostName, or IP.");
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveBootstrapIpsAsync(
        DnsServerEntry upstream,
        Uri requestUri,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(requestUri.DnsSafeHost, out IPAddress? uriIp))
        {
            return [uriIp];
        }

        return await EndpointResolutionHelper
            .ResolveTargetAddressesAsync(upstream, requestUri.DnsSafeHost, _bootstrapResolver, cancellationToken)
            .ConfigureAwait(false);
    }

    private HttpRequestMessage BuildRequest(Uri requestUri, byte[] queryWire, bool useHttp3)
    {
        HttpRequestMessage request;
        if (_options.DohMethod == DohHttpMethod.Get)
        {
            string encoded = Convert.ToBase64String(queryWire)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            string separator = string.IsNullOrEmpty(requestUri.Query) ? "?" : "&";
            Uri getUri = new(string.Concat(requestUri.AbsoluteUri, separator, "dns=", encoded), UriKind.Absolute);
            request = new HttpRequestMessage(HttpMethod.Get, getUri);
        }
        else
        {
            request = new HttpRequestMessage(HttpMethod.Post, requestUri)
            {
                Content = new ByteArrayContent(queryWire)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(DnsMessageMediaType);
        }

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(DnsMessageMediaType));
        request.Version = useHttp3 ? HttpVersion.Version30 : HttpVersion.Version20;
        request.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        return request;
    }

    private HttpMessageInvoker CreateInvoker(
        IReadOnlyList<IPAddress> bootstrapIps,
        string? spkiPinSha256,
        bool useTlsFragmentation,
        bool useHttp3)
    {
        string? expectedPin = string.IsNullOrWhiteSpace(spkiPinSha256) ? null : spkiPinSha256;
        X509ChainPolicy? chainPolicy = TlsCertificateValidator.BuildCustomChainPolicy(_options.CustomTrustAnchors);

        SocketsHttpHandler? handler = new()
        {
            PooledConnectionIdleTimeout = _options.ConnectionIdleTimeout,
            EnableMultipleHttp2Connections = true,
            EnableMultipleHttp3Connections = useHttp3,
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = _options.EnabledSslProtocols,
                CertificateChainPolicy = chainPolicy,
                RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                    TlsCertificateValidator.ValidateServerCertificate(certificate, sslPolicyErrors, expectedPin)
            }
        };

        try
        {
            if (bootstrapIps.Count > 0 || useTlsFragmentation)
            {
                int chunkSize = _options.TlsFragmentChunkSize;
                TimeSpan? delay = _options.TlsFragmentInterChunkDelay;

                handler.ConnectCallback = async (context, ct) =>
                {
                    IReadOnlyList<IPAddress> candidates = bootstrapIps.Count > 0
                        ? bootstrapIps
                        : await ResolveFallbackForConnectAsync(context.DnsEndPoint.Host, ct).ConfigureAwait(false);

                    if (candidates.Count == 0)
                    {
                        throw new SocketException((int)SocketError.HostNotFound);
                    }

                    Exception? connectFailure = null;
                    foreach (IPAddress ip in candidates)
                    {
                        Socket socket = new(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                        {
                            NoDelay = true
                        };

                        bool ownershipTransferred = false;
                        try
                        {
                            await socket.ConnectAsync(new IPEndPoint(ip, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
                            Stream stream = useTlsFragmentation
                                ? new TlsFragmentingStream(socket, chunkSize, ownsSocket: true, delay)
                                : new NetworkStream(socket, ownsSocket: true);
                            ownershipTransferred = true;
                            return stream;
                        }
                        catch (SocketException ex)
                        {
                            connectFailure = ex;
                        }
                        catch (IOException ex)
                        {
                            connectFailure = ex;
                        }
                        finally
                        {
                            if (!ownershipTransferred)
                            {
                                socket.Dispose();
                            }
                        }
                    }

                    throw connectFailure ?? new SocketException((int)SocketError.HostNotFound);
                };
            }

            HttpMessageInvoker invoker = new(handler, disposeHandler: true);
            handler = null;
            return invoker;
        }
        finally
        {
            handler?.Dispose();
        }
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveFallbackForConnectAsync(string host, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            return [literal];
        }

        if (_bootstrapResolver is not null)
        {
            IReadOnlyList<IPAddress> resolved = await _bootstrapResolver.ResolveHostAsync(host, cancellationToken).ConfigureAwait(false);
            if (resolved.Count > 0)
            {
                return resolved;
            }
        }

        return await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
    }

    private readonly record struct DohInvokerKey(
        string Host,
        int Port,
        string BootstrapIpsKey,
        string SpkiPinSha256,
        bool UseTlsFragmentation,
        bool UseHttp3);
}
