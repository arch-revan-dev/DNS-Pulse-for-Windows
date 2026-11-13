using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Hosting;

/// <summary>
/// Lightweight unprivileged socket-based HTTP/1.1 RFC 8484 DoH server on loopback,
/// supporting <c>POST /dns-query</c> (<c>application/dns-message</c>) and <c>GET /dns-query?dns=&lt;base64url&gt;</c>.
/// </summary>
public sealed class LocalDohHttpListener : IAsyncDisposable, IDisposable
{
    private const int MaxHeaderBytes = 16 * 1024;
    private const string DohMediaType = "application/dns-message";

    private readonly IPulseDnsResolver _resolver;
    private readonly LocalDohServerOptions _options;
    private readonly string _normalizedPath;
    private readonly SemaphoreSlim _concurrencyGate;
    private readonly CancellationTokenSource _disposeCts = new();

    private TcpListener? _tcpListener;
    private Task? _acceptLoopTask;
    private int _started;
    private int _disposed;

    public LocalDohHttpListener(IPulseDnsResolver resolver, LocalDohServerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        _options = options ?? new LocalDohServerOptions();

        ArgumentNullException.ThrowIfNull(_options.ListenAddress);
        ArgumentOutOfRangeException.ThrowIfNegative(_options.Port, nameof(options));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(_options.Port, 65535, nameof(options));
        ArgumentException.ThrowIfNullOrWhiteSpace(_options.Path, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.MaxRequestBodyBytes, 12, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(_options.MaxConcurrentConnections, 1, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(_options.ReadTimeout, TimeSpan.Zero, nameof(options));

        _resolver = resolver;
        _normalizedPath = _options.Path.StartsWith('/') ? _options.Path : "/" + _options.Path;
        _concurrencyGate = new SemaphoreSlim(_options.MaxConcurrentConnections, _options.MaxConcurrentConnections);
    }

    public IPEndPoint? BoundEndPoint { get; private set; }

    public int BoundPort => BoundEndPoint?.Port ?? 0;

    public Uri? ListenUri { get; private set; }

    /// <summary>
    /// Binds the loopback TCP listener and starts accepting HTTP/1.1 DoH requests.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("LocalDohHttpListener has already been started.");
        }

        TcpListener listener = new(_options.ListenAddress, _options.Port);
        listener.Start();
        _tcpListener = listener;

        IPEndPoint bound = (IPEndPoint)listener.LocalEndpoint;
        BoundEndPoint = bound;

        string host = bound.Address.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Create(CultureInfo.InvariantCulture, $"[{bound.Address}]")
            : bound.Address.ToString();

        ListenUri = new Uri(string.Create(CultureInfo.InvariantCulture, $"http://{host}:{bound.Port}{_normalizedPath}"));
        _acceptLoopTask = Task.Run(() => RunAcceptLoopAsync(listener, _disposeCts.Token));
    }

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
        StopListener();
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
        StopListener();

        if (_acceptLoopTask is not null)
        {
            await AwaitQuietlyAsync(_acceptLoopTask).ConfigureAwait(false);
        }

        _concurrencyGate.Dispose();
        _disposeCts.Dispose();
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "HTTP accept loop must isolate transient accept errors until shutdown.")]
    private async Task RunAcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            bool acquired = false;
            try
            {
                await _concurrencyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;

                TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                acquired = false; // Ownership of slot transferred to HandleConnectionAsync.
                _ = HandleConnectionAsync(client, cancellationToken);
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

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Per-connection HTTP handler must isolate client disconnects and malformed HTTP payloads.")]
    private async Task HandleConnectionAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            using (client)
            {
                client.NoDelay = true;
                using NetworkStream stream = client.GetStream();
                BufferedHttpStream reader = new(stream, MaxHeaderBytes);

                while (!cancellationToken.IsCancellationRequested)
                {
                    using CancellationTokenSource readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    readCts.CancelAfter(_options.ReadTimeout);

                    HttpRequestHead? head = await reader.ReadHeadersAsync(readCts.Token).ConfigureAwait(false);
                    if (head is null)
                    {
                        break;
                    }

                    if (!head.IsValid)
                    {
                        await WriteErrorResponseAsync(stream, 400, "Bad Request", closeConnection: true, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    bool keepAlive = ShouldKeepAlive(head);
                    if (!string.Equals(head.Path, _normalizedPath, StringComparison.Ordinal))
                    {
                        await DrainBodyIfPresentAsync(reader, head, readCts.Token).ConfigureAwait(false);
                        await WriteErrorResponseAsync(stream, 404, "Not Found", !keepAlive, cancellationToken).ConfigureAwait(false);
                        if (!keepAlive)
                        {
                            break;
                        }

                        continue;
                    }

                    byte[]? dnsPayload = null;
                    int errorStatus = 0;
                    string errorReason = string.Empty;

                    if (string.Equals(head.Method, "POST", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!IsDohContentType(head.ContentType))
                        {
                            await DrainBodyIfPresentAsync(reader, head, readCts.Token).ConfigureAwait(false);
                            errorStatus = 415;
                            errorReason = "Unsupported Media Type";
                        }
                        else if (!head.ContentLength.HasValue)
                        {
                            errorStatus = 411;
                            errorReason = "Length Required";
                            keepAlive = false;
                        }
                        else if (head.ContentLength.Value <= 0 || head.ContentLength.Value > _options.MaxRequestBodyBytes)
                        {
                            errorStatus = head.ContentLength.Value > _options.MaxRequestBodyBytes ? 413 : 400;
                            errorReason = head.ContentLength.Value > _options.MaxRequestBodyBytes ? "Payload Too Large" : "Bad Request";
                            keepAlive = false;
                        }
                        else
                        {
                            dnsPayload = await reader.ReadBodyAsync(head.ContentLength.Value, readCts.Token).ConfigureAwait(false);
                            if (dnsPayload is null)
                            {
                                break;
                            }
                        }
                    }
                    else if (string.Equals(head.Method, "GET", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!TryExtractDnsQueryParam(head.QueryString, out string? encodedDns) ||
                            !TryDecodeBase64Url(encodedDns, out dnsPayload) ||
                            dnsPayload.Length > _options.MaxRequestBodyBytes)
                        {
                            errorStatus = 400;
                            errorReason = "Bad Request";
                        }
                    }
                    else
                    {
                        await DrainBodyIfPresentAsync(reader, head, readCts.Token).ConfigureAwait(false);
                        errorStatus = 405;
                        errorReason = "Method Not Allowed";
                    }

                    if (errorStatus != 0)
                    {
                        await WriteErrorResponseAsync(stream, errorStatus, errorReason, !keepAlive, cancellationToken).ConfigureAwait(false);
                        if (!keepAlive)
                        {
                            break;
                        }

                        continue;
                    }

                    if (dnsPayload is null || !DnsWireCodec.TryParse(dnsPayload, out DnsMessage? dnsQuery))
                    {
                        await WriteErrorResponseAsync(stream, 400, "Bad Request", !keepAlive, cancellationToken).ConfigureAwait(false);
                        if (!keepAlive)
                        {
                            break;
                        }

                        continue;
                    }

                    DnsMessage dnsResponse = await _resolver.ResolveAsync(dnsQuery, cancellationToken).ConfigureAwait(false);
                    using PooledDnsPacket serialized = DnsWireCodec.SerializePooled(dnsResponse);
                    uint maxAge = ComputeCacheControlMaxAge(dnsResponse);

                    await WriteDohOkResponseAsync(stream, serialized.Memory, maxAge, !keepAlive, cancellationToken).ConfigureAwait(false);
                    if (!keepAlive)
                    {
                        break;
                    }
                }
            }
        }
        catch (Exception)
        {
            // Isolated per-connection termination.
        }
        finally
        {
            TryReleaseConcurrencySlot();
        }
    }

    private static async Task DrainBodyIfPresentAsync(
        BufferedHttpStream reader,
        HttpRequestHead head,
        CancellationToken cancellationToken)
    {
        if (head.ContentLength is > 0 and <= 65535)
        {
            _ = await reader.ReadBodyAsync(head.ContentLength.Value, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool ShouldKeepAlive(HttpRequestHead head)
    {
        if (string.Equals(head.Connection, "close", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.Equals(head.HttpVersion, "HTTP/1.0", StringComparison.OrdinalIgnoreCase))
        {
            return string.Equals(head.Connection, "keep-alive", StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    private static bool IsDohContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return false;
        }

        int semiIndex = contentType.IndexOf(';', StringComparison.Ordinal);
        ReadOnlySpan<char> mediaType = semiIndex >= 0
            ? contentType.AsSpan(0, semiIndex).Trim()
            : contentType.AsSpan().Trim();

        return mediaType.Equals(DohMediaType, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryExtractDnsQueryParam(string? queryString, out string encodedDns)
    {
        encodedDns = string.Empty;
        if (string.IsNullOrEmpty(queryString))
        {
            return false;
        }

        string trimmed = queryString.StartsWith('?') ? queryString[1..] : queryString;
        string[] pairs = trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (string pair in pairs)
        {
            int eqIndex = pair.IndexOf('=', StringComparison.Ordinal);
            if (eqIndex <= 0)
            {
                continue;
            }

            string key = pair[..eqIndex];
            if (!string.Equals(key, "dns", StringComparison.Ordinal))
            {
                continue;
            }

            encodedDns = Uri.UnescapeDataString(pair[(eqIndex + 1)..]);
            return encodedDns.Length > 0;
        }

        return false;
    }

    private static bool TryDecodeBase64Url(string input, out byte[] decoded)
    {
        decoded = [];
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        int mod4 = input.Length % 4;
        if (mod4 == 1)
        {
            return false;
        }

        int paddedLength = mod4 == 0 ? input.Length : input.Length + (4 - mod4);
        char[] chars = new char[paddedLength];
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            chars[i] = c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c
            };
        }

        for (int i = input.Length; i < paddedLength; i++)
        {
            chars[i] = '=';
        }

        try
        {
            decoded = Convert.FromBase64CharArray(chars, 0, chars.Length);
            return decoded.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static uint ComputeCacheControlMaxAge(DnsMessage response)
    {
        if (response.EffectiveResponseCode != DnsResponseCode.NoError || response.Answers.Count == 0)
        {
            return 0;
        }

        uint minTtl = uint.MaxValue;
        foreach (DnsResourceRecord record in response.Answers)
        {
            if (record.RecordType == DnsRecordType.OPT)
            {
                continue;
            }

            if (record.TimeToLive < minTtl)
            {
                minTtl = record.TimeToLive;
            }
        }

        return minTtl == uint.MaxValue ? 0 : minTtl;
    }

    private static async Task WriteDohOkResponseAsync(
        NetworkStream stream,
        ReadOnlyMemory<byte> dnsWirePayload,
        uint maxAgeSeconds,
        bool closeConnection,
        CancellationToken cancellationToken)
    {
        string connectionHeader = closeConnection ? "close" : "keep-alive";
        string headerText = string.Create(
            CultureInfo.InvariantCulture,
            $"HTTP/1.1 200 OK\r\nContent-Type: {DohMediaType}\r\nContent-Length: {dnsWirePayload.Length}\r\nCache-Control: max-age={maxAgeSeconds}\r\nConnection: {connectionHeader}\r\n\r\n");

        byte[] headerBytes = Encoding.ASCII.GetBytes(headerText);
        byte[] packet = new byte[headerBytes.Length + dnsWirePayload.Length];
        headerBytes.CopyTo(packet, 0);
        dnsWirePayload.CopyTo(packet.AsMemory(headerBytes.Length));

        await stream.WriteAsync(packet.AsMemory(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteErrorResponseAsync(
        NetworkStream stream,
        int statusCode,
        string reasonPhrase,
        bool closeConnection,
        CancellationToken cancellationToken)
    {
        string connectionHeader = closeConnection ? "close" : "keep-alive";
        string headerText = string.Create(
            CultureInfo.InvariantCulture,
            $"HTTP/1.1 {statusCode} {reasonPhrase}\r\nContent-Length: 0\r\nConnection: {connectionHeader}\r\n\r\n");

        byte[] headerBytes = Encoding.ASCII.GetBytes(headerText);
        await stream.WriteAsync(headerBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
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
        }
    }

    private void StopListener()
    {
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
        }
    }

    private sealed class BufferedHttpStream(NetworkStream stream, int maxHeaderBytes)
    {
        private readonly byte[] _buffer = new byte[maxHeaderBytes];
        private int _readOffset;
        private int _writeOffset;

        public async Task<HttpRequestHead?> ReadHeadersAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                int headerEnd = FindHeaderTerminator(_buffer.AsSpan(_readOffset, _writeOffset - _readOffset));
                if (headerEnd >= 0)
                {
                    string rawHeaders = Encoding.ASCII.GetString(_buffer, _readOffset, headerEnd);
                    _readOffset += headerEnd + 4;
                    CompactIfEmpty();
                    return ParseHeaders(rawHeaders);
                }

                if (_writeOffset == _buffer.Length)
                {
                    if (_readOffset > 0)
                    {
                        Compact();
                    }
                    else
                    {
                        return HttpRequestHead.Invalid;
                    }
                }

                int bytesRead = await stream.ReadAsync(
                    _buffer.AsMemory(_writeOffset, _buffer.Length - _writeOffset),
                    cancellationToken).ConfigureAwait(false);

                if (bytesRead == 0)
                {
                    return _writeOffset == _readOffset ? null : HttpRequestHead.Invalid;
                }

                _writeOffset += bytesRead;
            }
        }

        public async Task<byte[]?> ReadBodyAsync(int length, CancellationToken cancellationToken)
        {
            byte[] body = new byte[length];
            int copied = 0;

            int bufferedAvailable = _writeOffset - _readOffset;
            if (bufferedAvailable > 0)
            {
                int toCopy = Math.Min(bufferedAvailable, length);
                Buffer.BlockCopy(_buffer, _readOffset, body, 0, toCopy);
                _readOffset += toCopy;
                copied += toCopy;
                CompactIfEmpty();
            }

            while (copied < length)
            {
                int read = await stream.ReadAsync(body.AsMemory(copied, length - copied), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return null;
                }

                copied += read;
            }

            return body;
        }

        private void CompactIfEmpty()
        {
            if (_readOffset >= _writeOffset)
            {
                _readOffset = 0;
                _writeOffset = 0;
            }
        }

        private void Compact()
        {
            int remaining = _writeOffset - _readOffset;
            if (remaining > 0)
            {
                Buffer.BlockCopy(_buffer, _readOffset, _buffer, 0, remaining);
            }

            _readOffset = 0;
            _writeOffset = remaining;
        }

        private static int FindHeaderTerminator(ReadOnlySpan<byte> span)
        {
            ReadOnlySpan<byte> delimiter = "\r\n\r\n"u8;
            return span.IndexOf(delimiter);
        }

        private static HttpRequestHead ParseHeaders(string rawHeaders)
        {
            string[] lines = rawHeaders.Split("\r\n", StringSplitOptions.None);
            if (lines.Length == 0)
            {
                return HttpRequestHead.Invalid;
            }

            string[] requestLineParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (requestLineParts.Length != 3 || !requestLineParts[2].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            {
                return HttpRequestHead.Invalid;
            }

            string method = requestLineParts[0];
            string target = requestLineParts[1];
            string httpVersion = requestLineParts[2];

            string path = target;
            string? queryString = null;

            if (Uri.TryCreate(target, UriKind.Absolute, out Uri? absoluteUri))
            {
                path = absoluteUri.AbsolutePath;
                queryString = absoluteUri.Query;
            }
            else
            {
                int queryIndex = target.IndexOf('?', StringComparison.Ordinal);
                if (queryIndex >= 0)
                {
                    path = target[..queryIndex];
                    queryString = target[queryIndex..];
                }
            }

            string? contentType = null;
            int? contentLength = null;
            string? connection = null;

            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                int colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon <= 0)
                {
                    continue;
                }

                string name = line[..colon].Trim();
                string value = line[(colon + 1)..].Trim();

                if (string.Equals(name, "Content-Type", StringComparison.OrdinalIgnoreCase))
                {
                    contentType = value;
                }
                else if (string.Equals(name, "Content-Length", StringComparison.OrdinalIgnoreCase) &&
                         int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int parsedLength))
                {
                    contentLength = parsedLength;
                }
                else if (string.Equals(name, "Connection", StringComparison.OrdinalIgnoreCase))
                {
                    connection = value;
                }
            }

            return new HttpRequestHead(true, method, path, queryString, httpVersion, contentType, contentLength, connection);
        }
    }

    private sealed record HttpRequestHead(
        bool IsValid,
        string Method,
        string Path,
        string? QueryString,
        string HttpVersion,
        string? ContentType,
        int? ContentLength,
        string? Connection)
    {
        public static readonly HttpRequestHead Invalid = new(
            false,
            string.Empty,
            string.Empty,
            null,
            string.Empty,
            null,
            null,
            null);
    }
}
