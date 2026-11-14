using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DnsPulse.Engine.Sidecar;

/// <summary>
/// Configuration options for <see cref="AutoPacServer"/>.
/// </summary>
public sealed record AutoPacServerOptions
{
    /// <summary>
    /// Local IP address to bind the PAC HTTP listener on.
    /// </summary>
    public IPAddress BindAddress { get; init; } = TlsFragmentationProxyOptions.DefaultBindAddress;

    /// <summary>
    /// TCP port to bind the PAC HTTP listener on (0 selects an ephemeral OS-assigned port).
    /// </summary>
    public int Port { get; init; }

    /// <summary>
    /// Proxy host emitted inside <c>FindProxyForURL</c> return directives.
    /// </summary>
    public string ProxyHost { get; init; } = "127.0.53.1";

    /// <summary>
    /// Proxy port emitted inside <c>FindProxyForURL</c> return directives.
    /// </summary>
    public int ProxyPort { get; init; } = 10808;
}

/// <summary>
/// Lightweight socket-based HTTP/1.1 server serving dynamic Proxy Auto-Config (<c>/proxy.pac</c>)
/// and health (<c>/health</c>) endpoints without requiring Windows HTTP.SYS URL ACL registration.
/// </summary>
public sealed class AutoPacServer : IAsyncDisposable, IDisposable
{
    private const int MaxHttpRequestBytes = 8 * 1024;
    private static readonly byte[] HeaderTerminator = "\r\n\r\n"u8.ToArray();

    private readonly AutoPacServerOptions _options;
    private readonly ConcurrentDictionary<long, Task> _activeConnections = new();
    private readonly Lock _lifecycleLock = new();
    private readonly Lock _snapshotUpdateLock = new();

    private PacSnapshot _snapshot;
    private Socket? _listenerSocket;
    private CancellationTokenSource? _serverCts;
    private Task? _acceptLoopTask;
    private long _nextConnectionId;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="AutoPacServer"/> with the specified options and optional initial split domains.
    /// </summary>
    public AutoPacServer(AutoPacServerOptions options, IEnumerable<string>? initialSplitDomains = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.BindAddress);
        ArgumentOutOfRangeException.ThrowIfNegative(options.Port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Port, 65535);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ProxyHost);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.ProxyPort, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.ProxyPort, 65535);

        _options = options;
        string[] normalized = NormalizeDomains(initialSplitDomains ?? []);
        _snapshot = BuildSnapshot(options.ProxyHost, options.ProxyPort, normalized);
    }

    /// <summary>
    /// Gets the bound local endpoint once started, or <c>null</c> when stopped.
    /// </summary>
    public IPEndPoint? BoundEndPoint { get; private set; }

    /// <summary>
    /// Gets the full HTTP URL for <c>/proxy.pac</c> while running, or <c>null</c> when stopped.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Exposes ready-to-embed PAC URL string for Windows/LAN configuration and QR generation.")]
    public string? PacUrl
    {
        get
        {
            IPEndPoint? ep = BoundEndPoint;
            if (ep is null)
            {
                return null;
            }

            string host = FormatHostForAuthority(ep.Address.ToString());
            return string.Create(CultureInfo.InvariantCulture, $"http://{host}:{ep.Port}/proxy.pac");
        }
    }

    /// <summary>
    /// Gets the current number of DPI-split domains routed through the sidecar proxy.
    /// </summary>
    public int SplitDomainCount => Volatile.Read(ref _snapshot).Domains.Length;

    /// <summary>
    /// Gets the currently active PAC JavaScript source.
    /// </summary>
    public string CurrentPacScript => Volatile.Read(ref _snapshot).ScriptText;

    /// <summary>
    /// Starts listening for HTTP/1.1 requests.
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

            Socket listener = TlsFragmentationProxyServer.CreateBoundTcpListener(_options.BindAddress, _options.Port, backlog: 128);
            _listenerSocket = listener;
            BoundEndPoint = (IPEndPoint?)listener.LocalEndPoint;
            _serverCts = new CancellationTokenSource();
            _acceptLoopTask = RunAcceptLoopAsync(listener, _serverCts.Token);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Stops the PAC HTTP server and closes active connections.
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

        Task[] pending = [.. _activeConnections.Values];
        if (pending.Length > 0)
        {
            try
            {
                await Task.WhenAll(pending).WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
        }

        cts?.Dispose();
    }

    /// <summary>
    /// Atomically replaces the set of DPI-blocked domains routed via the fragmentation proxy.
    /// </summary>
    public void UpdateSplitDomains(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        string[] normalized = NormalizeDomains(domains);

        lock (_snapshotUpdateLock)
        {
            PacSnapshot current = _snapshot;
            PacSnapshot next = BuildSnapshot(current.ProxyHost, current.ProxyPort, normalized);
            Volatile.Write(ref _snapshot, next);
        }
    }

    /// <summary>
    /// Atomically updates the proxy host and port emitted by <c>FindProxyForURL</c>.
    /// </summary>
    public void UpdateProxyEndpoint(string proxyHost, int proxyPort)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(proxyHost);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(proxyPort, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(proxyPort, 65535);

        lock (_snapshotUpdateLock)
        {
            PacSnapshot current = _snapshot;
            PacSnapshot next = BuildSnapshot(proxyHost.Trim(), proxyPort, current.Domains);
            Volatile.Write(ref _snapshot, next);
        }
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
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Accept loop isolates transient socket failures.")]
    private async Task RunAcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                Socket accepted = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                long id = Interlocked.Increment(ref _nextConnectionId);
                Task task = HandleClientAsync(id, accepted, cancellationToken);
                _activeConnections.TryAdd(id, task);
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
            }
            catch (Exception)
            {
            }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Per-request isolation prevents malformed clients from stopping the PAC server.")]
    private async Task HandleClientAsync(long connectionId, Socket clientSocket, CancellationToken cancellationToken)
    {
        try
        {
            using (clientSocket)
            {
                clientSocket.NoDelay = true;
                byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxHttpRequestBytes);
                try
                {
                    int totalRead = 0;
                    int headerEnd = -1;
                    while (headerEnd < 0)
                    {
                        if (totalRead >= MaxHttpRequestBytes)
                        {
                            await SendResponseAsync(
                                clientSocket,
                                "431 Request Header Fields Too Large",
                                "text/plain; charset=utf-8",
                                [],
                                includeBody: false,
                                cancellationToken).ConfigureAwait(false);
                            return;
                        }

                        int n = await clientSocket.ReceiveAsync(
                            buffer.AsMemory(totalRead, MaxHttpRequestBytes - totalRead),
                            SocketFlags.None,
                            cancellationToken).ConfigureAwait(false);
                        if (n <= 0)
                        {
                            return;
                        }

                        totalRead += n;
                        headerEnd = buffer.AsSpan(0, totalRead).IndexOf(HeaderTerminator);
                    }

                    string headerText = Encoding.ASCII.GetString(buffer, 0, headerEnd);
                    int firstLineEnd = headerText.IndexOf("\r\n", StringComparison.Ordinal);
                    string requestLine = firstLineEnd >= 0 ? headerText[..firstLineEnd] : headerText;
                    string[] parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                    {
                        await SendResponseAsync(
                            clientSocket,
                            "400 Bad Request",
                            "text/plain; charset=utf-8",
                            "Bad Request"u8.ToArray(),
                            includeBody: true,
                            cancellationToken).ConfigureAwait(false);
                        return;
                    }

                    string method = parts[0];
                    string rawPath = parts[1];
                    int queryIndex = rawPath.IndexOf('?', StringComparison.Ordinal);
                    string path = queryIndex >= 0 ? rawPath[..queryIndex] : rawPath;

                    bool isGet = method.Equals("GET", StringComparison.OrdinalIgnoreCase);
                    bool isHead = method.Equals("HEAD", StringComparison.OrdinalIgnoreCase);
                    if (!isGet && !isHead)
                    {
                        await SendResponseAsync(
                            clientSocket,
                            "405 Method Not Allowed",
                            "text/plain; charset=utf-8",
                            "Method Not Allowed"u8.ToArray(),
                            includeBody: true,
                            cancellationToken).ConfigureAwait(false);
                        return;
                    }

                    PacSnapshot snapshot = Volatile.Read(ref _snapshot);

                    if (path.Equals("/proxy.pac", StringComparison.OrdinalIgnoreCase))
                    {
                        await SendResponseAsync(
                            clientSocket,
                            "200 OK",
                            "application/x-ns-proxy-autoconfig; charset=utf-8",
                            snapshot.ScriptUtf8Bytes,
                            includeBody: isGet,
                            cancellationToken).ConfigureAwait(false);
                        return;
                    }

                    if (path.Equals("/health", StringComparison.OrdinalIgnoreCase))
                    {
                        byte[] healthBody = Encoding.UTF8.GetBytes(
                            string.Create(CultureInfo.InvariantCulture, $"{{\"status\":\"ok\",\"splitDomainCount\":{snapshot.Domains.Length}}}"));
                        await SendResponseAsync(
                            clientSocket,
                            "200 OK",
                            "application/json; charset=utf-8",
                            healthBody,
                            includeBody: isGet,
                            cancellationToken).ConfigureAwait(false);
                        return;
                    }

                    await SendResponseAsync(
                        clientSocket,
                        "404 Not Found",
                        "text/plain; charset=utf-8",
                        "Not Found"u8.ToArray(),
                        includeBody: isGet,
                        cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
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
        catch (Exception)
        {
        }
        finally
        {
            _activeConnections.TryRemove(connectionId, out _);
        }
    }

    private static async Task SendResponseAsync(
        Socket clientSocket,
        string statusLine,
        string contentType,
        byte[] body,
        bool includeBody,
        CancellationToken cancellationToken)
    {
        string headers = string.Create(
            CultureInfo.InvariantCulture,
            $"HTTP/1.1 {statusLine}\r\nContent-Type: {contentType}\r\nContent-Length: {body.Length}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nConnection: close\r\n\r\n");
        byte[] headerBytes = Encoding.ASCII.GetBytes(headers);

        await SendAllAsync(clientSocket, headerBytes, cancellationToken).ConfigureAwait(false);
        if (includeBody && body.Length > 0)
        {
            await SendAllAsync(clientSocket, body, cancellationToken).ConfigureAwait(false);
        }
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

    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "DNS domain names in PAC scripts are canonically lowercased.")]
    private static string[] NormalizeDomains(IEnumerable<string> domains)
    {
        HashSet<string> unique = new(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in domains)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            string candidate = raw.Trim();
            if (candidate.StartsWith("*.", StringComparison.Ordinal))
            {
                candidate = candidate[2..];
            }

            candidate = candidate.Trim('.').ToLowerInvariant();
            if (candidate.Length == 0 || !IsSafeHostLiteral(candidate))
            {
                continue;
            }

            unique.Add(candidate);
        }

        string[] sorted = [.. unique];
        Array.Sort(sorted, StringComparer.Ordinal);
        return sorted;
    }

    private static bool IsSafeHostLiteral(string domain)
    {
        for (int i = 0; i < domain.Length; i++)
        {
            char c = domain[i];
            bool valid = (c is >= 'a' and <= 'z') || (c is >= '0' and <= '9') || c is '-' or '.' or '_';
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    private static string FormatHostForAuthority(string host)
    {
        if (IPAddress.TryParse(host, out IPAddress? parsed) && parsed.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return string.Concat("[", parsed.ToString(), "]");
        }

        return host;
    }

    private static PacSnapshot BuildSnapshot(string proxyHost, int proxyPort, string[] domains)
    {
        string authorityHost = FormatHostForAuthority(proxyHost);
        string proxyDirective = string.Create(
            CultureInfo.InvariantCulture,
            $"PROXY {authorityHost}:{proxyPort}; SOCKS5 {authorityHost}:{proxyPort}; DIRECT");

        StringBuilder sb = new(512 + (domains.Length * 24));
        sb.AppendLine("function FindProxyForURL(url, host) {");
        sb.AppendLine("    if (!host) {");
        sb.AppendLine("        return \"DIRECT\";");
        sb.AppendLine("    }");
        sb.AppendLine("    if (host.charAt(0) === \"[\") {");
        sb.AppendLine("        var closeBracket = host.indexOf(\"]\");");
        sb.AppendLine("        if (closeBracket !== -1) {");
        sb.AppendLine("            host = host.substring(1, closeBracket);");
        sb.AppendLine("        }");
        sb.AppendLine("    } else {");
        sb.AppendLine("        var colon = host.indexOf(\":\");");
        sb.AppendLine("        if (colon !== -1) {");
        sb.AppendLine("            host = host.substring(0, colon);");
        sb.AppendLine("        }");
        sb.AppendLine("    }");
        sb.AppendLine("    host = host.toLowerCase();");
        sb.AppendLine("    while (host.length > 0 && host.charAt(host.length - 1) === \".\") {");
        sb.AppendLine("        host = host.substring(0, host.length - 1);");
        sb.AppendLine("    }");
        sb.AppendLine("    if (isPlainHostName(host) || host === \"localhost\" || host === \"127.0.0.1\" || host === \"::1\") {");
        sb.AppendLine("        return \"DIRECT\";");
        sb.AppendLine("    }");

        if (domains.Length == 0)
        {
            sb.AppendLine("    return \"DIRECT\";");
            sb.AppendLine("}");
        }
        else
        {
            sb.AppendLine("    var splitDomains = {");
            for (int i = 0; i < domains.Length; i++)
            {
                string comma = i < domains.Length - 1 ? "," : string.Empty;
                sb.Append("        \"").Append(domains[i]).Append("\": 1").AppendLine(comma);
            }

            sb.AppendLine("    };");
            sb.Append("    var proxyRoute = \"").Append(proxyDirective).AppendLine("\";");
            sb.AppendLine("    var candidate = host;");
            sb.AppendLine("    while (candidate.length > 0) {");
            sb.AppendLine("        if (Object.prototype.hasOwnProperty.call(splitDomains, candidate)) {");
            sb.AppendLine("            return proxyRoute;");
            sb.AppendLine("        }");
            sb.AppendLine("        var dot = candidate.indexOf(\".\");");
            sb.AppendLine("        if (dot === -1) {");
            sb.AppendLine("            break;");
            sb.AppendLine("        }");
            sb.AppendLine("        candidate = candidate.substring(dot + 1);");
            sb.AppendLine("    }");
            sb.AppendLine("    return \"DIRECT\";");
            sb.AppendLine("}");
        }

        string script = sb.ToString();
        byte[] utf8 = Encoding.UTF8.GetBytes(script);
        return new PacSnapshot(proxyHost, proxyPort, domains, script, utf8);
    }

    private sealed record PacSnapshot(
        string ProxyHost,
        int ProxyPort,
        string[] Domains,
        string ScriptText,
        byte[] ScriptUtf8Bytes);
}
