using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsPulse.Engine.Sidecar;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Sidecar;

public sealed class TlsFragmentationProxyServerTests
{
    [Fact]
    public void ComputeFragmentRanges_SplitsDirectlyInsideSniHostname()
    {
        byte[] hello = TlsClientHelloInspectorTests.BuildSyntheticClientHello("api.openai.com", includeGrease: true, includeEch: false);
        TlsClientHelloInspection inspection = TlsClientHelloInspector.Inspect(hello);

        IReadOnlyList<(int Offset, int Length)> ranges = TlsFragmentationProxyServer.ComputeFragmentRanges(
            hello.Length,
            inspection,
            splitAtSni: true,
            fragmentChunkSize: 0);

        ranges.Should().HaveCount(2);
        ranges[0].Offset.Should().Be(0);
        int splitPoint = ranges[0].Length;
        ranges[1].Offset.Should().Be(splitPoint);
        (ranges[0].Length + ranges[1].Length).Should().Be(hello.Length);

        splitPoint.Should().BeGreaterThan(inspection.ServerNameOffset);
        splitPoint.Should().BeLessThan(inspection.ServerNameOffset + inspection.ServerNameLength);
    }

    [Fact]
    public async Task HttpConnect_FragmentsClientHelloAcrossSniAndRelaysFullDuplex()
    {
        byte[] clientHello = TlsClientHelloInspectorTests.BuildSyntheticClientHello("api.openai.com", includeGrease: true, includeEch: false);
        await using MockUpstreamServer upstream = new(expectedClientBytes: clientHello.Length, responseBytes: "TLS-ECHO-OK"u8.ToArray());
        await upstream.StartAsync();

        TlsFragmentationProxyOptions options = new()
        {
            BindAddress = IPAddress.Loopback,
            Port = 0,
            SplitAtSni = true,
            FragmentChunkSize = 32,
            InterFragmentDelayMs = 15,
            BlockPrivateDestinationIps = false
        };

        await using TlsFragmentationProxyServer proxy = new(
            options,
            (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]));
        await proxy.StartAsync();

        using TcpClient client = new() { NoDelay = true };
        await client.ConnectAsync(proxy.BoundEndPoint!.Address, proxy.BoundEndPoint.Port);
        await using NetworkStream stream = client.GetStream();

        byte[] connectRequest = Encoding.ASCII.GetBytes($"CONNECT api.openai.com:{upstream.Port} HTTP/1.1\r\nHost: api.openai.com:{upstream.Port}\r\n\r\n");
        await stream.WriteAsync(connectRequest);

        string connectResponse = await ReadUntilHttpHeadersEndAsync(stream);
        connectResponse.Should().StartWith("HTTP/1.1 200 Connection Established");

        await stream.WriteAsync(clientHello);
        await stream.FlushAsync();

        byte[] reply = await ReadExactAsync(stream, "TLS-ECHO-OK"u8.Length);
        Encoding.ASCII.GetString(reply).Should().Be("TLS-ECHO-OK");

        await upstream.WaitForClientSessionAsync();
        upstream.ReassembledBytes.Should().Equal(clientHello);
        upstream.ReceivedChunks.Count.Should().BeGreaterThan(1);

        byte[] sniAscii = "api.openai.com"u8.ToArray();
        upstream.ReceivedChunks.Should().AllSatisfy(
            chunk => chunk.AsSpan().IndexOf(sniAscii).Should().Be(-1, "the SNI hostname must be split across separate TCP segments"));
        proxy.FragmentedClientHellosCount.Should().Be(1);
    }

    [Fact]
    public async Task Socks5ConnectDomain_FragmentsClientHelloAcrossSniAndRelaysFullDuplex()
    {
        byte[] clientHello = TlsClientHelloInspectorTests.BuildSyntheticClientHello("chatgpt.com", includeGrease: true, includeEch: true);
        await using MockUpstreamServer upstream = new(expectedClientBytes: clientHello.Length, responseBytes: "SOCKS5-OK"u8.ToArray());
        await upstream.StartAsync();

        TlsFragmentationProxyOptions options = new()
        {
            BindAddress = IPAddress.Loopback,
            Port = 0,
            SplitAtSni = true,
            FragmentChunkSize = 24,
            InterFragmentDelayMs = 15,
            BlockPrivateDestinationIps = false
        };

        await using TlsFragmentationProxyServer proxy = new(
            options,
            (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]));
        await proxy.StartAsync();

        using TcpClient client = new() { NoDelay = true };
        await client.ConnectAsync(proxy.BoundEndPoint!.Address, proxy.BoundEndPoint.Port);
        await using NetworkStream stream = client.GetStream();

        // SOCKS5 Greeting: VER=5, NMETHODS=1, METHOD=0x00 (NO AUTH)
        byte[] greeting = [0x05, 0x01, 0x00];
        await stream.WriteAsync(greeting);
        byte[] authReply = await ReadExactAsync(stream, 2);
        authReply.Should().Equal(0x05, 0x00);

        // SOCKS5 CONNECT domain "chatgpt.com"
        byte[] domainBytes = "chatgpt.com"u8.ToArray();
        byte[] req = new byte[4 + 1 + domainBytes.Length + 2];
        req[0] = 0x05;
        req[1] = 0x01; // CONNECT
        req[2] = 0x00;
        req[3] = 0x03; // Domain
        req[4] = (byte)domainBytes.Length;
        domainBytes.CopyTo(req, 5);
        BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(5 + domainBytes.Length, 2), (ushort)upstream.Port);
        await stream.WriteAsync(req);

        byte[] connectReplyHead = await ReadExactAsync(stream, 4);
        connectReplyHead[0].Should().Be(0x05);
        connectReplyHead[1].Should().Be(0x00);
        int addrLen = connectReplyHead[3] == 0x04 ? 16 : 4;
        _ = await ReadExactAsync(stream, addrLen + 2);

        await stream.WriteAsync(clientHello);
        await stream.FlushAsync();

        byte[] reply = await ReadExactAsync(stream, "SOCKS5-OK"u8.Length);
        Encoding.ASCII.GetString(reply).Should().Be("SOCKS5-OK");

        await upstream.WaitForClientSessionAsync();
        upstream.ReassembledBytes.Should().Equal(clientHello);
        upstream.ReceivedChunks.Count.Should().BeGreaterThan(1);

        byte[] sniAscii = "chatgpt.com"u8.ToArray();
        upstream.ReceivedChunks.Should().AllSatisfy(
            chunk => chunk.AsSpan().IndexOf(sniAscii).Should().Be(-1, "the SNI hostname must be split across separate TCP segments"));
    }

    [Fact]
    public async Task PlainHttpProxyRequest_NormalizesHostHeaderAndStripsProxyHeaders()
    {
        byte[] upstreamHttpResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"u8.ToArray();
        await using MockHttpOriginServer origin = new(upstreamHttpResponse);
        await origin.StartAsync();

        TlsFragmentationProxyOptions options = new()
        {
            BindAddress = IPAddress.Loopback,
            Port = 0,
            NormalizePlainHttpHostHeader = true,
            NormalizedHostHeaderName = "host",
            BlockPrivateDestinationIps = false
        };

        await using TlsFragmentationProxyServer proxy = new(
            options,
            (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]));
        await proxy.StartAsync();

        using TcpClient client = new() { NoDelay = true };
        await client.ConnectAsync(proxy.BoundEndPoint!.Address, proxy.BoundEndPoint.Port);
        await using NetworkStream stream = client.GetStream();

        string proxyRequest =
            $"GET http://plain.example.test:{origin.Port}/hello?x=1 HTTP/1.1\r\n" +
            $"Host: plain.example.test:{origin.Port}\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "Connection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(proxyRequest));

        string receivedResponse = await ReadToEndAsciiAsync(stream);
        receivedResponse.Should().Contain("200 OK");
        receivedResponse.Should().EndWith("OK");

        string? originReceivedRequest = await origin.WaitForRequestAsync();
        originReceivedRequest.Should().StartWith("GET /hello?x=1 HTTP/1.1\r\n");
        originReceivedRequest.Should().Contain($"\r\nhost: plain.example.test:{origin.Port}\r\n");
        originReceivedRequest.Should().NotContain("Host:");
        originReceivedRequest.Should().NotContain("Proxy-Connection");
    }

    [Fact]
    public async Task SsrfGuard_RejectsLoopbackAndPrivateTargetsInHttpConnectAndSocks5()
    {
        TlsFragmentationProxyOptions options = new()
        {
            BindAddress = IPAddress.Loopback,
            Port = 0,
            BlockPrivateDestinationIps = true
        };

        await using TlsFragmentationProxyServer proxy = new(
            options,
            (host, _) =>
            {
                if (host.Equals("ssrf-internal.test", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse("10.20.30.40")]);
                }

                return Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse("127.0.0.1")]);
            });
        await proxy.StartAsync();

        // 1. HTTP CONNECT literal loopback
        using (TcpClient client = new())
        {
            await client.ConnectAsync(proxy.BoundEndPoint!.Address, proxy.BoundEndPoint.Port);
            await using NetworkStream stream = client.GetStream();
            await stream.WriteAsync("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"u8.ToArray());
            string response = await ReadUntilHttpHeadersEndAsync(stream);
            response.Should().StartWith("HTTP/1.1 403 Forbidden");
        }

        // 2. HTTP CONNECT domain resolving to RFC 1918 private IP
        using (TcpClient client = new())
        {
            await client.ConnectAsync(proxy.BoundEndPoint!.Address, proxy.BoundEndPoint.Port);
            await using NetworkStream stream = client.GetStream();
            await stream.WriteAsync("CONNECT ssrf-internal.test:443 HTTP/1.1\r\nHost: ssrf-internal.test:443\r\n\r\n"u8.ToArray());
            string response = await ReadUntilHttpHeadersEndAsync(stream);
            response.Should().StartWith("HTTP/1.1 403 Forbidden");
        }

        // 3. SOCKS5 CONNECT IPv4 loopback
        using (TcpClient client = new())
        {
            await client.ConnectAsync(proxy.BoundEndPoint!.Address, proxy.BoundEndPoint.Port);
            await using NetworkStream stream = client.GetStream();
            byte[] greeting = [0x05, 0x01, 0x00];
            await stream.WriteAsync(greeting);
            byte[] auth = await ReadExactAsync(stream, 2);
            auth.Should().Equal(0x05, 0x00);

            // CONNECT 127.0.0.1:443
            byte[] connectLoopback = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB];
            await stream.WriteAsync(connectLoopback);
            byte[] reply = await ReadExactAsync(stream, 10);
            reply[0].Should().Be(0x05);
            reply[1].Should().Be(0x02); // Connection not allowed by ruleset
        }

        proxy.BlockedSsrfsCount.Should().Be(3);
    }

    private static async Task<string> ReadUntilHttpHeadersEndAsync(NetworkStream stream)
    {
        List<byte> bytes = [];
        byte[] buf = new byte[1024];
        while (true)
        {
            int n = await stream.ReadAsync(buf);
            if (n <= 0)
            {
                break;
            }

            bytes.AddRange(buf.AsSpan(0, n).ToArray());
            string text = Encoding.ASCII.GetString([.. bytes]);
            if (text.Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                return text;
            }
        }

        return Encoding.ASCII.GetString([.. bytes]);
    }

    private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int count)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(offset, count - offset));
            if (n <= 0)
            {
                throw new EndOfStreamException($"Expected {count} bytes but stream ended at {offset}.");
            }

            offset += n;
        }

        return buffer;
    }

    private static async Task<string> ReadToEndAsciiAsync(NetworkStream stream)
    {
        using MemoryStream ms = new();
        await stream.CopyToAsync(ms);
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    private sealed class MockUpstreamServer : IAsyncDisposable
    {
        private readonly int _expectedClientBytes;
        private readonly byte[] _responseBytes;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly TaskCompletionSource _sessionDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ConcurrentQueue<byte[]> _chunks = new();
        private Task? _acceptTask;

        public MockUpstreamServer(int expectedClientBytes, byte[] responseBytes)
        {
            _expectedClientBytes = expectedClientBytes;
            _responseBytes = responseBytes;
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public IReadOnlyList<byte[]> ReceivedChunks => [.. _chunks];

        public byte[] ReassembledBytes
        {
            get
            {
                List<byte> all = [];
                foreach (byte[] chunk in _chunks)
                {
                    all.AddRange(chunk);
                }

                return [.. all];
            }
        }

        public Task StartAsync()
        {
            _listener.Start();
            _acceptTask = AcceptOneAsync();
            return Task.CompletedTask;
        }

        public Task WaitForClientSessionAsync() => _sessionDone.Task.WaitAsync(TimeSpan.FromSeconds(5));

        private async Task AcceptOneAsync()
        {
            try
            {
                using TcpClient client = await _listener.AcceptTcpClientAsync();
                client.NoDelay = true;
                await using NetworkStream stream = client.GetStream();

                int total = 0;
                byte[] buf = new byte[4096];
                while (total < _expectedClientBytes)
                {
                    int n = await stream.ReadAsync(buf);
                    if (n <= 0)
                    {
                        break;
                    }

                    byte[] copy = new byte[n];
                    Buffer.BlockCopy(buf, 0, copy, 0, n);
                    _chunks.Enqueue(copy);
                    total += n;
                }

                await stream.WriteAsync(_responseBytes);
                await stream.FlushAsync();
                _sessionDone.TrySetResult();
            }
            catch (ObjectDisposedException ex)
            {
                _sessionDone.TrySetException(ex);
            }
            catch (SocketException ex)
            {
                _sessionDone.TrySetException(ex);
            }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            _listener.Dispose();
            if (_acceptTask is not null)
            {
                try
                {
                    await _acceptTask;
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
            }
        }
    }

    private sealed class MockHttpOriginServer : IAsyncDisposable
    {
        private readonly byte[] _responseBytes;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly TaskCompletionSource<string> _capturedRequest = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task? _acceptTask;

        public MockHttpOriginServer(byte[] responseBytes)
        {
            _responseBytes = responseBytes;
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public Task StartAsync()
        {
            _listener.Start();
            _acceptTask = AcceptOneAsync();
            return Task.CompletedTask;
        }

        public Task<string> WaitForRequestAsync() => _capturedRequest.Task.WaitAsync(TimeSpan.FromSeconds(5));

        private async Task AcceptOneAsync()
        {
            using TcpClient client = await _listener.AcceptTcpClientAsync();
            await using NetworkStream stream = client.GetStream();
            string req = await ReadUntilHttpHeadersEndAsync(stream);
            _capturedRequest.TrySetResult(req);
            await stream.WriteAsync(_responseBytes);
            await stream.FlushAsync();
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            _listener.Dispose();
            if (_acceptTask is not null)
            {
                try
                {
                    await _acceptTask;
                }
                catch (SocketException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }
    }
}
