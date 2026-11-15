using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Core.Models;
using DnsPulse.Core.Security;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// Upstream transport client for <see cref="DnsProtocol.SniProxy"/> (<c>smartproxy://</c>) nodes.
/// Verifies TCP reachability on the proxy port (default 443) and synthesizes <c>A</c> records pointing to the
/// SNI-Proxy IPv4 address while returning clean <c>NOERROR</c> NODATA for <c>AAAA</c>, <c>HTTPS</c>, and <c>SVCB</c>.
/// </summary>
public sealed class SniProxyDnsClient : IDnsUpstreamClient
{
    private const int DefaultSniProxyPort = 443;
    private const uint DefaultSyntheticTtlSeconds = 45;

    private readonly TransportOptions _options;
    private readonly Func<IPEndPoint, CancellationToken, Task>? _tcpProbeOverride;
    private readonly bool _allowNonPublicTargets;

    /// <summary>
    /// Initializes a new <see cref="SniProxyDnsClient"/>.
    /// </summary>
    public SniProxyDnsClient(
        TransportOptions? options = null,
        Func<IPEndPoint, CancellationToken, Task>? tcpProbeOverride = null,
        bool allowNonPublicTargets = false)
    {
        _options = options ?? new TransportOptions();
        _tcpProbeOverride = tcpProbeOverride;
        _allowNonPublicTargets = allowNonPublicTargets;
    }

    /// <inheritdoc />
    public DnsProtocol Protocol => DnsProtocol.SniProxy;

    /// <inheritdoc />
    public async Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);
        cancellationToken.ThrowIfCancellationRequested();

        if (!TryResolveProxyEndpoint(upstream, out IPAddress? proxyIp, out int port) || proxyIp is null)
        {
            throw new InvalidOperationException(
                string.Create(CultureInfo.InvariantCulture, $"SNI-Proxy upstream '{upstream.Name}' does not have a valid public SmartProxy IP."));
        }

        IPEndPoint endpoint = new(proxyIp, port);
        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);

        Stopwatch sw = Stopwatch.StartNew();
        if (_tcpProbeOverride is not null)
        {
            await _tcpProbeOverride(endpoint, timeoutCts.Token).ConfigureAwait(false);
        }
        else
        {
            using TcpClient tcp = new(proxyIp.AddressFamily);
            await tcp.ConnectAsync(proxyIp, port, timeoutCts.Token).ConfigureAwait(false);
        }

        sw.Stop();

        DnsMessage synthesized = BuildSynthesizedResponse(query, proxyIp, DefaultSyntheticTtlSeconds);
        string endpointLabel = string.Create(CultureInfo.InvariantCulture, $"smartproxy://{proxyIp}:{port}");
        return new UpstreamQueryResult(
            synthesized,
            sw.Elapsed > TimeSpan.Zero ? sw.Elapsed : TimeSpan.FromMilliseconds(1),
            endpointLabel,
            DnsProtocol.SniProxy);
    }

    /// <summary>
    /// Builds a synthetic DNS response directing IPv4 A queries to <paramref name="proxyIp"/>
    /// and emitting clean empty <c>NOERROR</c> NODATA for <c>AAAA</c>, <c>HTTPS</c>, and <c>SVCB</c>.
    /// </summary>
    public static DnsMessage BuildSynthesizedResponse(
        DnsMessage query,
        IPAddress proxyIp,
        uint ttlSeconds = DefaultSyntheticTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(proxyIp);

        if (query.Questions.Count == 0)
        {
            return new DnsMessage
            {
                Header = new DnsHeader
                {
                    Id = query.Header.Id,
                    IsResponse = true,
                    OpCode = query.Header.OpCode,
                    RecursionDesired = query.Header.RecursionDesired,
                    RecursionAvailable = true,
                    ResponseCode = DnsResponseCode.NoError
                }
            };
        }

        DnsQuestion question = query.Questions[0];
        List<DnsResourceRecord> answers = [];

        if (question.RecordType == DnsRecordType.A && proxyIp.AddressFamily == AddressFamily.InterNetwork)
        {
            answers.Add(DnsResourceRecord.CreateA(question.Name, proxyIp, ttlSeconds));
        }
        else if (question.RecordType == DnsRecordType.AAAA && proxyIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            answers.Add(DnsResourceRecord.CreateAaaa(question.Name, proxyIp, ttlSeconds));
        }

        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = query.Header.Id,
                IsResponse = true,
                OpCode = query.Header.OpCode,
                RecursionDesired = query.Header.RecursionDesired,
                RecursionAvailable = true,
                ResponseCode = DnsResponseCode.NoError,
                QuestionCount = (ushort)query.Questions.Count,
                AnswerCount = (ushort)answers.Count
            },
            Questions = query.Questions,
            Answers = answers
        };
    }

    private bool TryResolveProxyEndpoint(DnsServerEntry upstream, out IPAddress? address, out int port)
    {
        address = null;
        port = upstream.Port is > 0 and <= 65535 ? upstream.Port.Value : DefaultSniProxyPort;

        string? rawIp = !string.IsNullOrWhiteSpace(upstream.SmartProxyIp)
            ? upstream.SmartProxyIp
            : upstream.PrimaryIp;

        if (!IPAddress.TryParse(rawIp, out IPAddress? parsed))
        {
            return false;
        }

        if (!_allowNonPublicTargets && !IpSafetyInspector.IsPublicRoutable(parsed))
        {
            return false;
        }

        address = parsed;
        return true;
    }
}
