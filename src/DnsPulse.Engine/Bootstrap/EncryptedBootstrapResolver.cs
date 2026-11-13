using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Security;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Transports;

namespace DnsPulse.Engine.Bootstrap;

/// <summary>
/// Happy Eyeballs encrypted-first bootstrap resolver that races Direct-IP DoH/DoT with 250 ms staggering,
/// falls back to TLS-fragmented DoH, and falls back to plaintext TCP/UDP 53 only when strictly validated
/// by <see cref="IpSafetyInspector"/> and <see cref="DnsRebindingValidator"/> to reject bogons and sinkholes.
/// </summary>
public sealed class EncryptedBootstrapResolver : IBootstrapResolver, IAsyncDisposable, IDisposable
{
    private readonly BootstrapOptions _options;
    private readonly IDnsUpstreamClient _dohClient;
    private readonly IDnsUpstreamClient _fragmentedDohClient;
    private readonly IDnsUpstreamClient _dotClient;
    private readonly IDnsUpstreamClient _plainClient;
    private readonly bool _ownsClients;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="EncryptedBootstrapResolver"/> using default transport clients.
    /// </summary>
    public EncryptedBootstrapResolver(
        BootstrapOptions? options = null,
        TransportOptions? transportOptions = null)
    {
        _options = options ?? new BootstrapOptions();
        TransportOptions baseTransport = (transportOptions ?? new TransportOptions()) with
        {
            Timeout = _options.CandidateTimeout
        };
        TransportOptions fragmentedTransport = baseTransport with
        {
            EnableTlsFragmentation = true
        };

        _dohClient = new DohDnsClient(DnsProtocol.DoH, bootstrapResolver: null, baseTransport);
        _fragmentedDohClient = new DohDnsClient(DnsProtocol.DoH, bootstrapResolver: null, fragmentedTransport);
        _dotClient = new DotDnsClient(bootstrapResolver: null, baseTransport);
        _plainClient = new UdpTcpDnsClient(DnsProtocol.Udp, bootstrapResolver: null, baseTransport);
        _ownsClients = true;
    }

    /// <summary>
    /// Initializes a new <see cref="EncryptedBootstrapResolver"/> with injected transport clients (for DI or testing).
    /// </summary>
    public EncryptedBootstrapResolver(
        BootstrapOptions options,
        IDnsUpstreamClient dohClient,
        IDnsUpstreamClient fragmentedDohClient,
        IDnsUpstreamClient dotClient,
        IDnsUpstreamClient plainClient)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dohClient);
        ArgumentNullException.ThrowIfNull(fragmentedDohClient);
        ArgumentNullException.ThrowIfNull(dotClient);
        ArgumentNullException.ThrowIfNull(plainClient);

        _options = options;
        _dohClient = dohClient;
        _fragmentedDohClient = fragmentedDohClient;
        _dotClient = dotClient;
        _plainClient = plainClient;
        _ownsClients = false;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        string trimmed = host.Trim();
        if (IPAddress.TryParse(trimmed, out IPAddress? literal))
        {
            return [literal];
        }

        Task<DnsMessage> v4Task = QueryBaselineAsync(trimmed, DnsRecordType.A, cancellationToken);
        Task<DnsMessage?>? v6Task = _options.QueryIpv6
            ? TryQueryBaselineOptionalAsync(trimmed, DnsRecordType.AAAA, cancellationToken)
            : null;

        DnsMessage v4Response = await v4Task.ConfigureAwait(false);
        List<IPAddress> addresses = ExtractValidatedPublicAddresses(v4Response);

        if (v6Task is not null)
        {
            DnsMessage? v6Response = await v6Task.ConfigureAwait(false);
            if (v6Response is not null)
            {
                foreach (IPAddress v6 in ExtractValidatedPublicAddresses(v6Response))
                {
                    if (!addresses.Contains(v6))
                    {
                        addresses.Add(v6);
                    }
                }
            }
        }

        if (addresses.Count == 0)
        {
            throw new InvalidOperationException($"Bootstrap resolution for '{trimmed}' yielded no public routable IP addresses.");
        }

        return addresses;
    }

    /// <inheritdoc />
    public async Task<DnsMessage> QueryBaselineAsync(
        string domain,
        DnsRecordType recordType,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        List<Exception> failures = [];

        if (_options.DirectEncryptedEndpoints.Count > 0)
        {
            (DnsMessage? directResult, List<Exception> directErrors) = await RaceTierAsync(
                _options.DirectEncryptedEndpoints,
                domain,
                recordType,
                isFragmentedTier: false,
                isPlaintextTier: false,
                cancellationToken).ConfigureAwait(false);

            if (directResult is not null)
            {
                return directResult;
            }

            failures.AddRange(directErrors);
        }

        if (_options.FragmentedDohEndpoints.Count > 0)
        {
            (DnsMessage? fragResult, List<Exception> fragErrors) = await RaceTierAsync(
                _options.FragmentedDohEndpoints,
                domain,
                recordType,
                isFragmentedTier: true,
                isPlaintextTier: false,
                cancellationToken).ConfigureAwait(false);

            if (fragResult is not null)
            {
                return fragResult;
            }

            failures.AddRange(fragErrors);
        }

        if (_options.PlaintextFallbackEndpoints.Count > 0)
        {
            (DnsMessage? plainResult, List<Exception> plainErrors) = await RaceTierAsync(
                _options.PlaintextFallbackEndpoints,
                domain,
                recordType,
                isFragmentedTier: false,
                isPlaintextTier: true,
                cancellationToken).ConfigureAwait(false);

            if (plainResult is not null)
            {
                return plainResult;
            }

            failures.AddRange(plainErrors);
        }

        throw new AggregateException(
            string.Create(CultureInfo.InvariantCulture, $"All bootstrap tiers failed for '{domain}' ({recordType})."),
            failures);
    }

    /// <summary>
    /// Validates a DNS bootstrap response against bogon, sinkhole, and DNS-rebinding addresses.
    /// </summary>
    public static bool IsSafeBootstrapResponse(
        DnsMessage response,
        DnsRecordType requestedType,
        bool strictPlaintextCheck,
        out string? rejectionReason)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (!response.Header.IsResponse)
        {
            rejectionReason = "Packet is not a DNS response.";
            return false;
        }

        if (response.Header.ResponseCode is DnsResponseCode.ServFail
            or DnsResponseCode.Refused
            or DnsResponseCode.FormErr
            or DnsResponseCode.NotImp
            or DnsResponseCode.NotAuth)
        {
            rejectionReason = string.Create(
                CultureInfo.InvariantCulture,
                $"Upstream returned non-authoritative error RCODE {response.Header.ResponseCode}.");
            return false;
        }

        List<IPAddress> answerIps = [];
        foreach (DnsResourceRecord record in response.Answers)
        {
            if (record.RecordType is DnsRecordType.A or DnsRecordType.AAAA && record.Address is not null)
            {
                answerIps.Add(record.Address);
            }
        }

        if (answerIps.Count > 0)
        {
            DnsRebindingValidationResult validation = DnsRebindingValidator.ValidateAnswer(
                RouteZone.Zone4EncryptedTrusted,
                answerIps,
                allowCarrierAnycastExceptions: false);

            if (!validation.IsSafe)
            {
                rejectionReason = validation.RejectionReason ?? "Bootstrap response contained private or bogon IP address(es).";
                return false;
            }

            foreach (IPAddress ip in answerIps)
            {
                if (!IpSafetyInspector.IsPublicRoutable(ip))
                {
                    rejectionReason = string.Create(CultureInfo.InvariantCulture, $"Address '{ip}' is not publicly routable.");
                    return false;
                }
            }
        }
        else if (strictPlaintextCheck && requestedType is DnsRecordType.A or DnsRecordType.AAAA)
        {
            rejectionReason = "Plaintext fallback returned no valid A/AAAA records.";
            return false;
        }

        rejectionReason = null;
        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsClients)
        {
            (_dohClient as IDisposable)?.Dispose();
            (_fragmentedDohClient as IDisposable)?.Dispose();
            (_dotClient as IDisposable)?.Dispose();
            (_plainClient as IDisposable)?.Dispose();
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
        if (_ownsClients)
        {
            await DisposeClientAsync(_dohClient).ConfigureAwait(false);
            await DisposeClientAsync(_fragmentedDohClient).ConfigureAwait(false);
            await DisposeClientAsync(_dotClient).ConfigureAwait(false);
            await DisposeClientAsync(_plainClient).ConfigureAwait(false);
        }
    }

    private async Task<DnsMessage?> TryQueryBaselineOptionalAsync(
        string domain,
        DnsRecordType recordType,
        CancellationToken cancellationToken)
    {
        try
        {
            return await QueryBaselineAsync(domain, recordType, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AggregateException)
        {
            return null;
        }
    }

    private async Task<(DnsMessage? Winner, List<Exception> Errors)> RaceTierAsync(
        IReadOnlyList<DnsServerEntry> candidates,
        string domain,
        DnsRecordType recordType,
        bool isFragmentedTier,
        bool isPlaintextTier,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource raceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        List<Task<CandidateOutcome>> pending = [];
        List<Exception> errors = [];

        for (int i = 0; i < candidates.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Task<CandidateOutcome> started = RunCandidateAsync(
                candidates[i],
                domain,
                recordType,
                isFragmentedTier,
                isPlaintextTier,
                raceCts.Token);
            pending.Add(started);

            if (i == candidates.Count - 1)
            {
                break;
            }

            Task delayTask = _options.StaggerDelay > TimeSpan.Zero
                ? Task.Delay(_options.StaggerDelay, raceCts.Token)
                : Task.CompletedTask;

            while (pending.Count > 0)
            {
                Task<Task<CandidateOutcome>> allOrAny = Task.WhenAny(pending);
                Task completed = await Task.WhenAny(allOrAny, delayTask).ConfigureAwait(false);
                if (completed == delayTask)
                {
                    break;
                }

                Task<CandidateOutcome> finishedTask = await allOrAny.ConfigureAwait(false);
                pending.Remove(finishedTask);
                CandidateOutcome outcome = await finishedTask.ConfigureAwait(false);
                if (outcome.Response is not null)
                {
                    await raceCts.CancelAsync().ConfigureAwait(false);
                    ObserveRemainingTasks(pending);
                    return (outcome.Response, errors);
                }

                if (outcome.Error is not null)
                {
                    errors.Add(outcome.Error);
                }

                // Launch next candidate immediately when current one fails early.
                break;
            }
        }

        while (pending.Count > 0)
        {
            Task<CandidateOutcome> finishedTask = await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(finishedTask);
            CandidateOutcome outcome = await finishedTask.ConfigureAwait(false);
            if (outcome.Response is not null)
            {
                await raceCts.CancelAsync().ConfigureAwait(false);
                ObserveRemainingTasks(pending);
                return (outcome.Response, errors);
            }

            if (outcome.Error is not null)
            {
                errors.Add(outcome.Error);
            }
        }

        return (null, errors);
    }

    private async Task<CandidateOutcome> RunCandidateAsync(
        DnsServerEntry upstream,
        string domain,
        DnsRecordType recordType,
        bool isFragmentedTier,
        bool isPlaintextTier,
        CancellationToken cancellationToken)
    {
        IDnsUpstreamClient client = SelectClient(upstream, isFragmentedTier);
        ushort queryId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        DnsMessage query = DnsMessage.CreateQuery(queryId, domain, recordType);

        try
        {
            UpstreamQueryResult result = await client.QueryAsync(query, upstream, cancellationToken).ConfigureAwait(false);
            if (!IsSafeBootstrapResponse(result.Response, recordType, isPlaintextTier, out string? rejectionReason))
            {
                return new CandidateOutcome(
                    null,
                    new InvalidDataException(
                        string.Create(CultureInfo.InvariantCulture, $"Bootstrap candidate '{upstream.Name}' rejected: {rejectionReason}")));
            }

            return new CandidateOutcome(result.Response, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new CandidateOutcome(null, null);
        }
        catch (SocketException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (IOException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (HttpRequestException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (AuthenticationException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (TimeoutException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (InvalidDataException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (FormatException ex)
        {
            return new CandidateOutcome(null, ex);
        }
        catch (InvalidOperationException ex)
        {
            return new CandidateOutcome(null, ex);
        }
    }

    private IDnsUpstreamClient SelectClient(DnsServerEntry upstream, bool isFragmentedTier)
    {
        if (isFragmentedTier)
        {
            return _fragmentedDohClient;
        }

        return upstream.Protocol switch
        {
            DnsProtocol.DoH or DnsProtocol.DoH3 => _dohClient,
            DnsProtocol.DoT => _dotClient,
            _ => _plainClient
        };
    }

    private static List<IPAddress> ExtractValidatedPublicAddresses(DnsMessage response)
    {
        List<IPAddress> result = [];
        foreach (DnsResourceRecord record in response.Answers)
        {
            if (record.RecordType is DnsRecordType.A or DnsRecordType.AAAA
                && record.Address is not null
                && IpSafetyInspector.IsPublicRoutable(record.Address)
                && !result.Contains(record.Address))
            {
                result.Add(record.Address);
            }
        }

        return result;
    }

    private static void ObserveRemainingTasks(List<Task<CandidateOutcome>> pending)
    {
        foreach (Task<CandidateOutcome> task in pending)
        {
            _ = task.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private static async ValueTask DisposeClientAsync(IDnsUpstreamClient client)
    {
        if (client is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync().ConfigureAwait(false);
        }
        else if (client is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    private readonly record struct CandidateOutcome(DnsMessage? Response, Exception? Error);
}
