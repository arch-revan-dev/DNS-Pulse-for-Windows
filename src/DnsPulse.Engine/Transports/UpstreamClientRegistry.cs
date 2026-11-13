using System.Diagnostics.CodeAnalysis;
using DnsPulse.Core.Models;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// Dispatches <see cref="DnsServerEntry"/> queries to the matching <see cref="IDnsUpstreamClient"/>
/// across UDP, TCP, DoT, DoH, DoH3, DoQ, DNSCrypt, Anonymized DNSCrypt, and ODoH.
/// </summary>
public sealed class UpstreamClientRegistry : IAsyncDisposable, IDisposable
{
    private readonly Dictionary<DnsProtocol, IDnsUpstreamClient> _clients = [];
    private readonly List<object> _ownedClients = [];
    private bool _disposed;

    /// <summary>
    /// Initializes an <see cref="UpstreamClientRegistry"/> from DI-provided <see cref="IDnsUpstreamClient"/> instances.
    /// </summary>
    public UpstreamClientRegistry(IEnumerable<IDnsUpstreamClient> clients)
        : this(clients, ownsClients: false)
    {
    }

    private UpstreamClientRegistry(IEnumerable<IDnsUpstreamClient> clients, bool ownsClients)
    {
        ArgumentNullException.ThrowIfNull(clients);

        foreach (IDnsUpstreamClient client in clients)
        {
            ArgumentNullException.ThrowIfNull(client);
            _clients[client.Protocol] = client;
            if (ownsClients)
            {
                _ownedClients.Add(client);
            }
        }
    }

    /// <summary>
    /// Creates a registry populated with default implementations for all supported DNS protocols.
    /// </summary>
    public static UpstreamClientRegistry CreateDefault(
        IBootstrapResolver? bootstrapResolver = null,
        TransportOptions? options = null)
    {
        TransportOptions effectiveOptions = options ?? new TransportOptions();
        DotDnsClient? dot = null;
        DohDnsClient? doh = null;
        DohDnsClient? doh3 = null;
        DoqDnsClient? doq = null;
        OdohClient? odoh = null;

        try
        {
            dot = new DotDnsClient(bootstrapResolver, effectiveOptions);
            doh = new DohDnsClient(DnsProtocol.DoH, bootstrapResolver, effectiveOptions);
            doh3 = new DohDnsClient(DnsProtocol.DoH3, bootstrapResolver, effectiveOptions);
            doq = new DoqDnsClient(bootstrapResolver, effectiveOptions);
            odoh = new OdohClient(bootstrapResolver, effectiveOptions);

            IDnsUpstreamClient[] clients =
            [
                new UdpTcpDnsClient(DnsProtocol.Udp, bootstrapResolver, effectiveOptions),
                new UdpTcpDnsClient(DnsProtocol.Tcp, bootstrapResolver, effectiveOptions),
                dot,
                doh,
                doh3,
                doq,
                new DnsCryptClient(DnsProtocol.DnsCrypt, effectiveOptions),
                new DnsCryptClient(DnsProtocol.AnonymizedDnsCrypt, effectiveOptions),
                odoh
            ];

            UpstreamClientRegistry registry = new(clients, ownsClients: true);
            dot = null;
            doh = null;
            doh3 = null;
            doq = null;
            odoh = null;
            return registry;
        }
        finally
        {
            dot?.Dispose();
            doh?.Dispose();
            doh3?.Dispose();
            doq?.Dispose();
            odoh?.Dispose();
        }
    }

    /// <summary>
    /// Returns the registered client for <paramref name="protocol"/>, or throws <see cref="NotSupportedException"/>.
    /// </summary>
    public IDnsUpstreamClient GetClient(DnsProtocol protocol)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_clients.TryGetValue(protocol, out IDnsUpstreamClient? client))
        {
            return client;
        }

        throw new NotSupportedException($"No DNS upstream transport client is registered for protocol '{protocol}'.");
    }

    /// <summary>
    /// Attempts to retrieve a registered client for <paramref name="protocol"/>.
    /// </summary>
    public bool TryGetClient(DnsProtocol protocol, [NotNullWhen(true)] out IDnsUpstreamClient? client)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _clients.TryGetValue(protocol, out client);
    }

    /// <summary>
    /// Dispatches a query for <paramref name="upstream"/> using the matching protocol client.
    /// </summary>
    public Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        IDnsUpstreamClient client = GetClient(upstream.Protocol);
        return client.QueryAsync(query, upstream, cancellationToken);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (object client in _ownedClients)
        {
            if (client is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        _ownedClients.Clear();
        _clients.Clear();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (object client in _ownedClients)
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

        _ownedClients.Clear();
        _clients.Clear();
    }
}
