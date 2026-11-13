using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using DnsPulse.Core.Models;
using DnsPulse.Core.Security;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// RFC 9462 Discovery of Designated Resolvers (DDR) client querying <c>_dns.resolver.arpa</c> <c>SVCB</c>
/// records and mapping them into candidate <see cref="DnsServerEntry"/> instances.
/// </summary>
public sealed class DdrDiscoveryClient
{
    public const string ResolverArpaDomain = "_dns.resolver.arpa";
    private const ushort SvcParamKeyDohPath = 7;

    /// <summary>
    /// Queries <paramref name="seedResolver"/> for <c>_dns.resolver.arpa SVCB</c> and returns discovered encrypted candidates.
    /// </summary>
    public static async Task<IReadOnlyList<DnsServerEntry>> DiscoverAsync(
        DnsServerEntry seedResolver,
        IDnsUpstreamClient upstreamClient,
        bool requirePublicHints = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(seedResolver);
        ArgumentNullException.ThrowIfNull(upstreamClient);

        ushort queryId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        DnsMessage query = DnsMessage.CreateQuery(queryId, ResolverArpaDomain, DnsRecordType.SVCB);
        UpstreamQueryResult result = await upstreamClient.QueryAsync(query, seedResolver, cancellationToken).ConfigureAwait(false);

        IPAddress? designatedIp = null;
        if (EndpointResolutionHelper.TryParseEndpointIp(seedResolver.PrimaryIp, out IPAddress parsedIp, out _))
        {
            designatedIp = parsedIp;
        }

        return ParseSvcbResponse(result.Response, seedResolver.Name, designatedIp, requirePublicHints);
    }

    /// <summary>
    /// Parses RFC 9462 <c>_dns.resolver.arpa SVCB</c> records from a DNS response into <see cref="DnsServerEntry"/> candidates.
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> ParseSvcbResponse(
        DnsMessage response,
        string? sourceResolverName = null,
        IPAddress? designatedResolverIp = null,
        bool requirePublicHints = false)
    {
        ArgumentNullException.ThrowIfNull(response);

        List<DnsResourceRecord> svcbRecords = [];
        foreach (DnsResourceRecord record in response.Answers)
        {
            if (record.RecordType == DnsRecordType.SVCB
                && string.Equals(record.Name.TrimEnd('.'), ResolverArpaDomain, StringComparison.OrdinalIgnoreCase)
                && record.SvcPriority > 0
                && !string.IsNullOrWhiteSpace(record.TargetName))
            {
                svcbRecords.Add(record);
            }
        }

        if (svcbRecords.Count == 0)
        {
            return [];
        }

        svcbRecords.Sort(static (left, right) => left.SvcPriority.CompareTo(right.SvcPriority));

        Dictionary<string, List<IPAddress>> glueByName = CollectGlueAddresses(response.Additionals, requirePublicHints);
        List<DnsServerEntry> candidates = [];
        int index = 0;

        foreach (DnsResourceRecord svcb in svcbRecords)
        {
            string targetHost = svcb.TargetName!.TrimEnd('.');
            if (string.IsNullOrWhiteSpace(targetHost))
            {
                continue;
            }

            IReadOnlyList<string> alpnIds = [];
            ushort? explicitPort = null;
            List<IPAddress> hints = [];
            string dohPath = "/dns-query";

            foreach (SvcParam param in svcb.SvcParams)
            {
                switch (param.Key)
                {
                    case (ushort)SvcParamKey.Alpn:
                        alpnIds = param.ParseAlpnIds();
                        break;

                    case (ushort)SvcParamKey.Port:
                        explicitPort = param.ParsePort();
                        break;

                    case (ushort)SvcParamKey.Ipv4Hint:
                        AddFilteredHints(hints, param.ParseIpv4Hints(), requirePublicHints);
                        break;

                    case (ushort)SvcParamKey.Ipv6Hint:
                        AddFilteredHints(hints, param.ParseIpv6Hints(), requirePublicHints);
                        break;

                    case SvcParamKeyDohPath:
                        dohPath = ParseDohPathTemplate(param.Value.Span);
                        break;
                }
            }

            if (glueByName.TryGetValue(targetHost, out List<IPAddress>? glueAddresses))
            {
                AddFilteredHints(hints, glueAddresses, requirePublicHints);
            }

            if (hints.Count == 0 && designatedResolverIp is not null)
            {
                if (!requirePublicHints || IpSafetyInspector.IsPublicRoutable(designatedResolverIp))
                {
                    hints.Add(designatedResolverIp);
                }
            }

            List<string> bootstrapIps = new(hints.Count);
            foreach (IPAddress ip in hints)
            {
                string ipText = ip.ToString();
                if (!bootstrapIps.Contains(ipText, StringComparer.Ordinal))
                {
                    bootstrapIps.Add(ipText);
                }
            }

            string primaryIp = bootstrapIps.Count > 0 ? bootstrapIps[0] : string.Empty;
            string? secondaryIp = bootstrapIps.Count > 1 ? bootstrapIps[1] : null;
            List<DnsProtocol> protocols = MapAlpnToProtocols(alpnIds);

            foreach (DnsProtocol protocol in protocols)
            {
                int port = explicitPort ?? GetDefaultPort(protocol);
                string? dohUrl = protocol is DnsProtocol.DoH or DnsProtocol.DoH3
                    ? BuildDohUrl(targetHost, port, dohPath)
                    : null;

                string id = string.Create(
                    CultureInfo.InvariantCulture,
                    $"ddr_{targetHost}_{protocol}_{++index}");

                candidates.Add(new DnsServerEntry
                {
                    Id = id,
                    Name = !string.IsNullOrWhiteSpace(sourceResolverName)
                        ? string.Create(CultureInfo.InvariantCulture, $"{sourceResolverName} (DDR {protocol})")
                        : string.Create(CultureInfo.InvariantCulture, $"{targetHost} ({protocol})"),
                    Provider = targetHost,
                    Protocol = protocol,
                    TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                    PrimaryIp = primaryIp,
                    SecondaryIp = secondaryIp,
                    DohUrl = dohUrl,
                    DotHost = targetHost,
                    BootstrapIps = bootstrapIps,
                    Port = port,
                    Category = "DDR",
                    Tags = ["ddr", "rfc9462", protocol.ToString()],
                    Description = string.Create(CultureInfo.InvariantCulture, $"Discovered via RFC 9462 DDR ({targetHost})"),
                    IsBuiltin = false
                });
            }
        }

        return candidates;
    }

    private static List<DnsProtocol> MapAlpnToProtocols(IReadOnlyList<string> alpnIds)
    {
        List<DnsProtocol> protocols = [];
        foreach (string alpn in alpnIds)
        {
            DnsProtocol? mapped = alpn switch
            {
                "h3" => DnsProtocol.DoH3,
                "h2" => DnsProtocol.DoH,
                "dot" => DnsProtocol.DoT,
                "doq" => DnsProtocol.DoQ,
                _ => null
            };

            if (mapped.HasValue && !protocols.Contains(mapped.Value))
            {
                protocols.Add(mapped.Value);
            }
        }

        return protocols;
    }

    private static int GetDefaultPort(DnsProtocol protocol)
    {
        return protocol is DnsProtocol.DoH or DnsProtocol.DoH3 ? 443 : 853;
    }

    private static string BuildDohUrl(string host, int port, string path)
    {
        string normalizedPath = path.StartsWith('/') ? path : string.Concat("/", path);
        string portSuffix = port == 443 ? string.Empty : string.Create(CultureInfo.InvariantCulture, $":{port}");
        return string.Concat("https://", host, portSuffix, normalizedPath);
    }

    private static string ParseDohPathTemplate(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            return "/dns-query";
        }

        string raw = System.Text.Encoding.UTF8.GetString(value);
        int templateStart = raw.IndexOf("{?", StringComparison.Ordinal);
        string cleaned = templateStart >= 0 ? raw[..templateStart] : raw;
        return string.IsNullOrWhiteSpace(cleaned) ? "/dns-query" : cleaned;
    }

    private static void AddFilteredHints(
        List<IPAddress> destination,
        IEnumerable<IPAddress> source,
        bool requirePublicHints)
    {
        foreach (IPAddress ip in source)
        {
            if (requirePublicHints && !IpSafetyInspector.IsPublicRoutable(ip))
            {
                continue;
            }

            if (!destination.Contains(ip))
            {
                destination.Add(ip);
            }
        }
    }

    private static Dictionary<string, List<IPAddress>> CollectGlueAddresses(
        IReadOnlyList<DnsResourceRecord> additionals,
        bool requirePublicHints)
    {
        Dictionary<string, List<IPAddress>> map = new(StringComparer.OrdinalIgnoreCase);
        foreach (DnsResourceRecord record in additionals)
        {
            if (record.RecordType is not DnsRecordType.A and not DnsRecordType.AAAA || record.Address is null)
            {
                continue;
            }

            if (requirePublicHints && !IpSafetyInspector.IsPublicRoutable(record.Address))
            {
                continue;
            }

            string owner = record.Name.TrimEnd('.');
            if (!map.TryGetValue(owner, out List<IPAddress>? list))
            {
                list = [];
                map[owner] = list;
            }

            list.Add(record.Address);
        }

        return map;
    }
}
