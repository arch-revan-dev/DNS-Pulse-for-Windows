using System.Text;

namespace DnsPulse.Core.Models;

/// <summary>
/// Parses and loads DNS server catalogs from the v1.5.3 <c>assets/dns_catalog_1000.tsv</c> format.
/// </summary>
public static class CatalogTsvLoader
{
    private static readonly char[] TagSeparators = [','];
    private static readonly string[] LineSeparators = ["\r\n", "\n"];

    /// <summary>
    /// Assigns the appropriate <see cref="TrustTier"/> for a built-in server entry.
    /// SNI proxy nodes are always <see cref="TrustTier.Tier4ExperimentalLab"/> and unencrypted transports
    /// never receive <see cref="TrustTier.Tier1EncryptedTrusted"/>.
    /// </summary>
    public static TrustTier AssignBuiltinTrustTier(DnsProtocol protocol, bool supportsBypass)
    {
        if (protocol == DnsProtocol.SniProxy)
        {
            return TrustTier.Tier4ExperimentalLab;
        }

        if (supportsBypass)
        {
            return TrustTier.Tier2VerifiedGeoUnlock;
        }

        return protocol is DnsProtocol.DoT
            or DnsProtocol.DoH
            or DnsProtocol.DoH3
            or DnsProtocol.DoQ
            or DnsProtocol.DnsCrypt
            or DnsProtocol.AnonymizedDnsCrypt
            or DnsProtocol.ODoH
            ? TrustTier.Tier1EncryptedTrusted
            : TrustTier.Tier3CustomOrSelfHosted;
    }

    /// <summary>
    /// Maps a catalog protocol string (including legacy <c>SNI443</c>) to <see cref="DnsProtocol"/>.
    /// </summary>
    public static DnsProtocol ParseProtocol(string rawProtocol)
    {
        ArgumentNullException.ThrowIfNull(rawProtocol);

        string trimmed = rawProtocol.Trim();
        if (string.Equals(trimmed, "SNI443", StringComparison.OrdinalIgnoreCase)
            || string.Equals(trimmed, "smartproxy", StringComparison.OrdinalIgnoreCase))
        {
            return DnsProtocol.SniProxy;
        }

        return Enum.TryParse<DnsProtocol>(trimmed, ignoreCase: true, out DnsProtocol parsed)
            ? parsed
            : DnsProtocol.Udp;
    }

    /// <summary>
    /// Loads flagship entries (optional) merged with TSV rows from a file path on disk.
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> LoadFromFile(string filePath, bool includeFlagships = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        string[] lines = File.ReadAllLines(filePath, Encoding.UTF8);
        return MergeCatalog(lines, includeFlagships);
    }

    /// <summary>
    /// Loads flagship entries (optional) merged with TSV rows from a stream.
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> LoadFromStream(Stream stream, bool includeFlagships = true)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        List<string> lines = [];
        while (reader.ReadLine() is string line)
        {
            lines.Add(line);
        }

        return MergeCatalog(lines, includeFlagships);
    }

    /// <summary>
    /// Parses TSV content text into catalog entries, skipping header lines and deduplicating by ID.
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> ParseTsvContent(string tsvContent, IReadOnlyCollection<string>? existingIds = null)
    {
        ArgumentNullException.ThrowIfNull(tsvContent);

        string[] lines = tsvContent.Split(LineSeparators, StringSplitOptions.None);
        return ParseTsvLines(lines, existingIds);
    }

    /// <summary>
    /// Parses TSV lines into catalog entries, skipping header lines and deduplicating by ID.
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> ParseTsvLines(IEnumerable<string> lines, IReadOnlyCollection<string>? existingIds = null)
    {
        ArgumentNullException.ThrowIfNull(lines);

        HashSet<string> seen = existingIds is not null
            ? new HashSet<string>(existingIds, StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);

        List<DnsServerEntry> entries = [];

        foreach (string rawLine in lines)
        {
            if (string.IsNullOrWhiteSpace(rawLine))
            {
                continue;
            }

            string[] cols = rawLine.Split('\t');
            if (cols.Length < 13)
            {
                continue;
            }

            string id = cols[0].Trim();
            if (string.IsNullOrEmpty(id) || string.Equals(id, "id", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!seen.Add(id))
            {
                continue;
            }

            DnsProtocol protocol = ParseProtocol(cols[3]);
            bool supportsBypass = string.Equals(cols[12].Trim(), "true", StringComparison.OrdinalIgnoreCase);
            string primaryIp = cols[4].Trim();
            string? secondaryIp = NullIfWhiteSpace(cols[5]);
            string? dohUrl = NullIfWhiteSpace(cols[6]);
            string? dotHost = NullIfWhiteSpace(cols[7]);
            string[] rawTags = cols[10].Split(TagSeparators, StringSplitOptions.RemoveEmptyEntries);
            List<string> tags = new(rawTags.Length);
            foreach (string rawTag in rawTags)
            {
                string trimmedTag = rawTag.Trim();
                if (trimmedTag.Length > 0)
                {
                    tags.Add(trimmedTag);
                }
            }

            entries.Add(new DnsServerEntry
            {
                Id = id,
                Name = cols[1].Trim(),
                Provider = cols[2].Trim(),
                Protocol = protocol,
                TrustTier = AssignBuiltinTrustTier(protocol, supportsBypass),
                PrimaryIp = primaryIp,
                SecondaryIp = secondaryIp,
                DohUrl = dohUrl,
                DotHost = dotHost,
                SmartProxyIp = protocol == DnsProtocol.SniProxy ? primaryIp : null,
                Port = protocol == DnsProtocol.SniProxy ? 443 : null,
                BootstrapIps = BuiltInCatalogPresets.BuildBootstrapIpList(primaryIp, secondaryIp),
                Category = cols[8].Trim(),
                Country = cols[9].Trim(),
                Tags = tags,
                Description = cols[11].Trim(),
                SupportsBypass = supportsBypass,
                IsBuiltin = true,
                IsFavorite = false,
                IsSubscription = false,
                IsFreeUnlimited = true
            });
        }

        return entries;
    }

    private static List<DnsServerEntry> MergeCatalog(IEnumerable<string> lines, bool includeFlagships)
    {
        List<DnsServerEntry> result = [];
        HashSet<string> seen = new(StringComparer.Ordinal);

        if (includeFlagships)
        {
            IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();
            foreach (DnsServerEntry flagship in flagships)
            {
                if (seen.Add(flagship.Id))
                {
                    result.Add(flagship);
                }
            }
        }

        IReadOnlyList<DnsServerEntry> tsvEntries = ParseTsvLines(lines, seen);
        result.AddRange(tsvEntries);
        return result;
    }

    private static string? NullIfWhiteSpace(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
