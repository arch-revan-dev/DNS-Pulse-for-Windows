using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using Microsoft.Data.Sqlite;

namespace DnsPulse.App.Data;

/// <summary>
/// SQLite-backed catalog repository (<c>%APPDATA%\DNS-Pulse\dns_pulse.db</c>) compatible with v1.5.3 schemas,
/// seeding flagships and <c>assets/dns_catalog_1000.tsv</c>, migrating legacy <c>scan_sni_*</c>/<c>scan_udp_*</c> IDs,
/// and tracking <see cref="TrustTier"/> and p50/p95 probe metrics.
/// </summary>
public sealed class PulseCatalogRepository : IDisposable
{
    public const string EmbeddedCatalogResourceName = "DnsPulse.App.assets.dns_catalog_1000.tsv";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly (string Name, string Definition)[] AdditionalSchemaColumns =
    [
        ("trustTier", "INTEGER NOT NULL DEFAULT 3"),
        ("dnsStampUri", "TEXT"),
        ("spkiPinSha256", "TEXT"),
        ("bootstrapIpsJson", "TEXT NOT NULL DEFAULT '[]'"),
        ("port", "INTEGER"),
        ("latencyP50Ms", "REAL"),
        ("latencyP95Ms", "REAL"),
        ("successRatePercent", "INTEGER"),
        ("resolvedIpsJson", "TEXT NOT NULL DEFAULT '[]'"),
        ("companionPassed", "INTEGER"),
        ("port443Ok", "INTEGER"),
        ("httpStatus", "INTEGER"),
        ("lastCheckedDomain", "TEXT"),
        ("lastCheckedAt", "TEXT")
    ];

    private readonly string _databasePath;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="PulseCatalogRepository"/> targeting <paramref name="databasePath"/>,
    /// or <c>%APPDATA%\DNS-Pulse\dns_pulse.db</c> when omitted.
    /// </summary>
    public PulseCatalogRepository(string? databasePath = null)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrWhiteSpace(appData))
            {
                appData = Path.GetTempPath();
            }

            _databasePath = Path.Combine(appData, "DNS-Pulse", "dns_pulse.db");
        }
        else
        {
            _databasePath = Path.GetFullPath(databasePath.Trim());
        }

        SqliteConnectionStringBuilder builder = new()
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        };
        _connectionString = builder.ConnectionString;
    }

    /// <summary>
    /// Gets the resolved SQLite database file path.
    /// </summary>
    public string DatabasePath => _databasePath;

    /// <summary>
    /// Ensures the SQLite schema exists (upgrading v1.5.3 tables in place), migrates and deduplicates
    /// legacy <c>scan_sni_*</c>/<c>scan_udp_*</c> rows, and seeds built-in flagships + TSV catalog entries.
    /// </summary>
    public async Task InitializeAsync(string? tsvFilePath = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? directory = Path.GetDirectoryName(_databasePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        IReadOnlyList<DnsServerEntry> seedEntries = LoadBuiltInSeedEntries(tsvFilePath);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);
            await MigrateLegacyScannedRowsAsync(connection, cancellationToken).ConfigureAwait(false);
            await SeedBuiltInServersAsync(connection, seedEntries, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Loads built-in flagship entries merged with <c>assets/dns_catalog_1000.tsv</c> (file on disk or embedded resource).
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> LoadBuiltInSeedEntries(string? tsvFilePath = null)
    {
        if (!string.IsNullOrWhiteSpace(tsvFilePath) && File.Exists(tsvFilePath))
        {
            return CatalogTsvLoader.LoadFromFile(tsvFilePath, includeFlagships: true);
        }

        string diskPath = Path.Combine(AppContext.BaseDirectory, "assets", "dns_catalog_1000.tsv");
        if (File.Exists(diskPath))
        {
            return CatalogTsvLoader.LoadFromFile(diskPath, includeFlagships: true);
        }

        Assembly assembly = typeof(PulseCatalogRepository).Assembly;
        using Stream? embeddedStream = assembly.GetManifestResourceStream(EmbeddedCatalogResourceName);
        if (embeddedStream is not null)
        {
            return CatalogTsvLoader.LoadFromStream(embeddedStream, includeFlagships: true);
        }

        return BuiltInCatalogPresets.BuildFlagshipServers();
    }

    /// <summary>
    /// Returns all persisted DNS server entries ordered by trust tier, favorite status, p50 latency, and name.
    /// </summary>
    public async Task<IReadOnlyList<DnsServerEntry>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            const string sql = """
                SELECT id, name, provider, protocol, trustTier, primaryIp, secondaryIp, dohUrl, dotHost, smartProxyIp,
                       dnsStampUri, spkiPinSha256, bootstrapIpsJson, port, category, country, tagsJson, description,
                       supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited,
                       lastLatencyMs, minLatencyMs, avgLatencyMs, latencyP50Ms, latencyP95Ms, jitterMs, lastTps,
                       successRatePercent, verdict, verdictReason, resolvedIpsJson, companionPassed, port443Ok,
                       httpStatus, lastCheckedDomain, lastCheckedAt, historyMsJson
                FROM dns_servers
                ORDER BY trustTier ASC, isFavorite DESC, COALESCE(latencyP50Ms, lastLatencyMs, 999999.0) ASC, name COLLATE NOCASE ASC;
                """;

            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            List<DnsServerEntry> items = [];
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                items.Add(ReadEntry(reader));
            }

            return items;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Returns all entries belonging to <paramref name="tier"/>.
    /// </summary>
    public async Task<IReadOnlyList<DnsServerEntry>> GetByTrustTierAsync(
        TrustTier tier,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<DnsServerEntry> all = await GetAllAsync(cancellationToken).ConfigureAwait(false);
        return [.. all.Where(entry => entry.TrustTier == tier)];
    }

    /// <summary>
    /// Retrieves a single catalog entry by its identifier, or <see langword="null"/> if absent.
    /// </summary>
    public async Task<DnsServerEntry?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            const string sql = """
                SELECT id, name, provider, protocol, trustTier, primaryIp, secondaryIp, dohUrl, dotHost, smartProxyIp,
                       dnsStampUri, spkiPinSha256, bootstrapIpsJson, port, category, country, tagsJson, description,
                       supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited,
                       lastLatencyMs, minLatencyMs, avgLatencyMs, latencyP50Ms, latencyP95Ms, jitterMs, lastTps,
                       successRatePercent, verdict, verdictReason, resolvedIpsJson, companionPassed, port443Ok,
                       httpStatus, lastCheckedDomain, lastCheckedAt, historyMsJson
                FROM dns_servers
                WHERE id = $id
                LIMIT 1;
                """;

            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.Parameters.AddWithValue("$id", id.Trim());

            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
                ? ReadEntry(reader)
                : null;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Inserts or updates a server entry in SQLite.
    /// </summary>
    public Task UpsertServerAsync(DnsServerEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return UpsertServersAsync([entry], cancellationToken);
    }

    /// <summary>
    /// Batch-upserts multiple server entries inside a single SQLite transaction.
    /// </summary>
    public async Task UpsertServersAsync(
        IEnumerable<DnsServerEntry> entries,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entries);

        List<DnsServerEntry> batch = [.. entries.Where(static e => e is not null && !string.IsNullOrWhiteSpace(e.Id))];
        if (batch.Count == 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using SqliteCommand command = CreateUpsertCommand(connection, transaction, preserveFavoriteAndMetrics: false);
                foreach (DnsServerEntry entry in batch)
                {
                    BindEntryParameters(command, entry);
                    await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Parses a <c>sdns://</c> stamp, <c>https://</c>, <c>tls://</c>, <c>quic://</c>, <c>odoh://</c>,
    /// <c>smartproxy://</c>, or raw IP endpoint via <see cref="EndpointUriParser"/> and persists it.
    /// </summary>
    public async Task<DnsServerEntry> UpsertFromEndpointOrStampAsync(
        string endpointInput,
        string? customName = null,
        TrustTier? overrideTier = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointInput);

        DnsServerEntry entry = CreateEntryFromEndpoint(endpointInput, customName, overrideTier);
        await UpsertServerAsync(entry, cancellationToken).ConfigureAwait(false);
        return entry;
    }

    /// <summary>
    /// Imports custom servers from JSON, CSV, or plain-text endpoint lines (<c>sdns://</c>, <c>https://</c>, <c>tls://</c>, <c>smartproxy://</c>, raw IP).
    /// </summary>
    public async Task<IReadOnlyList<DnsServerEntry>> ImportFromTextAsync(
        string rawContent,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawContent);

        List<DnsServerEntry> parsed = ParseImportText(rawContent);
        if (parsed.Count > 0)
        {
            await UpsertServersAsync(parsed, cancellationToken).ConfigureAwait(false);
        }

        return parsed;
    }

    /// <summary>
    /// Updates the favorite flag on an existing server entry.
    /// </summary>
    public async Task SetFavoriteAsync(
        string serverId,
        bool isFavorite,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverId);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE dns_servers SET isFavorite = $fav WHERE id = $id;";
            command.Parameters.AddWithValue("$fav", isFavorite ? 1 : 0);
            command.Parameters.AddWithValue("$id", serverId.Trim());
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Persists updated benchmark/diagnostic metrics for <paramref name="updatedEntry"/>.
    /// </summary>
    public async Task UpdateProbeMetricsAsync(
        DnsServerEntry updatedEntry,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(updatedEntry);
        ArgumentException.ThrowIfNullOrWhiteSpace(updatedEntry.Id);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            const string sql = """
                UPDATE dns_servers
                SET lastLatencyMs = $lastLatencyMs,
                    minLatencyMs = $minLatencyMs,
                    avgLatencyMs = $avgLatencyMs,
                    latencyP50Ms = $latencyP50Ms,
                    latencyP95Ms = $latencyP95Ms,
                    jitterMs = $jitterMs,
                    lastTps = $lastTps,
                    successRatePercent = $successRatePercent,
                    verdict = $verdict,
                    verdictReason = $verdictReason,
                    resolvedIpsJson = $resolvedIpsJson,
                    companionPassed = $companionPassed,
                    port443Ok = $port443Ok,
                    httpStatus = $httpStatus,
                    lastCheckedDomain = $lastCheckedDomain,
                    lastCheckedAt = $lastCheckedAt,
                    historyMsJson = $historyMsJson
                WHERE id = $id;
                """;

            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.Parameters.AddWithValue("$id", updatedEntry.Id);
            command.Parameters.AddWithValue("$lastLatencyMs", updatedEntry.LastLatencyMs.HasValue ? updatedEntry.LastLatencyMs.Value : DBNull.Value);
            command.Parameters.AddWithValue("$minLatencyMs", updatedEntry.MinLatencyMs.HasValue ? updatedEntry.MinLatencyMs.Value : DBNull.Value);
            command.Parameters.AddWithValue("$avgLatencyMs", updatedEntry.AvgLatencyMs.HasValue ? updatedEntry.AvgLatencyMs.Value : DBNull.Value);
            command.Parameters.AddWithValue("$latencyP50Ms", updatedEntry.LatencyP50Ms.HasValue ? updatedEntry.LatencyP50Ms.Value : DBNull.Value);
            command.Parameters.AddWithValue("$latencyP95Ms", updatedEntry.LatencyP95Ms.HasValue ? updatedEntry.LatencyP95Ms.Value : DBNull.Value);
            command.Parameters.AddWithValue("$jitterMs", updatedEntry.JitterMs.HasValue ? updatedEntry.JitterMs.Value : DBNull.Value);
            command.Parameters.AddWithValue("$lastTps", updatedEntry.LastTps.HasValue ? updatedEntry.LastTps.Value : DBNull.Value);
            command.Parameters.AddWithValue("$successRatePercent", updatedEntry.SuccessRatePercent.HasValue ? updatedEntry.SuccessRatePercent.Value : DBNull.Value);
            command.Parameters.AddWithValue("$verdict", updatedEntry.Verdict.ToString());
            command.Parameters.AddWithValue("$verdictReason", updatedEntry.VerdictReason ?? string.Empty);
            command.Parameters.AddWithValue("$resolvedIpsJson", JsonSerializer.Serialize(updatedEntry.ResolvedIps, JsonOptions));
            command.Parameters.AddWithValue("$companionPassed", updatedEntry.CompanionPassed.HasValue ? (updatedEntry.CompanionPassed.Value ? 1 : 0) : DBNull.Value);
            command.Parameters.AddWithValue("$port443Ok", updatedEntry.Port443Ok.HasValue ? (updatedEntry.Port443Ok.Value ? 1 : 0) : DBNull.Value);
            command.Parameters.AddWithValue("$httpStatus", updatedEntry.HttpStatus.HasValue ? updatedEntry.HttpStatus.Value : DBNull.Value);
            command.Parameters.AddWithValue("$lastCheckedDomain", (object?)updatedEntry.LastCheckedDomain ?? DBNull.Value);
            command.Parameters.AddWithValue("$lastCheckedAt", updatedEntry.LastCheckedAt.HasValue ? updatedEntry.LastCheckedAt.Value.ToString("O", CultureInfo.InvariantCulture) : DBNull.Value);
            command.Parameters.AddWithValue("$historyMsJson", JsonSerializer.Serialize(updatedEntry.HistoryMs, JsonOptions));

            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Deletes a custom (non-built-in) server entry by ID.
    /// </summary>
    public async Task<bool> DeleteCustomServerAsync(string serverId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverId);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "DELETE FROM dns_servers WHERE id = $id AND isBuiltin = 0;";
            command.Parameters.AddWithValue("$id", serverId.Trim());
            int affected = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return affected > 0;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Converts a validated <c>sdns://</c> stamp or URI/IP endpoint into a <see cref="DnsServerEntry"/>.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Server IDs canonically use lowercase protocol tags.")]
    public static DnsServerEntry CreateEntryFromEndpoint(
        string endpointInput,
        string? customName = null,
        TrustTier? overrideTier = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointInput);

        ParsedEndpoint parsed = EndpointUriParser.Parse(endpointInput.Trim());
        string idHash = ComputeShortIdHash(parsed.NormalizedEndpoint);

        if (parsed.Kind == EndpointKind.DnsStamp && parsed.Stamp is DnsStamp stamp)
        {
            DnsProtocol stampProtocol = stamp.Protocol switch
            {
                DnsStampProtocol.DoH => DnsProtocol.DoH,
                DnsStampProtocol.DoT => DnsProtocol.DoT,
                DnsStampProtocol.DoQ => DnsProtocol.DoQ,
                DnsStampProtocol.DnsCrypt => DnsProtocol.DnsCrypt,
                DnsStampProtocol.AnonymizedDnsCryptRelay => DnsProtocol.AnonymizedDnsCrypt,
                DnsStampProtocol.ObliviousDoHTarget or DnsStampProtocol.ObliviousDoHRelay => DnsProtocol.ODoH,
                _ => DnsProtocol.Udp
            };

            string host = !string.IsNullOrWhiteSpace(stamp.HostName)
                ? stamp.HostName
                : (!string.IsNullOrWhiteSpace(stamp.ProviderName) ? stamp.ProviderName : stamp.ServerAddress);

            string? dohUrl = stampProtocol == DnsProtocol.DoH && !string.IsNullOrWhiteSpace(stamp.HostName)
                ? string.Create(CultureInfo.InvariantCulture, $"https://{stamp.HostName}{(string.IsNullOrWhiteSpace(stamp.Path) ? "/dns-query" : stamp.Path)}")
                : null;

            string primaryIp = ExtractHostOnly(stamp.ServerAddress);
            TrustTier tier = overrideTier ?? (stampProtocol == DnsProtocol.Udp
                ? TrustTier.Tier3CustomOrSelfHosted
                : TrustTier.Tier3CustomOrSelfHosted);

            string? pin = !stamp.Hashes.IsDefaultOrEmpty && stamp.Hashes.Length > 0 && !stamp.Hashes[0].IsDefaultOrEmpty
                ? Convert.ToBase64String(stamp.Hashes[0].AsSpan())
                : null;

            return new DnsServerEntry
            {
                Id = string.Create(CultureInfo.InvariantCulture, $"custom_sdns_{idHash}"),
                Name = string.IsNullOrWhiteSpace(customName)
                    ? (string.IsNullOrWhiteSpace(host) ? "Imported SDNS Stamp" : host)
                    : customName.Trim(),
                Provider = "Custom Stamp",
                Protocol = stampProtocol,
                TrustTier = tier,
                PrimaryIp = IPAddress.TryParse(primaryIp, out _) ? primaryIp : string.Empty,
                DohUrl = dohUrl,
                DotHost = stampProtocol is DnsProtocol.DoT or DnsProtocol.DoQ ? ExtractHostOnly(stamp.HostName) : null,
                DnsStampUri = parsed.NormalizedEndpoint,
                SpkiPinSha256 = pin,
                BootstrapIps = [.. stamp.BootstrapIps],
                Category = "Свои / Найденные",
                Country = "CUSTOM",
                Tags = ["Custom", "SDNS"],
                Description = "Imported via sdns:// DNSCrypt stamp",
                SupportsBypass = false,
                IsBuiltin = false,
                IsFavorite = true
            };
        }

        DnsProtocol protocol = parsed.Kind switch
        {
            EndpointKind.DoH => DnsProtocol.DoH,
            EndpointKind.DoT => DnsProtocol.DoT,
            EndpointKind.DoQ => DnsProtocol.DoQ,
            EndpointKind.ObliviousDoH => DnsProtocol.ODoH,
            EndpointKind.SmartProxy => DnsProtocol.SniProxy,
            EndpointKind.PlainHttpLoopback => DnsProtocol.DoH,
            _ => DnsProtocol.Udp
        };

        TrustTier resolvedTier = overrideTier ?? (protocol == DnsProtocol.SniProxy
            ? TrustTier.Tier4ExperimentalLab
            : TrustTier.Tier3CustomOrSelfHosted);

        string displayName = !string.IsNullOrWhiteSpace(customName)
            ? customName.Trim()
            : (!string.IsNullOrWhiteSpace(parsed.Host) ? parsed.Host : parsed.NormalizedEndpoint);

        bool isSubscription = parsed.NormalizedEndpoint.Contains("/kkkr", StringComparison.OrdinalIgnoreCase);

        return new DnsServerEntry
        {
            Id = string.Create(CultureInfo.InvariantCulture, $"custom_{protocol.ToString().ToLowerInvariant()}_{idHash}"),
            Name = displayName,
            Provider = "Custom",
            Protocol = protocol,
            TrustTier = resolvedTier,
            PrimaryIp = IPAddress.TryParse(parsed.Host, out _) ? parsed.Host : string.Empty,
            DohUrl = parsed.Kind is EndpointKind.DoH or EndpointKind.PlainHttpLoopback ? parsed.NormalizedEndpoint : null,
            DotHost = parsed.Kind is EndpointKind.DoT or EndpointKind.DoQ ? parsed.Host : null,
            SmartProxyIp = parsed.Kind == EndpointKind.SmartProxy ? parsed.Host : null,
            Port = parsed.Port > 0 ? parsed.Port : null,
            Category = "Свои / Найденные",
            Country = "CUSTOM",
            Tags = isSubscription ? ["Custom", "Subscription"] : ["Custom"],
            Description = string.Create(CultureInfo.InvariantCulture, $"Imported {protocol} endpoint"),
            SupportsBypass = parsed.Kind == EndpointKind.SmartProxy,
            IsBuiltin = false,
            IsFavorite = true,
            IsSubscription = isSubscription
        };
    }

    private static List<DnsServerEntry> ParseImportText(string rawContent)
    {
        string trimmed = rawContent.Trim();
        if (trimmed.StartsWith('[') || trimmed.StartsWith('{'))
        {
            try
            {
                if (trimmed.StartsWith('['))
                {
                    List<DnsServerEntry>? list = JsonSerializer.Deserialize<List<DnsServerEntry>>(trimmed, JsonOptions);
                    if (list is not null)
                    {
                        return [.. list.Where(static e => e is not null).Select(NormalizeImportedEntry)];
                    }
                }
                else
                {
                    DnsServerEntry? single = JsonSerializer.Deserialize<DnsServerEntry>(trimmed, JsonOptions);
                    if (single is not null)
                    {
                        return [NormalizeImportedEntry(single)];
                    }
                }
            }
            catch (JsonException)
            {
                // Fall back to line-by-line parsing below.
            }
        }

        List<DnsServerEntry> results = [];
        using StringReader reader = new(trimmed);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            string clean = line.Trim();
            if (string.IsNullOrWhiteSpace(clean) || clean.StartsWith('#') || clean.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            // CSV form: name,endpoint,provider,supportsBypass
            if (clean.Contains(',', StringComparison.Ordinal) && !clean.StartsWith("sdns://", StringComparison.OrdinalIgnoreCase))
            {
                string[] parts = clean.Split(',', StringSplitOptions.TrimEntries);
                if (parts.Length >= 2 && EndpointUriParser.TryParse(parts[1], out _))
                {
                    DnsServerEntry csvEntry = CreateEntryFromEndpoint(parts[1], parts[0]);
                    if (parts.Length >= 3 && !string.IsNullOrWhiteSpace(parts[2]))
                    {
                        csvEntry = csvEntry with { Provider = parts[2] };
                    }

                    if (parts.Length >= 4 && bool.TryParse(parts[3], out bool supportsBypass))
                    {
                        csvEntry = csvEntry with
                        {
                            SupportsBypass = supportsBypass,
                            TrustTier = supportsBypass && csvEntry.Protocol != DnsProtocol.SniProxy
                                ? TrustTier.Tier2VerifiedGeoUnlock
                                : csvEntry.TrustTier
                        };
                    }

                    results.Add(csvEntry);
                    continue;
                }
            }

            // Plain text: "<endpoint> [optional name]"
            int spaceIdx = clean.IndexOfAny([' ', '\t']);
            string endpointPart = spaceIdx > 0 ? clean[..spaceIdx].Trim() : clean;
            string? namePart = spaceIdx > 0 ? clean[(spaceIdx + 1)..].Trim() : null;

            if (EndpointUriParser.TryParse(endpointPart, out _))
            {
                results.Add(CreateEntryFromEndpoint(endpointPart, namePart));
            }
        }

        return results;
    }

    private static DnsServerEntry NormalizeImportedEntry(DnsServerEntry entry)
    {
        string id = string.IsNullOrWhiteSpace(entry.Id)
            ? string.Create(CultureInfo.InvariantCulture, $"custom_{ComputeShortIdHash(entry.EndpointLabel)}")
            : entry.Id.Trim();

        TrustTier tier = entry.Protocol == DnsProtocol.SniProxy
            ? TrustTier.Tier4ExperimentalLab
            : (entry.TrustTier == default ? TrustTier.Tier3CustomOrSelfHosted : entry.TrustTier);

        return entry with
        {
            Id = id,
            TrustTier = tier,
            IsBuiltin = false
        };
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Uses compile-time constant column definitions from AdditionalSchemaColumns.")]
    private static async Task EnsureSchemaAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        const string createTableSql = """
            CREATE TABLE IF NOT EXISTS dns_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                protocol TEXT NOT NULL,
                primaryIp TEXT NOT NULL DEFAULT '',
                secondaryIp TEXT,
                dohUrl TEXT,
                dotHost TEXT,
                smartProxyIp TEXT,
                category TEXT NOT NULL,
                country TEXT NOT NULL DEFAULT 'GLOBAL',
                tagsJson TEXT NOT NULL DEFAULT '[]',
                description TEXT NOT NULL DEFAULT '',
                supportsBypass INTEGER NOT NULL DEFAULT 0,
                isBuiltin INTEGER NOT NULL DEFAULT 0,
                isFavorite INTEGER NOT NULL DEFAULT 0,
                isSubscription INTEGER NOT NULL DEFAULT 0,
                isFreeUnlimited INTEGER NOT NULL DEFAULT 1,
                lastLatencyMs REAL,
                minLatencyMs REAL,
                avgLatencyMs REAL,
                jitterMs REAL,
                lastTps REAL,
                verdict TEXT NOT NULL DEFAULT 'UNCHECKED',
                verdictReason TEXT NOT NULL DEFAULT 'Не проверялся',
                historyMsJson TEXT NOT NULL DEFAULT '[]',
                trustTier INTEGER NOT NULL DEFAULT 3,
                dnsStampUri TEXT,
                spkiPinSha256 TEXT,
                bootstrapIpsJson TEXT NOT NULL DEFAULT '[]',
                port INTEGER,
                latencyP50Ms REAL,
                latencyP95Ms REAL,
                successRatePercent INTEGER,
                resolvedIpsJson TEXT NOT NULL DEFAULT '[]',
                companionPassed INTEGER,
                port443Ok INTEGER,
                httpStatus INTEGER,
                lastCheckedDomain TEXT,
                lastCheckedAt TEXT
            );
            """;

        await using (SqliteCommand createCmd = connection.CreateCommand())
        {
            createCmd.CommandText = createTableSql;
            await createCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        HashSet<string> existingColumns = new(StringComparer.OrdinalIgnoreCase);
        await using (SqliteCommand pragmaCmd = connection.CreateCommand())
        {
            pragmaCmd.CommandText = "PRAGMA table_info(dns_servers);";
            await using SqliteDataReader reader = await pragmaCmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                existingColumns.Add(reader.GetString(1));
            }
        }

        foreach ((string colName, string colDef) in AdditionalSchemaColumns)
        {
            if (existingColumns.Contains(colName))
            {
                continue;
            }

            await using SqliteCommand alterCmd = connection.CreateCommand();
            alterCmd.CommandText = string.Create(CultureInfo.InvariantCulture, $"ALTER TABLE dns_servers ADD COLUMN {colName} {colDef};");
            await alterCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task MigrateLegacyScannedRowsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        List<(string OldId, string NewId, int IsFavorite, string Protocol, int SupportsBypass)> legacyRows = [];

        await using (SqliteCommand selectCmd = connection.CreateCommand())
        {
            selectCmd.CommandText = """
                SELECT id, isFavorite, protocol, supportsBypass
                FROM dns_servers
                WHERE id LIKE 'scan_sni_%' OR id LIKE 'scan_udp_%';
                """;
            await using SqliteDataReader reader = await selectCmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                string oldId = reader.GetString(0);
                int isFav = reader.GetInt32(1);
                string protocol = reader.GetString(2);
                int supportsBypass = reader.GetInt32(3);

                string newId = oldId.StartsWith("scan_sni_", StringComparison.Ordinal)
                    ? string.Concat("auto_proxy_", oldId["scan_sni_".Length..])
                    : string.Concat("auto_smartdns_", oldId["scan_udp_".Length..]);

                legacyRows.Add((oldId, newId, isFav, protocol, supportsBypass));
            }
        }

        if (legacyRows.Count == 0)
        {
            return;
        }

        await using SqliteTransaction tx = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            foreach ((string oldId, string newId, int isFav, string protocol, int supportsBypass) in legacyRows)
            {
                await using SqliteCommand existsCmd = connection.CreateCommand();
                existsCmd.Transaction = tx;
                existsCmd.CommandText = "SELECT COUNT(1) FROM dns_servers WHERE id = $newId;";
                existsCmd.Parameters.AddWithValue("$newId", newId);
                long existingCount = (long)(await existsCmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? 0L);

                if (existingCount > 0)
                {
                    if (isFav != 0)
                    {
                        await using SqliteCommand favCmd = connection.CreateCommand();
                        favCmd.Transaction = tx;
                        favCmd.CommandText = "UPDATE dns_servers SET isFavorite = 1 WHERE id = $newId;";
                        favCmd.Parameters.AddWithValue("$newId", newId);
                        await favCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                    }

                    await using SqliteCommand deleteCmd = connection.CreateCommand();
                    deleteCmd.Transaction = tx;
                    deleteCmd.CommandText = "DELETE FROM dns_servers WHERE id = $oldId;";
                    deleteCmd.Parameters.AddWithValue("$oldId", oldId);
                    await deleteCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    DnsProtocol parsedProtocol = CatalogTsvLoader.ParseProtocol(protocol);
                    TrustTier migratedTier = parsedProtocol == DnsProtocol.SniProxy
                        ? TrustTier.Tier4ExperimentalLab
                        : (supportsBypass != 0 ? TrustTier.Tier2VerifiedGeoUnlock : TrustTier.Tier3CustomOrSelfHosted);

                    await using SqliteCommand renameCmd = connection.CreateCommand();
                    renameCmd.Transaction = tx;
                    renameCmd.CommandText = "UPDATE dns_servers SET id = $newId, trustTier = $tier WHERE id = $oldId;";
                    renameCmd.Parameters.AddWithValue("$newId", newId);
                    renameCmd.Parameters.AddWithValue("$tier", (int)migratedTier);
                    renameCmd.Parameters.AddWithValue("$oldId", oldId);
                    await renameCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await tx.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task SeedBuiltInServersAsync(
        SqliteConnection connection,
        IReadOnlyList<DnsServerEntry> seedEntries,
        CancellationToken cancellationToken)
    {
        if (seedEntries.Count == 0)
        {
            return;
        }

        await using SqliteTransaction tx = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using SqliteCommand command = CreateUpsertCommand(connection, tx, preserveFavoriteAndMetrics: true);
            foreach (DnsServerEntry entry in seedEntries)
            {
                BindEntryParameters(command, entry);
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await tx.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    [SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Uses compile-time constant SQL clauses; all data values are bound via parameters.")]
    private static SqliteCommand CreateUpsertCommand(
        SqliteConnection connection,
        SqliteTransaction transaction,
        bool preserveFavoriteAndMetrics)
    {
        SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;

        string conflictClause = preserveFavoriteAndMetrics
            ? """
              ON CONFLICT(id) DO UPDATE SET
                  name = excluded.name,
                  provider = excluded.provider,
                  protocol = excluded.protocol,
                  trustTier = excluded.trustTier,
                  primaryIp = excluded.primaryIp,
                  secondaryIp = excluded.secondaryIp,
                  dohUrl = excluded.dohUrl,
                  dotHost = excluded.dotHost,
                  smartProxyIp = excluded.smartProxyIp,
                  dnsStampUri = excluded.dnsStampUri,
                  spkiPinSha256 = excluded.spkiPinSha256,
                  bootstrapIpsJson = excluded.bootstrapIpsJson,
                  port = excluded.port,
                  category = excluded.category,
                  country = excluded.country,
                  tagsJson = excluded.tagsJson,
                  description = excluded.description,
                  supportsBypass = excluded.supportsBypass,
                  isBuiltin = excluded.isBuiltin,
                  isSubscription = excluded.isSubscription,
                  isFreeUnlimited = excluded.isFreeUnlimited
              """
            : """
              ON CONFLICT(id) DO UPDATE SET
                  name = excluded.name,
                  provider = excluded.provider,
                  protocol = excluded.protocol,
                  trustTier = excluded.trustTier,
                  primaryIp = excluded.primaryIp,
                  secondaryIp = excluded.secondaryIp,
                  dohUrl = excluded.dohUrl,
                  dotHost = excluded.dotHost,
                  smartProxyIp = excluded.smartProxyIp,
                  dnsStampUri = excluded.dnsStampUri,
                  spkiPinSha256 = excluded.spkiPinSha256,
                  bootstrapIpsJson = excluded.bootstrapIpsJson,
                  port = excluded.port,
                  category = excluded.category,
                  country = excluded.country,
                  tagsJson = excluded.tagsJson,
                  description = excluded.description,
                  supportsBypass = excluded.supportsBypass,
                  isBuiltin = excluded.isBuiltin,
                  isFavorite = excluded.isFavorite,
                  isSubscription = excluded.isSubscription,
                  isFreeUnlimited = excluded.isFreeUnlimited,
                  lastLatencyMs = excluded.lastLatencyMs,
                  minLatencyMs = excluded.minLatencyMs,
                  avgLatencyMs = excluded.avgLatencyMs,
                  latencyP50Ms = excluded.latencyP50Ms,
                  latencyP95Ms = excluded.latencyP95Ms,
                  jitterMs = excluded.jitterMs,
                  lastTps = excluded.lastTps,
                  successRatePercent = excluded.successRatePercent,
                  verdict = excluded.verdict,
                  verdictReason = excluded.verdictReason,
                  resolvedIpsJson = excluded.resolvedIpsJson,
                  companionPassed = excluded.companionPassed,
                  port443Ok = excluded.port443Ok,
                  httpStatus = excluded.httpStatus,
                  lastCheckedDomain = excluded.lastCheckedDomain,
                  lastCheckedAt = excluded.lastCheckedAt,
                  historyMsJson = excluded.historyMsJson
              """;

        command.CommandText = $"""
            INSERT INTO dns_servers (
                id, name, provider, protocol, trustTier, primaryIp, secondaryIp, dohUrl, dotHost, smartProxyIp,
                dnsStampUri, spkiPinSha256, bootstrapIpsJson, port, category, country, tagsJson, description,
                supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited,
                lastLatencyMs, minLatencyMs, avgLatencyMs, latencyP50Ms, latencyP95Ms, jitterMs, lastTps,
                successRatePercent, verdict, verdictReason, resolvedIpsJson, companionPassed, port443Ok,
                httpStatus, lastCheckedDomain, lastCheckedAt, historyMsJson
            )
            VALUES (
                $id, $name, $provider, $protocol, $trustTier, $primaryIp, $secondaryIp, $dohUrl, $dotHost, $smartProxyIp,
                $dnsStampUri, $spkiPinSha256, $bootstrapIpsJson, $port, $category, $country, $tagsJson, $description,
                $supportsBypass, $isBuiltin, $isFavorite, $isSubscription, $isFreeUnlimited,
                $lastLatencyMs, $minLatencyMs, $avgLatencyMs, $latencyP50Ms, $latencyP95Ms, $jitterMs, $lastTps,
                $successRatePercent, $verdict, $verdictReason, $resolvedIpsJson, $companionPassed, $port443Ok,
                $httpStatus, $lastCheckedDomain, $lastCheckedAt, $historyMsJson
            )
            {conflictClause};
            """;

        command.Parameters.Add("$id", SqliteType.Text);
        command.Parameters.Add("$name", SqliteType.Text);
        command.Parameters.Add("$provider", SqliteType.Text);
        command.Parameters.Add("$protocol", SqliteType.Text);
        command.Parameters.Add("$trustTier", SqliteType.Integer);
        command.Parameters.Add("$primaryIp", SqliteType.Text);
        command.Parameters.Add("$secondaryIp", SqliteType.Text);
        command.Parameters.Add("$dohUrl", SqliteType.Text);
        command.Parameters.Add("$dotHost", SqliteType.Text);
        command.Parameters.Add("$smartProxyIp", SqliteType.Text);
        command.Parameters.Add("$dnsStampUri", SqliteType.Text);
        command.Parameters.Add("$spkiPinSha256", SqliteType.Text);
        command.Parameters.Add("$bootstrapIpsJson", SqliteType.Text);
        command.Parameters.Add("$port", SqliteType.Integer);
        command.Parameters.Add("$category", SqliteType.Text);
        command.Parameters.Add("$country", SqliteType.Text);
        command.Parameters.Add("$tagsJson", SqliteType.Text);
        command.Parameters.Add("$description", SqliteType.Text);
        command.Parameters.Add("$supportsBypass", SqliteType.Integer);
        command.Parameters.Add("$isBuiltin", SqliteType.Integer);
        command.Parameters.Add("$isFavorite", SqliteType.Integer);
        command.Parameters.Add("$isSubscription", SqliteType.Integer);
        command.Parameters.Add("$isFreeUnlimited", SqliteType.Integer);
        command.Parameters.Add("$lastLatencyMs", SqliteType.Real);
        command.Parameters.Add("$minLatencyMs", SqliteType.Real);
        command.Parameters.Add("$avgLatencyMs", SqliteType.Real);
        command.Parameters.Add("$latencyP50Ms", SqliteType.Real);
        command.Parameters.Add("$latencyP95Ms", SqliteType.Real);
        command.Parameters.Add("$jitterMs", SqliteType.Real);
        command.Parameters.Add("$lastTps", SqliteType.Real);
        command.Parameters.Add("$successRatePercent", SqliteType.Integer);
        command.Parameters.Add("$verdict", SqliteType.Text);
        command.Parameters.Add("$verdictReason", SqliteType.Text);
        command.Parameters.Add("$resolvedIpsJson", SqliteType.Text);
        command.Parameters.Add("$companionPassed", SqliteType.Integer);
        command.Parameters.Add("$port443Ok", SqliteType.Integer);
        command.Parameters.Add("$httpStatus", SqliteType.Integer);
        command.Parameters.Add("$lastCheckedDomain", SqliteType.Text);
        command.Parameters.Add("$lastCheckedAt", SqliteType.Text);
        command.Parameters.Add("$historyMsJson", SqliteType.Text);

        return command;
    }

    private static void BindEntryParameters(SqliteCommand command, DnsServerEntry entry)
    {
        command.Parameters["$id"].Value = entry.Id;
        command.Parameters["$name"].Value = entry.Name;
        command.Parameters["$provider"].Value = entry.Provider;
        command.Parameters["$protocol"].Value = entry.Protocol == DnsProtocol.SniProxy ? "SNI443" : entry.Protocol.ToString();
        command.Parameters["$trustTier"].Value = (int)entry.TrustTier;
        command.Parameters["$primaryIp"].Value = entry.PrimaryIp ?? string.Empty;
        command.Parameters["$secondaryIp"].Value = (object?)entry.SecondaryIp ?? DBNull.Value;
        command.Parameters["$dohUrl"].Value = (object?)entry.DohUrl ?? DBNull.Value;
        command.Parameters["$dotHost"].Value = (object?)entry.DotHost ?? DBNull.Value;
        command.Parameters["$smartProxyIp"].Value = (object?)entry.SmartProxyIp ?? DBNull.Value;
        command.Parameters["$dnsStampUri"].Value = (object?)entry.DnsStampUri ?? DBNull.Value;
        command.Parameters["$spkiPinSha256"].Value = (object?)entry.SpkiPinSha256 ?? DBNull.Value;
        command.Parameters["$bootstrapIpsJson"].Value = JsonSerializer.Serialize(entry.BootstrapIps, JsonOptions);
        command.Parameters["$port"].Value = entry.Port.HasValue ? entry.Port.Value : DBNull.Value;
        command.Parameters["$category"].Value = entry.Category ?? string.Empty;
        command.Parameters["$country"].Value = entry.Country ?? "GLOBAL";
        command.Parameters["$tagsJson"].Value = JsonSerializer.Serialize(entry.Tags, JsonOptions);
        command.Parameters["$description"].Value = entry.Description ?? string.Empty;
        command.Parameters["$supportsBypass"].Value = entry.SupportsBypass ? 1 : 0;
        command.Parameters["$isBuiltin"].Value = entry.IsBuiltin ? 1 : 0;
        command.Parameters["$isFavorite"].Value = entry.IsFavorite ? 1 : 0;
        command.Parameters["$isSubscription"].Value = entry.IsSubscription ? 1 : 0;
        command.Parameters["$isFreeUnlimited"].Value = entry.IsFreeUnlimited ? 1 : 0;
        command.Parameters["$lastLatencyMs"].Value = entry.LastLatencyMs.HasValue ? entry.LastLatencyMs.Value : DBNull.Value;
        command.Parameters["$minLatencyMs"].Value = entry.MinLatencyMs.HasValue ? entry.MinLatencyMs.Value : DBNull.Value;
        command.Parameters["$avgLatencyMs"].Value = entry.AvgLatencyMs.HasValue ? entry.AvgLatencyMs.Value : DBNull.Value;
        command.Parameters["$latencyP50Ms"].Value = entry.LatencyP50Ms.HasValue ? entry.LatencyP50Ms.Value : DBNull.Value;
        command.Parameters["$latencyP95Ms"].Value = entry.LatencyP95Ms.HasValue ? entry.LatencyP95Ms.Value : DBNull.Value;
        command.Parameters["$jitterMs"].Value = entry.JitterMs.HasValue ? entry.JitterMs.Value : DBNull.Value;
        command.Parameters["$lastTps"].Value = entry.LastTps.HasValue ? entry.LastTps.Value : DBNull.Value;
        command.Parameters["$successRatePercent"].Value = entry.SuccessRatePercent.HasValue ? entry.SuccessRatePercent.Value : DBNull.Value;
        command.Parameters["$verdict"].Value = entry.Verdict.ToString();
        command.Parameters["$verdictReason"].Value = entry.VerdictReason ?? string.Empty;
        command.Parameters["$resolvedIpsJson"].Value = JsonSerializer.Serialize(entry.ResolvedIps, JsonOptions);
        command.Parameters["$companionPassed"].Value = entry.CompanionPassed.HasValue ? (entry.CompanionPassed.Value ? 1 : 0) : DBNull.Value;
        command.Parameters["$port443Ok"].Value = entry.Port443Ok.HasValue ? (entry.Port443Ok.Value ? 1 : 0) : DBNull.Value;
        command.Parameters["$httpStatus"].Value = entry.HttpStatus.HasValue ? entry.HttpStatus.Value : DBNull.Value;
        command.Parameters["$lastCheckedDomain"].Value = (object?)entry.LastCheckedDomain ?? DBNull.Value;
        command.Parameters["$lastCheckedAt"].Value = entry.LastCheckedAt.HasValue ? entry.LastCheckedAt.Value.ToString("O", CultureInfo.InvariantCulture) : DBNull.Value;
        command.Parameters["$historyMsJson"].Value = JsonSerializer.Serialize(entry.HistoryMs, JsonOptions);
    }

    private static DnsServerEntry ReadEntry(SqliteDataReader reader)
    {
        DnsProtocol protocol = CatalogTsvLoader.ParseProtocol(reader.GetString(3));
        bool supportsBypass = reader.GetInt32(18) != 0;
        bool isBuiltin = reader.GetInt32(19) != 0;

        int rawTier = reader.IsDBNull(4) ? (int)TrustTier.Tier3CustomOrSelfHosted : reader.GetInt32(4);
        TrustTier trustTier = Enum.IsDefined(typeof(TrustTier), rawTier)
            ? (TrustTier)rawTier
            : (isBuiltin
                ? CatalogTsvLoader.AssignBuiltinTrustTier(protocol, supportsBypass)
                : (protocol == DnsProtocol.SniProxy ? TrustTier.Tier4ExperimentalLab : TrustTier.Tier3CustomOrSelfHosted));

        if (protocol == DnsProtocol.SniProxy)
        {
            trustTier = TrustTier.Tier4ExperimentalLab;
        }
        else if (trustTier == TrustTier.Tier1EncryptedTrusted &&
            !TrustTierPolicy.CanServeDefaultInternet(trustTier, protocol))
        {
            trustTier = TrustTier.Tier3CustomOrSelfHosted;
        }

        string verdictText = reader.IsDBNull(31) ? string.Empty : reader.GetString(31);
        DiagnosticVerdict verdict = ParseVerdict(verdictText);

        DateTimeOffset? lastCheckedAt = null;
        if (!reader.IsDBNull(38))
        {
            string rawDate = reader.GetString(38);
            if (DateTimeOffset.TryParse(rawDate, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset parsedDate))
            {
                lastCheckedAt = parsedDate;
            }
        }

        return new DnsServerEntry
        {
            Id = reader.GetString(0),
            Name = reader.GetString(1),
            Provider = reader.GetString(2),
            Protocol = protocol,
            TrustTier = trustTier,
            PrimaryIp = reader.IsDBNull(5) ? string.Empty : reader.GetString(5),
            SecondaryIp = reader.IsDBNull(6) ? null : reader.GetString(6),
            DohUrl = reader.IsDBNull(7) ? null : reader.GetString(7),
            DotHost = reader.IsDBNull(8) ? null : reader.GetString(8),
            SmartProxyIp = reader.IsDBNull(9) ? null : reader.GetString(9),
            DnsStampUri = reader.IsDBNull(10) ? null : reader.GetString(10),
            SpkiPinSha256 = reader.IsDBNull(11) ? null : reader.GetString(11),
            BootstrapIps = DeserializeStringList(reader.IsDBNull(12) ? null : reader.GetString(12)),
            Port = reader.IsDBNull(13) ? null : reader.GetInt32(13),
            Category = reader.IsDBNull(14) ? string.Empty : reader.GetString(14),
            Country = reader.IsDBNull(15) ? "GLOBAL" : reader.GetString(15),
            Tags = DeserializeStringList(reader.IsDBNull(16) ? null : reader.GetString(16)),
            Description = reader.IsDBNull(17) ? string.Empty : reader.GetString(17),
            SupportsBypass = supportsBypass,
            IsBuiltin = isBuiltin,
            IsFavorite = reader.GetInt32(20) != 0,
            IsSubscription = reader.GetInt32(21) != 0,
            IsFreeUnlimited = reader.GetInt32(22) != 0,
            LastLatencyMs = reader.IsDBNull(23) ? null : reader.GetDouble(23),
            MinLatencyMs = reader.IsDBNull(24) ? null : reader.GetDouble(24),
            AvgLatencyMs = reader.IsDBNull(25) ? null : reader.GetDouble(25),
            LatencyP50Ms = reader.IsDBNull(26) ? null : reader.GetDouble(26),
            LatencyP95Ms = reader.IsDBNull(27) ? null : reader.GetDouble(27),
            JitterMs = reader.IsDBNull(28) ? null : reader.GetDouble(28),
            LastTps = reader.IsDBNull(29) ? null : reader.GetDouble(29),
            SuccessRatePercent = reader.IsDBNull(30) ? null : reader.GetInt32(30),
            Verdict = verdict,
            VerdictReason = reader.IsDBNull(32) ? "Не проверялся" : reader.GetString(32),
            ResolvedIps = DeserializeStringList(reader.IsDBNull(33) ? null : reader.GetString(33)),
            CompanionPassed = reader.IsDBNull(34) ? null : reader.GetInt32(34) != 0,
            Port443Ok = reader.IsDBNull(35) ? null : reader.GetInt32(35) != 0,
            HttpStatus = reader.IsDBNull(36) ? null : reader.GetInt32(36),
            LastCheckedDomain = reader.IsDBNull(37) ? null : reader.GetString(37),
            LastCheckedAt = lastCheckedAt,
            HistoryMs = DeserializeIntList(reader.IsDBNull(39) ? null : reader.GetString(39))
        };
    }

    private static DiagnosticVerdict ParseVerdict(string rawVerdict)
    {
        if (string.IsNullOrWhiteSpace(rawVerdict) ||
            string.Equals(rawVerdict, "UNCHECKED", StringComparison.OrdinalIgnoreCase))
        {
            return DiagnosticVerdict.Unknown;
        }

        if (string.Equals(rawVerdict, "OK", StringComparison.OrdinalIgnoreCase))
        {
            return DiagnosticVerdict.Healthy;
        }

        if (string.Equals(rawVerdict, "GEO_BLOCKED", StringComparison.OrdinalIgnoreCase))
        {
            return DiagnosticVerdict.GeoBlockedByService;
        }

        return Enum.TryParse<DiagnosticVerdict>(rawVerdict, ignoreCase: true, out DiagnosticVerdict parsed)
            ? parsed
            : DiagnosticVerdict.Unknown;
    }

    private static List<string> DeserializeStringList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json, JsonOptions) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static List<int> DeserializeIntList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<int>>(json, JsonOptions) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string ExtractHostOnly(string? hostOrHostPort)
    {
        if (string.IsNullOrWhiteSpace(hostOrHostPort))
        {
            return string.Empty;
        }

        string trimmed = hostOrHostPort.Trim();
        if (trimmed.StartsWith('['))
        {
            int endBracket = trimmed.IndexOf(']', StringComparison.Ordinal);
            if (endBracket > 1)
            {
                return trimmed[1..endBracket];
            }
        }

        int colonIdx = trimmed.LastIndexOf(':');
        if (colonIdx > 0 && trimmed.IndexOf(':', StringComparison.Ordinal) == colonIdx)
        {
            return trimmed[..colonIdx];
        }

        return trimmed;
    }

    /// <summary>
    /// Releases internal synchronization resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Dispose();
    }

    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Hexadecimal ID hashes are canonically lowercase.")]
    private static string ComputeShortIdHash(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash.AsSpan(0, 6)).ToLowerInvariant();
    }
}
