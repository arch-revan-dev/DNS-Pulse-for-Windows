using System.IO;
using DnsPulse.App.Data;
using DnsPulse.Core.Models;
using FluentAssertions;
using Microsoft.Data.Sqlite;

namespace DnsPulse.App.Tests.Data;

public sealed class PulseCatalogRepositoryTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;

    public PulseCatalogRepositoryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DnsPulseAppTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "dns_pulse.db");
    }

    [Fact]
    public async Task InitializeAsync_SeedsFlagshipsAndTsvWithStrictTrustTierSeparation()
    {
        using PulseCatalogRepository repository = new(_dbPath);
        await repository.InitializeAsync();

        IReadOnlyList<DnsServerEntry> all = await repository.GetAllAsync();

        all.Count.Should().BeGreaterThanOrEqualTo(1000);
        all.Where(static s => s.TrustTier == TrustTier.Tier1EncryptedTrusted)
            .Should().OnlyContain(static s => s.IsEncrypted && s.Protocol != DnsProtocol.SniProxy);
        all.Where(static s => s.Protocol == DnsProtocol.SniProxy)
            .Should().OnlyContain(static s => s.TrustTier == TrustTier.Tier4ExperimentalLab);
        all.Where(static s => s.SupportsBypass && s.Protocol != DnsProtocol.SniProxy)
            .Should().OnlyContain(static s => s.TrustTier == TrustTier.Tier2VerifiedGeoUnlock);
    }

    [Fact]
    public async Task InitializeAsync_MigratesLegacyV153SchemaAndDeduplicatesScanSniAndScanUdpRows()
    {
        string connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Pooling = false
        }.ConnectionString;

        await using (SqliteConnection conn = new(connectionString))
        {
            await conn.OpenAsync();
            await using SqliteCommand cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE dns_servers (
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
                    historyMsJson TEXT NOT NULL DEFAULT '[]'
                );

                INSERT INTO dns_servers (id, name, provider, protocol, primaryIp, smartProxyIp, category, supportsBypass, isBuiltin, isFavorite)
                VALUES ('scan_sni_192_0_2_10', 'Legacy SNI', 'Scanner', 'SNI443', '192.0.2.10', '192.0.2.10', 'Свои / Найденные', 1, 0, 1);

                INSERT INTO dns_servers (id, name, provider, protocol, primaryIp, smartProxyIp, category, supportsBypass, isBuiltin, isFavorite)
                VALUES ('auto_proxy_192_0_2_10', 'New SNI', 'Scanner', 'SNI443', '192.0.2.10', '192.0.2.10', 'Свои / Найденные', 1, 0, 0);

                INSERT INTO dns_servers (id, name, provider, protocol, primaryIp, category, supportsBypass, isBuiltin, isFavorite)
                VALUES ('scan_udp_198_51_100_20', 'Legacy SmartUDP', 'Scanner', 'UDP', '198.51.100.20', 'Smart-DNS', 1, 0, 1);
                """;
            await cmd.ExecuteNonQueryAsync();
        }

        using PulseCatalogRepository repository = new(_dbPath);
        await repository.InitializeAsync();

        (await repository.GetByIdAsync("scan_sni_192_0_2_10")).Should().BeNull();
        (await repository.GetByIdAsync("scan_udp_198_51_100_20")).Should().BeNull();

        DnsServerEntry? dedupedProxy = await repository.GetByIdAsync("auto_proxy_192_0_2_10");
        dedupedProxy.Should().NotBeNull();
        dedupedProxy!.IsFavorite.Should().BeTrue();
        dedupedProxy.TrustTier.Should().Be(TrustTier.Tier4ExperimentalLab);

        DnsServerEntry? migratedUdp = await repository.GetByIdAsync("auto_smartdns_198_51_100_20");
        migratedUdp.Should().NotBeNull();
        migratedUdp!.IsFavorite.Should().BeTrue();
        migratedUdp.TrustTier.Should().Be(TrustTier.Tier2VerifiedGeoUnlock);
    }

    [Fact]
    public async Task UpsertFromEndpointOrStampAsync_And_FavoriteToggle_PersistCorrectly()
    {
        const string cloudflareStamp = "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk";

        using PulseCatalogRepository repository = new(_dbPath);
        await repository.InitializeAsync();

        DnsServerEntry imported = await repository.UpsertFromEndpointOrStampAsync(cloudflareStamp, "My Cloudflare Stamp");
        imported.Protocol.Should().Be(DnsProtocol.DoH);
        imported.TrustTier.Should().Be(TrustTier.Tier3CustomOrSelfHosted);
        imported.DnsStampUri.Should().Be(cloudflareStamp);

        await repository.SetFavoriteAsync(imported.Id, false);
        DnsServerEntry? reloaded = await repository.GetByIdAsync(imported.Id);
        reloaded.Should().NotBeNull();
        reloaded!.IsFavorite.Should().BeFalse();

        bool deleted = await repository.DeleteCustomServerAsync(imported.Id);
        deleted.Should().BeTrue();
        (await repository.GetByIdAsync(imported.Id)).Should().BeNull();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            try
            {
                Directory.Delete(_tempDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
