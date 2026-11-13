using System.IO;
using System.Text.Json;
using DnsPulse.App.Models;
using Microsoft.Data.Sqlite;

namespace DnsPulse.App.Data;

public sealed class DnsDatabaseRepository
{
    private readonly string _dbPath;
    private readonly string _vaultPath;
    private readonly string _hostsCachePath;

    public DnsDatabaseRepository(string? customDirectory = null)
    {
        var dir = customDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "DNS-Pulse");
        Directory.CreateDirectory(dir);
        _dbPath = Path.Combine(dir, "dns_pulse.db");
        _vaultPath = Path.Combine(dir, "custom_dns_vault.json");
        _hostsCachePath = Path.Combine(dir, "dynamic_bypass_domains_cache.json");
        InitializeSchema();
    }

    private SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        return conn;
    }

    private void InitializeSchema()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
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
                historyMsJson TEXT NOT NULL DEFAULT '[]'
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public int SeedMissingBuiltins(IEnumerable<DnsServerEntry> builtins)
    {
        using var conn = OpenConnection();
        using var tx = conn.BeginTransaction();
        int added = 0;

        foreach (var s in builtins)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT OR IGNORE INTO dns_servers
                (id, name, provider, protocol, primaryIp, secondaryIp, dohUrl, dotHost, smartProxyIp, category, country, tagsJson, description, supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited)
                VALUES ($id, $name, $prov, $proto, $ip1, $ip2, $doh, $dot, $sni, $cat, $cc, $tags, $desc, $bypass, 1, 0, 0, 1);
                """;
            cmd.Parameters.AddWithValue("$id", s.Id);
            cmd.Parameters.AddWithValue("$name", s.Name);
            cmd.Parameters.AddWithValue("$prov", s.Provider);
            cmd.Parameters.AddWithValue("$proto", s.Protocol.ToString());
            cmd.Parameters.AddWithValue("$ip1", s.PrimaryIp);
            cmd.Parameters.AddWithValue("$ip2", (object?)s.SecondaryIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$doh", (object?)s.DohUrl ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$dot", (object?)s.DotHost ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sni", (object?)s.SmartProxyIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$cat", s.Category);
            cmd.Parameters.AddWithValue("$cc", s.Country);
            cmd.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(s.Tags));
            cmd.Parameters.AddWithValue("$desc", s.Description);
            cmd.Parameters.AddWithValue("$bypass", s.SupportsBypass ? 1 : 0);
            added += cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return added;
    }

    public int UpsertCustomServers(IEnumerable<DnsServerEntry> servers)
    {
        using var conn = OpenConnection();
        using var tx = conn.BeginTransaction();
        int count = 0;

        foreach (var s in servers)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO dns_servers
                (id, name, provider, protocol, primaryIp, secondaryIp, dohUrl, dotHost, smartProxyIp, category, country, tagsJson, description, supportsBypass, isBuiltin, isFavorite, isSubscription, isFreeUnlimited, lastLatencyMs, verdict, verdictReason)
                VALUES ($id, $name, $prov, $proto, $ip1, $ip2, $doh, $dot, $sni, $cat, $cc, $tags, $desc, $bypass, 0, $fav, $sub, $free, $lat, $verdict, $reason)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    provider = excluded.provider,
                    protocol = excluded.protocol,
                    primaryIp = excluded.primaryIp,
                    dohUrl = excluded.dohUrl,
                    dotHost = excluded.dotHost,
                    smartProxyIp = excluded.smartProxyIp,
                    supportsBypass = excluded.supportsBypass;
                """;
            cmd.Parameters.AddWithValue("$id", s.Id);
            cmd.Parameters.AddWithValue("$name", s.Name);
            cmd.Parameters.AddWithValue("$prov", s.Provider);
            cmd.Parameters.AddWithValue("$proto", s.Protocol.ToString());
            cmd.Parameters.AddWithValue("$ip1", s.PrimaryIp);
            cmd.Parameters.AddWithValue("$ip2", (object?)s.SecondaryIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$doh", (object?)s.DohUrl ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$dot", (object?)s.DotHost ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sni", (object?)s.SmartProxyIp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$cat", s.Category);
            cmd.Parameters.AddWithValue("$cc", s.Country);
            cmd.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(s.Tags));
            cmd.Parameters.AddWithValue("$desc", s.Description);
            cmd.Parameters.AddWithValue("$bypass", s.SupportsBypass ? 1 : 0);
            cmd.Parameters.AddWithValue("$fav", s.IsFavorite ? 1 : 0);
            cmd.Parameters.AddWithValue("$sub", s.IsSubscription ? 1 : 0);
            cmd.Parameters.AddWithValue("$free", s.IsFreeUnlimited ? 1 : 0);
            cmd.Parameters.AddWithValue("$lat", (object?)s.LastLatencyMs ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$verdict", s.Verdict.ToString());
            cmd.Parameters.AddWithValue("$reason", s.VerdictReason);
            count += cmd.ExecuteNonQuery();
        }

        tx.Commit();
        SaveCustomVault(GetAllServers());
        return count;
    }

    public void ToggleFavorite(string serverId)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE dns_servers SET isFavorite = CASE WHEN isFavorite = 1 THEN 0 ELSE 1 END WHERE id = $id;";
        cmd.Parameters.AddWithValue("$id", serverId);
        cmd.ExecuteNonQuery();
        SaveCustomVault(GetAllServers());
    }

    /// <summary>
    /// Intentionally does NOT apply ORDER BY isFavorite DESC so user sorting always works cleanly.
    /// </summary>
    public List<DnsServerEntry> GetAllServers()
    {
        var list = new List<DnsServerEntry>();
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM dns_servers;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new DnsServerEntry
            {
                Id = reader.GetString(reader.GetOrdinal("id")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                Provider = reader.GetString(reader.GetOrdinal("provider")),
                Protocol = Enum.TryParse<DnsProtocol>(reader.GetString(reader.GetOrdinal("protocol")), out var p) ? p : DnsProtocol.UDP,
                PrimaryIp = reader.GetString(reader.GetOrdinal("primaryIp")),
                SecondaryIp = reader.IsDBNull(reader.GetOrdinal("secondaryIp")) ? null : reader.GetString(reader.GetOrdinal("secondaryIp")),
                DohUrl = reader.IsDBNull(reader.GetOrdinal("dohUrl")) ? null : reader.GetString(reader.GetOrdinal("dohUrl")),
                DotHost = reader.IsDBNull(reader.GetOrdinal("dotHost")) ? null : reader.GetString(reader.GetOrdinal("dotHost")),
                SmartProxyIp = reader.IsDBNull(reader.GetOrdinal("smartProxyIp")) ? null : reader.GetString(reader.GetOrdinal("smartProxyIp")),
                Category = reader.GetString(reader.GetOrdinal("category")),
                Country = reader.GetString(reader.GetOrdinal("country")),
                Tags = JsonSerializer.Deserialize<List<string>>(reader.GetString(reader.GetOrdinal("tagsJson"))) ?? [],
                Description = reader.GetString(reader.GetOrdinal("description")),
                SupportsBypass = reader.GetInt32(reader.GetOrdinal("supportsBypass")) == 1,
                IsBuiltin = reader.GetInt32(reader.GetOrdinal("isBuiltin")) == 1,
                IsFavorite = reader.GetInt32(reader.GetOrdinal("isFavorite")) == 1,
                IsSubscription = reader.GetInt32(reader.GetOrdinal("isSubscription")) == 1,
                IsFreeUnlimited = reader.GetInt32(reader.GetOrdinal("isFreeUnlimited")) == 1,
                LastLatencyMs = reader.IsDBNull(reader.GetOrdinal("lastLatencyMs")) ? null : reader.GetDouble(reader.GetOrdinal("lastLatencyMs")),
                MinLatencyMs = reader.IsDBNull(reader.GetOrdinal("minLatencyMs")) ? null : reader.GetDouble(reader.GetOrdinal("minLatencyMs")),
                AvgLatencyMs = reader.IsDBNull(reader.GetOrdinal("avgLatencyMs")) ? null : reader.GetDouble(reader.GetOrdinal("avgLatencyMs")),
                JitterMs = reader.IsDBNull(reader.GetOrdinal("jitterMs")) ? null : reader.GetDouble(reader.GetOrdinal("jitterMs")),
                LastTps = reader.IsDBNull(reader.GetOrdinal("lastTps")) ? null : reader.GetDouble(reader.GetOrdinal("lastTps")),
                Verdict = Enum.TryParse<BypassVerdict>(reader.GetString(reader.GetOrdinal("verdict")), out var v) ? v : BypassVerdict.UNCHECKED,
                VerdictReason = reader.GetString(reader.GetOrdinal("verdictReason")),
                HistoryMs = JsonSerializer.Deserialize<List<int>>(reader.GetString(reader.GetOrdinal("historyMsJson"))) ?? []
            });
        }
        return list;
    }

    public void SaveProbeResult(ProbeResult r)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE dns_servers SET
                lastLatencyMs = $lat,
                minLatencyMs = $min,
                avgLatencyMs = $avg,
                jitterMs = $jit,
                lastTps = $tps,
                verdict = $verdict,
                verdictReason = $reason
            WHERE id = $id;
            """;
        cmd.Parameters.AddWithValue("$lat", (object?)r.LatencyMs ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$min", (object?)r.MinLatencyMs ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$avg", (object?)r.AvgLatencyMs ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$jit", (object?)r.JitterMs ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$tps", (object?)r.Tps ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$verdict", r.Verdict.ToString());
        cmd.Parameters.AddWithValue("$reason", r.VerdictReason);
        cmd.Parameters.AddWithValue("$id", r.ServerId);
        cmd.ExecuteNonQuery();
    }

    public void SaveCustomVault(IEnumerable<DnsServerEntry> servers)
    {
        var custom = servers.Where(s => !s.IsBuiltin || s.IsFavorite).ToList();
        File.WriteAllText(_vaultPath, JsonSerializer.Serialize(custom, new JsonSerializerOptions { WriteIndented = true }));
    }

    public void SaveHostsCache(IEnumerable<string> hosts)
    {
        File.WriteAllText(_hostsCachePath, JsonSerializer.Serialize(hosts.Distinct().ToList()));
    }

    public List<string> LoadHostsCache()
    {
        if (!File.Exists(_hostsCachePath)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<string>>(File.ReadAllText(_hostsCachePath)) ?? [];
        }
        catch
        {
            return [];
        }
    }
}
