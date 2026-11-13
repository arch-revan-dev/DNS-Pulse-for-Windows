using System.IO;
using System.Text.Json;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;
using Xunit;

namespace DnsPulse.Tests;

public class DnsPulseTests
{
    private static string FindCatalogTsvPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "assets", "dns_catalog_1000.tsv");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return Path.Combine(AppContext.BaseDirectory, "assets", "dns_catalog_1000.tsv");
    }

    [Fact]
    public void BuiltinCatalog_Has1050PlusServers_IncludesSmartDns_NoPersonalTokens_NoDefaultFavorites()
    {
        var catalog = CatalogSeeder.LoadFullCatalog(FindCatalogTsvPath());
        Assert.True(catalog.Count >= 1050, $"Expected >= 1050 built-in servers, got {catalog.Count}");

        var json = JsonSerializer.Serialize(catalog);
        Assert.DoesNotContain("kkkrbbawqq2", json, StringComparison.OrdinalIgnoreCase);
        Assert.All(catalog, s => Assert.False(s.IsFavorite));
        Assert.All(catalog, s => Assert.False(s.IsSubscription));

        Assert.Contains(catalog, s => s.DohUrl == "https://dns.bezmezhau.com/dns-query");
        for (int i = 1; i <= 20; i++)
        {
            string expected = $"https://gemini{i}.bezmezhau.com/dns-query";
            Assert.Contains(catalog, s => s.DohUrl == expected);
        }
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.magicdns.ru/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://us.geohide.ru/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.malw.link/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.comss.one/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://xbox-dns.ru/dns-query");
        Assert.Contains(catalog, s => s.Provider.Contains("Common Network", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FilterAndSort_RespectsAllModesAndPersistedMetricsWithoutFavoriteBias()
    {
        var items = new List<DnsServerEntry>
        {
            new() { Id = "a", Name = "Beta", Category = "Smart-DNS", Protocol = DnsProtocol.DoH, IsFavorite = true, LastLatencyMs = 190, LastTps = 12, SupportsBypass = true },
            new() { Id = "b", Name = "Alpha", Category = "Smart-DNS", Protocol = DnsProtocol.DoH, IsFavorite = false, LastLatencyMs = 18, LastTps = 95, Verdict = BypassVerdict.VERIFIED_PROXY_OK, SupportsBypass = true },
            new() { Id = "c", Name = "Gamma", Category = "Скоростные", Protocol = DnsProtocol.UDP, IsFavorite = false, LastLatencyMs = 45, LastTps = 140, SupportsBypass = false }
        };

        var byPing = ServerFilterSorter.FilterAndSort(items, "Все", false, false, false, false, "", SortMode.LOWEST_PING, true);
        Assert.Equal("b", byPing[0].Id);

        var byTps = ServerFilterSorter.FilterAndSort(items, "Все", false, false, false, false, "", SortMode.HIGHEST_TPS, true);
        Assert.Equal("c", byTps[0].Id);

        var byFav = ServerFilterSorter.FilterAndSort(items, "Все", false, false, false, false, "", SortMode.FAVORITES_FIRST, true);
        Assert.Equal("a", byFav[0].Id);

        var encryptedBypass = ServerFilterSorter.FilterAndSort(items, "Smart-DNS", true, false, true, true, "alpha", SortMode.BEST, true);
        Assert.Single(encryptedBypass);
        Assert.Equal("b", encryptedBypass[0].Id);
    }

    [Fact]
    public void DnsPacketCodec_And_AntiDirectIp_And_HostsParser_WorkCorrectly()
    {
        var query = DnsPacketCodec.EncodeQuery("gemini.google.com", 1, 0x2244);
        Assert.True(query.Length > 17);

        var resp = new byte[query.Length + 16];
        Buffer.BlockCopy(query, 0, resp, 0, query.Length);
        resp[2] = 0x81; resp[3] = 0x80; resp[7] = 1;
        Buffer.BlockCopy(new byte[] { 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 255, 159, 240 }, 0, resp, query.Length, 16);

        var decoded = DnsPacketCodec.DecodeResponse(resp);
        Assert.Equal(0x2244, decoded.TransactionId);
        Assert.Equal(["192.255.159.240"], decoded.Ips);

        Assert.True(AntiDirectIpFilter.IsDirectServiceIp("142.250.185.78", "gemini.google.com"));
        Assert.False(AntiDirectIpFilter.IsDirectServiceIp("192.255.159.240", "gemini.google.com"));
        Assert.True(AntiDirectIpFilter.IsGeoBlockedRedirect(302, "https://aistudio.google.com/docs/available-regions"));

        var (verdict, _) = AntiDirectIpFilter.Classify(true, ["142.250.185.78"], true, true, 200, null, "gemini.google.com", false);
        Assert.Equal(BypassVerdict.DIRECT_NO_PROXY, verdict);

        var hosts = ServerFilterSorter.ParseDynamicHosts("0.0.0.0 doubleclick.net\n127.0.0.1 ads.google.com\n179.254.166.171 gemini.google.com");
        Assert.Equal(["gemini.google.com"], hosts);

        var queue = ServerFilterSorter.BuildRotationQueue(
        [
            new DnsServerEntry { Id = "s1", Verdict = BypassVerdict.VERIFIED_PROXY_OK, LastLatencyMs = 20 },
            new DnsServerEntry { Id = "s2", Verdict = BypassVerdict.VERIFIED_PROXY_OK, LastLatencyMs = 35 }
        ], null);
        Assert.Equal("s2", ServerFilterSorter.NextRotationId(queue, "s1"));
    }
}
