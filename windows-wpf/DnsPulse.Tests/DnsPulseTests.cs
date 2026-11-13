using System.IO;
using System.Text.Json;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;
using DnsPulse.App.ViewModels;
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
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.astracat.ru/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.zapret.moe/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://free.shecan.ir/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.403.online/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://cloudflare-dns.com/dns-query");
        Assert.Contains(catalog, s => s.DohUrl == "https://dns.google/dns-query");
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
    public void DnsPacketCodec_TunnelResponseBuilder_And_ImportSafety_WorkCorrectly()
    {
        var query = DnsPacketCodec.EncodeQuery("gemini.google.com", 1, 0x2244);
        Assert.True(query.Length > 17);

        // Simulate query with trailing EDNS0 OPT record (11 extra bytes) and ensure tunnel response strips it cleanly
        var queryWithEdns = new byte[query.Length + 11];
        Buffer.BlockCopy(query, 0, queryWithEdns, 0, query.Length);
        queryWithEdns[11] = 1; // ARCOUNT=1

        var tunnelResp = LocalDnsTunnelServer.BuildResponsePacket(queryWithEdns, ["192.255.159.240"], 60);
        var decoded = DnsPacketCodec.DecodeResponse(tunnelResp);
        Assert.Equal(0x2244, decoded.TransactionId);
        Assert.Equal(0, decoded.Rcode);
        Assert.Equal(["192.255.159.240"], decoded.Ips);
        Assert.Equal(0, tunnelResp[11]); // ARCOUNT must be cleared

        Assert.True(AntiDirectIpFilter.IsDirectServiceIp("142.250.185.78", "gemini.google.com"));
        Assert.False(AntiDirectIpFilter.IsDirectServiceIp("192.255.159.240", "gemini.google.com"));
        Assert.True(AntiDirectIpFilter.IsGeoBlockedRedirect(302, "https://aistudio.google.com/docs/available-regions"));

        var (verdict, _) = AntiDirectIpFilter.Classify(true, ["142.250.185.78"], true, true, 200, null, "gemini.google.com", false);
        Assert.Equal(BypassVerdict.DIRECT_NO_PROXY, verdict);

        var hosts = ServerFilterSorter.ParseDynamicHosts("0.0.0.0 doubleclick.net\n127.0.0.1 ads.google.com\n179.254.166.171 gemini.google.com");
        Assert.Equal(["gemini.google.com"], hosts);

        // Malformed URL in plain-text import must not crash
        var imported = ImportExportCodec.ParseImportedServers("https://[bad-url BadNode\nhttps://dns.bezmezhau.com/dns-query ValidNode");
        Assert.Single(imported);
        Assert.Equal("ValidNode", imported[0].Name);

        var queue = ServerFilterSorter.BuildRotationQueue(
        [
            new DnsServerEntry { Id = "s1", Verdict = BypassVerdict.VERIFIED_PROXY_OK, LastLatencyMs = 20 },
            new DnsServerEntry { Id = "s2", Verdict = BypassVerdict.VERIFIED_PROXY_OK, LastLatencyMs = 35 }
        ], null);
        Assert.Equal("s2", ServerFilterSorter.NextRotationId(queue, "s1"));
    }

    [Fact]
    public void MainViewModel_MvvmCommandsAndFilters_WorkWithoutWindow()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"dnspulse-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var repo = new DnsDatabaseRepository(tempDir);
            var vm = new MainViewModel(repo);

            Assert.True(vm.TotalCatalogCount >= 1050);
            Assert.NotEmpty(vm.Categories);
            Assert.NotEmpty(vm.PresetGroups);
            Assert.NotEmpty(vm.ActivePresets);
            Assert.False(vm.IsInspectorOpen);

            vm.SelectPresetGroupCommand.Execute("streaming");
            Assert.Equal("Стриминг", vm.ActiveGroupLabel);
            Assert.Equal("open.spotify.com", vm.TargetDomain);

            var custom = new DnsServerEntry
            {
                Id = "custom_test_node",
                Name = "Custom Test Node",
                Provider = "Test",
                Protocol = DnsProtocol.DoH,
                DohUrl = "https://dns.bezmezhau.com/dns-query",
                Category = "Свои / Найденные",
                IsBuiltin = false
            };
            vm.AddCustomServer(custom);
            Assert.True(vm.IsInspectorOpen);
            Assert.Equal("custom_test_node", vm.SelectedServer?.Id);

            vm.DeleteCustomServerCommand.Execute(custom);
            Assert.False(vm.IsInspectorOpen);
            Assert.Null(vm.SelectedServer);

            vm.CloseInspectorCommand.Execute(null);
            vm.ResetFiltersCommand.Execute(null);
            Assert.Equal("Все", vm.SelectedCategory);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { /* ignore sqlite handle release lag */ }
        }
    }
}
