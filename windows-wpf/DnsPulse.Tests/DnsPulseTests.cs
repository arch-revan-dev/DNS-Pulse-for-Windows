using System.IO;
using System.Text.Json;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;
using DnsPulse.App.Services;
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

    [Fact]
    public void DynamicBypassRegistry_QuestionParser_MultiTokenSearch_And_DiscoveryTargets_Work()
    {
        // Built-in protected bypass registry must NEVER be empty
        Assert.True(DynamicBypassRegistry.IsBypassTargetDomain("gemini.google.com"));
        Assert.True(DynamicBypassRegistry.IsBypassTargetDomain("sub.aistudio.google.com"));
        Assert.True(DynamicBypassRegistry.IsBypassTargetDomain("open.spotify.com"));
        Assert.False(DynamicBypassRegistry.IsBypassTargetDomain("github.com"));
        Assert.False(DynamicBypassRegistry.IsValidDomainName("localhost"));

        // Question extraction & empty IPv6 NoError response
        var aaaaQuery = DnsPacketCodec.EncodeQuery("aistudio.google.com", qtype: 28, transactionId: 0x3355);
        Assert.True(BootstrapDnsResolver.TryParseQuestion(aaaaQuery, out var parsedHost, out var parsedType));
        Assert.Equal("aistudio.google.com", parsedHost);
        Assert.Equal((ushort)28, parsedType);

        var emptyReply = LocalDnsTunnelServer.BuildEmptyNoErrorResponse(aaaaQuery);
        var decodedEmpty = DnsPacketCodec.DecodeResponse(emptyReply);
        Assert.Equal((ushort)0x3355, decodedEmpty.TransactionId);
        Assert.Equal(0, decodedEmpty.Rcode);
        Assert.Empty(decodedEmpty.Ips);

        // Expanded Android direct CDN detection & geo-block body
        Assert.True(AntiDirectIpFilter.IsDirectServiceIp("34.117.59.81", "gemini.google.com"));
        Assert.True(AntiDirectIpFilter.IsDirectServiceIp("104.16.12.34", "chatgpt.com"));
        Assert.True(AntiDirectIpFilter.IsGeoBlockedBody("See https://ai.google.dev/available-regions for supported countries"));

        // Multi-token search across Country + Protocol + Name
        var multiItems = new[]
        {
            new DnsServerEntry { Id = "x1", Name = "Bezmezhau Node", Protocol = DnsProtocol.DoH, Country = "FI", DohUrl = "https://dns.bezmezhau.com/dns-query" },
            new DnsServerEntry { Id = "x2", Name = "Cloudflare", Protocol = DnsProtocol.UDP, Country = "GLOBAL", PrimaryIp = "1.1.1.1" }
        };
        var found = ServerFilterSorter.FilterAndSort(multiItems, "Все", false, false, false, false, "bez doh fi", SortMode.BEST, true);
        Assert.Single(found);
        Assert.Equal("x1", found[0].Id);

        // Discovery AUTO curated /24 subnet candidates
        var candidates = SubnetScannerService.BuildHunterCandidateIps("AUTO");
        Assert.True(candidates.Count >= 200);
        Assert.Contains("192.255.159.240", candidates);
    }

    [Fact]
    public void AppUpdateService_ParsesReleaseJson_Versions_And_Sha256Sums()
    {
        Assert.True(AppUpdateService.TryParseVersion("v1.4.2+abc123", out var parsed));
        Assert.Equal(new Version(1, 4, 2), parsed);
        Assert.True(AppUpdateService.CompareVersions(new Version(1, 4, 0), new Version(1, 3, 0)) > 0);
        Assert.Equal(0, AppUpdateService.CompareVersions(new Version(1, 3, 0), new Version(1, 3)));

        const string json = """
        {
          "tag_name": "v1.4.0",
          "html_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/tag/v1.4.0",
          "body": "Release notes",
          "assets": [
            { "name": "DNS-Pulse-win-x64-setup.exe", "url": "https://api.github.com/repos/arch-revan-dev/DNS-Pulse-for-Windows/releases/assets/101", "browser_download_url": "https://example.com/setup.exe" },
            { "name": "DnsPulse.exe", "url": "https://api.github.com/repos/arch-revan-dev/DNS-Pulse-for-Windows/releases/assets/102", "browser_download_url": "https://example.com/DnsPulse.exe" },
            { "name": "SHA256SUMS.txt", "url": "https://api.github.com/repos/arch-revan-dev/DNS-Pulse-for-Windows/releases/assets/103", "browser_download_url": "https://example.com/SHA256SUMS.txt" }
          ]
        }
        """;

        var rel = AppUpdateService.ParseReleaseJson(json);
        Assert.NotNull(rel);
        Assert.Equal("v1.4.0", rel!.VersionText);
        Assert.Equal("https://example.com/setup.exe", rel.SetupExeUrl);
        Assert.Equal("https://api.github.com/repos/arch-revan-dev/DNS-Pulse-for-Windows/releases/assets/101", rel.SetupApiUrl);
        Assert.Equal("https://example.com/DnsPulse.exe", rel.PortableExeUrl);
        Assert.Equal("https://api.github.com/repos/arch-revan-dev/DNS-Pulse-for-Windows/releases/assets/102", rel.PortableApiUrl);
        Assert.Equal("https://example.com/SHA256SUMS.txt", rel.Sha256SumsUrl);
        Assert.Equal("https://api.github.com/repos/arch-revan-dev/DNS-Pulse-for-Windows/releases/assets/103", rel.Sha256ApiUrl);

        var sums = AppUpdateService.ParseSha256Sums(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  DnsPulse.exe\n" +
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef *DNS-Pulse-win-x64-setup.exe");
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sums["DnsPulse.exe"]);
        Assert.Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", sums["DNS-Pulse-win-x64-setup.exe"]);
    }

    [Fact]
    public void Settings_Autostart_ScannerParity_And_Sni443Nodes_AreValid()
    {
        // 1. Settings persistence & normalization round-trip
        var tempDir = Path.Combine(Path.GetTempPath(), $"dnspulse-settings-{Guid.NewGuid():N}");
        try
        {
            var svc = new AppSettingsService(tempDir);
            var initial = svc.Load();
            Assert.True(initial.MinimizeToTrayOnClose);
            Assert.True(initial.BlockIpv6OnBypass);
            Assert.Equal("Emerald", initial.AccentPreset);

            initial.IsDarkTheme = false;
            initial.AccentPreset = "Violet";
            initial.CompactMode = true;
            initial.MinimizeToTrayOnClose = false;
            initial.AutoModeEnabled = true;
            initial.BootstrapDnsProvider = "8.8.8.8";
            initial.ProbeTimeoutMs = 99999;      // should clamp to 6000
            initial.BenchmarkConcurrency = 99;  // should clamp to 16
            svc.Save(initial);

            var reloaded = svc.Load();
            Assert.False(reloaded.IsDarkTheme);
            Assert.Equal("Violet", reloaded.AccentPreset);
            Assert.True(reloaded.CompactMode);
            Assert.False(reloaded.MinimizeToTrayOnClose);
            Assert.True(reloaded.AutoModeEnabled);
            Assert.Equal("8.8.8.8", reloaded.BootstrapDnsProvider);
            Assert.Equal(6000, reloaded.ProbeTimeoutMs);
            Assert.Equal(16, reloaded.BenchmarkConcurrency);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }

        // 2. Quoted autostart command with spaces & extraction
        var cmdMin = WindowsAutostartService.BuildQuotedLaunchCommand(@"C:\Program Files\DNS Pulse\DnsPulse.exe", startMinimized: true);
        Assert.Equal("\"C:\\Program Files\\DNS Pulse\\DnsPulse.exe\" --autostart --minimized", cmdMin);
        Assert.Equal(@"C:\Program Files\DNS Pulse\DnsPulse.exe", WindowsAutostartService.ExtractExecutablePath(cmdMin));

        var cmdNormal = WindowsAutostartService.BuildQuotedLaunchCommand(@"D:\Tools\DnsPulse.exe", startMinimized: false);
        Assert.Equal("\"D:\\Tools\\DnsPulse.exe\" --autostart", cmdNormal);

        // 3. Built-in Open SNI Node smartproxy:// entries from Android parity + >= 900 scanner candidates
        var catalog = CatalogSeeder.LoadFullCatalog(FindCatalogTsvPath());
        Assert.Contains(catalog, s => s.DohUrl == "smartproxy://185.236.10.37" && s.Protocol == DnsProtocol.SNI443);
        Assert.Contains(catalog, s => s.DohUrl == "smartproxy://163.5.63.112" && s.Protocol == DnsProtocol.SNI443);

        var candidates = SubnetScannerService.BuildHunterCandidateIps("AUTO");
        Assert.True(candidates.Count >= 900, $"Expected >= 900 AUTO scanner candidates, got {candidates.Count}");
        Assert.Contains("185.236.10.37", candidates);
    }

    [Fact]
    public void AutoProxy_DomainClassification_SortingWithBuiltins_And_LegacyDeduplication()
    {
        // 1. Domain classification across AI/Streaming, Gaming, and Clean Speed
        var ai = SubnetScannerService.ClassifyTargetDomain("gemini.google.com", requiresBypass: true);
        Assert.Equal("Smart-DNS", ai.Category);
        Assert.Equal("Gemini", ai.ServiceTag);

        var studio = SubnetScannerService.ClassifyTargetDomain("aistudio.google.com", requiresBypass: true);
        Assert.Equal("Smart-DNS", studio.Category);
        Assert.Equal("AIStudio", studio.ServiceTag);

        var brawl = SubnetScannerService.ClassifyTargetDomain("game.brawlstarsgame.com", requiresBypass: true);
        Assert.Equal("Игры и Регионы", brawl.Category);
        Assert.Equal("BrawlStars", brawl.ServiceTag);

        var xbox = SubnetScannerService.ClassifyTargetDomain("login.live.com", requiresBypass: true);
        Assert.Equal("Игры и Регионы", xbox.Category);
        Assert.Equal("Xbox", xbox.ServiceTag);

        var steam = SubnetScannerService.ClassifyTargetDomain("store.steampowered.com", requiresBypass: true);
        Assert.Equal("Игры и Регионы", steam.Category);
        Assert.Equal("Steam", steam.ServiceTag);

        var fast = SubnetScannerService.ClassifyTargetDomain("one.one.one.one", requiresBypass: false);
        Assert.Equal("Скоростные", fast.Category);
        Assert.Equal("CleanPing", fast.ServiceTag);

        // 2. Auto Proxy Node appears directly inside matched class alongside built-in servers
        var autoNode = new DnsServerEntry
        {
            Id = "auto_proxy_185_236_10_37",
            Name = "Auto Proxy Node 185.236.10.37",
            Protocol = DnsProtocol.SNI443,
            PrimaryIp = "185.236.10.37",
            SmartProxyIp = "185.236.10.37",
            DohUrl = "smartproxy://185.236.10.37",
            Port = 443,
            Category = ai.Category,
            SupportsBypass = true,
            LastLatencyMs = 31,
            Verdict = BypassVerdict.VERIFIED_PROXY_OK
        };
        var builtinSmart = new DnsServerEntry
        {
            Id = "builtin_smart_test",
            Name = "Xbox-DNS",
            Protocol = DnsProtocol.DoH,
            DohUrl = "https://xbox-dns.ru/dns-query",
            Category = "Smart-DNS",
            IsBuiltin = true,
            SupportsBypass = true,
            LastLatencyMs = 55,
            Verdict = BypassVerdict.UNCHECKED
        };
        var ranked = ServerFilterSorter.FilterAndSort(
            new[] { builtinSmart, autoNode },
            "Smart-DNS",
            bypassOnly: true,
            favoritesOnly: false,
            encryptedOnly: false,
            freeOnly: false,
            searchQuery: "",
            sortMode: SortMode.BEST,
            hideUnsafeDirectIps: true);
        Assert.Equal(2, ranked.Count);
        Assert.Equal("auto_proxy_185_236_10_37", ranked[0].Id);

        // 3. Legacy scan_sni_* deduplication, favorite preservation, and re-classification update
        var tempDir = Path.Combine(Path.GetTempPath(), $"dnspulse-autoproxy-db-{Guid.NewGuid():N}");
        try
        {
            var repo = new DnsDatabaseRepository(tempDir);
            repo.UpsertCustomServers(new[]
            {
                new DnsServerEntry
                {
                    Id = "scan_sni_192_255_159_2",
                    Name = "Smart-Proxy SNI 192.255.159.2",
                    Protocol = DnsProtocol.SNI443,
                    PrimaryIp = "192.255.159.2",
                    SmartProxyIp = "192.255.159.2",
                    DohUrl = "smartproxy://192.255.159.2",
                    Port = 443,
                    Category = "Свои / Найденные",
                    SupportsBypass = true,
                    IsFavorite = true
                }
            });

            repo.UpsertCustomServers(new[]
            {
                new DnsServerEntry
                {
                    Id = "auto_proxy_192_255_159_2",
                    Name = "Auto Proxy Node 192.255.159.2",
                    Protocol = DnsProtocol.SNI443,
                    PrimaryIp = "192.255.159.2",
                    SmartProxyIp = "192.255.159.2",
                    DohUrl = "smartproxy://192.255.159.2",
                    Port = 443,
                    Category = "Игры и Регионы",
                    Tags = new List<string> { "AutoProxy", "SNI443", "BrawlStars" },
                    SupportsBypass = true,
                    LastLatencyMs = 28,
                    Verdict = BypassVerdict.VERIFIED_PROXY_OK,
                    VerdictReason = "Auto Proxy SNI-443 (HTTP 200, 28 мс)"
                }
            });

            var rows = repo.GetAllServers();
            Assert.DoesNotContain(rows, s => s.Id == "scan_sni_192_255_159_2");
            var migrated = Assert.Single(rows, s => s.Id == "auto_proxy_192_255_159_2");
            Assert.True(migrated.IsFavorite);
            Assert.Equal("Игры и Регионы", migrated.Category);
            Assert.Equal(28, migrated.LastLatencyMs);
            Assert.Equal(BypassVerdict.VERIFIED_PROXY_OK, migrated.Verdict);

            repo.UpsertCustomServers(new[]
            {
                new DnsServerEntry
                {
                    Id = "auto_proxy_192_255_159_2",
                    Name = "Auto Proxy Node 192.255.159.2",
                    Protocol = DnsProtocol.SNI443,
                    PrimaryIp = "192.255.159.2",
                    SmartProxyIp = "192.255.159.2",
                    DohUrl = "smartproxy://192.255.159.2",
                    Port = 443,
                    Category = "Smart-DNS",
                    Tags = new List<string> { "AutoProxy", "SNI443", "Gemini" },
                    SupportsBypass = true,
                    LastLatencyMs = 22,
                    Verdict = BypassVerdict.VERIFIED_PROXY_OK,
                    VerdictReason = "Auto Proxy SNI-443 (HTTP 200, 22 мс)"
                }
            });

            var reclassified = Assert.Single(repo.GetAllServers(), s => s.Id == "auto_proxy_192_255_159_2");
            Assert.Equal("Smart-DNS", reclassified.Category);
            Assert.Equal(22, reclassified.LastLatencyMs);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { /* ignore sqlite handle release lag */ }
        }
    }
}
