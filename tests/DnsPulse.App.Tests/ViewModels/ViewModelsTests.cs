using System.IO;
using System.IO.Compression;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Recovery;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.App.Tests.ViewModels;

public sealed class ViewModelsTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;

    public ViewModelsTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DnsPulseVmTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "dns_pulse.db");
    }

    [Fact]
    public async Task OverviewViewModel_ToggleConnection_TransitionsHeroStateAndSparkline()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        OverviewViewModel vm = new(runtime, localization);

        DnsServerEntry trusted = new()
        {
            Id = "cf-doh",
            Name = "Cloudflare DoH",
            Provider = "Cloudflare",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            DohUrl = "https://cloudflare-dns.com/dns-query"
        };
        vm.ConfigureContextProviders(() => [trusted], () => new PulseAppSettings());

        vm.HeroState.Should().Be(HeroConnectionState.Disconnected);

        await vm.ToggleConnectionCommand.ExecuteAsync(null);
        vm.IsConnected.Should().BeTrue();
        vm.HeroState.Should().Be(HeroConnectionState.SmartBypassActive);

        vm.SelectStrategyProfileCommand.Execute(StrategyProfileKind.EncryptedDnsOnly);
        vm.HeroState.Should().Be(HeroConnectionState.Protected);

        for (int i = 1; i <= 35; i++)
        {
            vm.RecordLatencySample(i);
        }

        vm.P50SparklineSamples.Should().HaveCount(30);
        vm.P50SparklineSamples[0].Should().Be(6);

        await vm.ToggleConnectionCommand.ExecuteAsync(null);
        vm.IsConnected.Should().BeFalse();
        vm.HeroState.Should().Be(HeroConnectionState.Disconnected);
    }

    [Fact]
    public void RoutingInspectorViewModel_ImportsRules_CapsTelemetryAt2000_And_FiltersChips()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        RoutingInspectorViewModel vm = new(runtime, localization);

        int adguardImported = vm.ImportRulesFromText("||ads.tracker.example^\n@@||good.tracker.example^", RuleFormatKind.AdGuard);
        adguardImported.Should().Be(2);
        vm.CustomBlockRules.Should().Contain("||ads.tracker.example^");
        vm.CustomAllowRules.Should().Contain("@@||good.tracker.example^");

        int jsonImported = vm.ImportRulesFromText("""{"geoUnlock":["custom-ai.example"]}""", RuleFormatKind.Json);
        jsonImported.Should().Be(1);
        vm.CustomGeoUnlockDomains.Should().Contain("custom-ai.example");

        for (int i = 0; i < 2050; i++)
        {
            vm.AddTelemetryEvent(new DnsQueryTelemetryEvent(
                DateTimeOffset.UtcNow,
                $"host{i}.example",
                DnsRecordType.A,
                RouteZone.Zone4EncryptedTrusted,
                "Cloudflare",
                DnsProtocol.DoH,
                10,
                false,
                false,
                DnsResponseCode.NoError,
                "Trusted"));
        }

        vm.AddTelemetryEvent(new DnsQueryTelemetryEvent(
            DateTimeOffset.UtcNow,
            "gemini.google.com",
            DnsRecordType.A,
            RouteZone.Zone3GeoUnlock,
            "SmartDNS",
            DnsProtocol.DoH,
            15,
            false,
            true,
            DnsResponseCode.NoError,
            "GeoUnlock+TLS-Split"));

        vm.AddTelemetryEvent(new DnsQueryTelemetryEvent(
            DateTimeOffset.UtcNow,
            "ads.bad.example",
            DnsRecordType.A,
            RouteZone.Zone2BlockOrProtect,
            "LocalBlock",
            DnsProtocol.Udp,
            1,
            false,
            false,
            DnsResponseCode.NxDomain,
            "Blocked"));

        vm.TelemetryEvents.Should().HaveCount(RoutingInspectorViewModel.MaxTelemetryRows);

        vm.SelectFilterChipCommand.Execute(TelemetryFilterChip.GeoUnlocked);
        vm.FilteredTelemetryEvents.Should().ContainSingle(static e => e.Domain == "gemini.google.com");

        vm.SelectFilterChipCommand.Execute(TelemetryFilterChip.DpiSplit);
        vm.FilteredTelemetryEvents.Should().ContainSingle(static e => e.RewrittenSvcb);

        vm.SelectFilterChipCommand.Execute(TelemetryFilterChip.Blocked);
        vm.FilteredTelemetryEvents.Should().ContainSingle(static e => e.Domain == "ads.bad.example");
    }

    [Fact]
    public async Task ServersCatalogViewModel_FiltersTrustTiers_And_GeneratesHardenedVpsBundle()
    {
        using PulseCatalogRepository repo = new(_dbPath);
        await repo.InitializeAsync();

        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        using ServersCatalogViewModel vm = new(repo, runtime, localization);
        await vm.LoadCatalogAsync();

        vm.Tier1Servers.Should().NotBeEmpty();
        vm.Tier2Servers.Should().NotBeEmpty();
        vm.Tier4Servers.Should().NotBeEmpty();

        vm.SelectTrustTierFilterCommand.Execute(TrustTier.Tier1EncryptedTrusted);
        vm.FilteredServers.Should().OnlyContain(static s => s.TrustTier == TrustTier.Tier1EncryptedTrusted);

        // Open resolver 0.0.0.0/0 must be rejected cleanly with inline error.
        vm.VpsHostName = "dns.myvps.example";
        vm.VpsServerIp = "203.0.113.55";
        vm.VpsAllowedCidrs = "0.0.0.0/0";
        vm.GenerateVpsBundleCommand.Execute(null);
        vm.GeneratedVpsBundle.Should().BeNull();
        vm.VpsValidationError.Should().NotBeNullOrWhiteSpace();

        // Explicit client CIDR generates complete bundle and adds as Tier 3.
        vm.VpsAllowedCidrs = "198.51.100.10/32";
        vm.GenerateVpsBundleCommand.Execute(null);
        vm.VpsValidationError.Should().BeNull();
        vm.GeneratedVpsBundle.Should().NotBeNull();
        vm.GeneratedVpsBundle!.DnsStampUri.Should().StartWith("sdns://");

        await vm.AddGeneratedVpsToCatalogCommand.ExecuteAsync(null);
        vm.Tier3Servers.Should().Contain(static s => s.HostNameOrEndpointMatches("dns.myvps.example"));
    }

    [Fact]
    public async Task DiagnosticsDoctorViewModel_AppliesRemediation_EnforcesLabOptIn_And_BuildsLanQr()
    {
        using PulseCatalogRepository repo = new(_dbPath);
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        using DiagnosticsDoctorViewModel vm = new(runtime, repo, localization);

        List<string> routedDomains = [];
        vm.ConfigureTargetProvider(
            () => null,
            (domain, _) =>
            {
                routedDomains.Add(domain);
                return Task.CompletedTask;
            });

        DiagnosticReport report = new()
        {
            TargetDomain = "aistudio.google.com",
            Upstream = new DnsServerEntry { Id = "cf", Name = "Cloudflare", Protocol = DnsProtocol.DoH },
            Verdict = DiagnosticVerdict.GeoBlockedByService,
            Reason = "HTTP 403 regional block",
            Remediation = new RecommendedRemediation(
                RemediationActionKind.RouteViaVerifiedGeoUnlock,
                "Route via Tier 2",
                "Add domain to Zone 3 Geo-Unlock",
                TargetDomain: "aistudio.google.com")
        };

        vm.ApplyReport(report);
        vm.CanApplyRemediation.Should().BeTrue();

        await vm.ApplyRecommendedFixCommand.ExecuteAsync(null);
        routedDomains.Should().Contain("aistudio.google.com");

        // Lab scan must refuse to run without explicit disclaimer opt-in.
        vm.HasAcceptedLabDisclaimer = false;
        await vm.StartLabScanCommand.ExecuteAsync(null);
        vm.IsScanningLab.Should().BeFalse();

        // LAN Gateway generates QR matrix when enabled.
        vm.LanIpAddress = "192.168.1.42";
        vm.IsLanGatewayEnabled = true;
        vm.LanGateway.Should().NotBeNull();
        vm.LanGateway!.PacUrl.Should().Be("http://192.168.1.42:10809/proxy.pac");
        vm.LanGateway.PacQrMatrix.GetLength(0).Should().BeGreaterThanOrEqualTo(21);
    }

    [Fact]
    public async Task SettingsSafetyViewModel_ClampsValues_SwitchesLanguage_And_ExportsRedactedBundle()
    {
        AppSettingsStore store = new(_tempDir, _tempDir);
        WindowsAutostartService autostart = new(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest");
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        ThemeAppearanceService theme = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal = new(_tempDir);

        SettingsSafetyViewModel vm = new(
            store,
            autostart,
            runtime,
            localization,
            theme,
            journal,
            antiCheatDetector: static () => (true, ["vgc"]));

        vm.IsWfpAntiCheatBlocked.Should().BeFalse();
        vm.SelectedInterceptionMode = InterceptionMode.WfpDivertPlugin;
        vm.IsWfpAntiCheatBlocked.Should().BeTrue();
        vm.AntiCheatStatusMessage.Should().Contain("vgc");

        vm.ProbeTimeoutMs = 99999;
        vm.BenchmarkConcurrency = 99;
        vm.GitHubToken = "ghp_secret_token_1234567890";
        vm.ZeroDiskQueryLogging = true;

        await vm.SaveSettingsCommand.ExecuteAsync(null);
        vm.ProbeTimeoutMs.Should().Be(6000);
        vm.BenchmarkConcurrency.Should().Be(16);

        vm.SelectedLanguageCode = "ru-RU";
        localization.CurrentLanguageCode.Should().Be("ru-RU");

        string zipPath = Path.Combine(_tempDir, "bundle.zip");
        await vm.ExportDiagnosticBundleToPathAsync(zipPath);
        File.Exists(zipPath).Should().BeTrue();

        using ZipArchive zip = ZipFile.OpenRead(zipPath);
        ZipArchiveEntry settingsEntry = zip.GetEntry("settings.json")!;
        using StreamReader reader = new(settingsEntry.Open());
        string settingsJson = await reader.ReadToEndAsync();
        settingsJson.Should().NotContain("ghp_secret_token_1234567890");
    }

    [Fact]
    public async Task MainShellViewModel_SurfacesAdvisories_And_SwitchesAll5NavigationPages()
    {
        LocalizationService localization = new();
        IPulseRuntimeService runtime = CreateMockRuntime();
        runtime.InspectHostHealthAsync(Arg.Any<CancellationToken>()).Returns(new HostNetworkHealthSnapshot
        {
            ActiveInterfaceNames = ["Ethernet", "WireGuard"],
            Port53OccupantName = "dnscrypt-proxy",
            Port53OccupantProcessId = 4242,
            IsSmhnrDisabled = false,
            DetectedBrowserDohBypassBrowsers = ["Chrome", "Edge"]
        });

        using PulseCatalogRepository repo = new(_dbPath);
        AppSettingsStore store = new(_tempDir, _tempDir);
        ThemeAppearanceService theme = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal = new(_tempDir);
        WindowsAutostartService autostart = new(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest");

        OverviewViewModel overview = new(runtime, localization);
        RoutingInspectorViewModel routing = new(runtime, localization);
        using ServersCatalogViewModel servers = new(repo, runtime, localization);
        using DiagnosticsDoctorViewModel diagnostics = new(runtime, repo, localization);
        SettingsSafetyViewModel settings = new(store, autostart, runtime, localization, theme, journal, static () => (false, []));

        MainShellViewModel shell = new(
            localization,
            runtime,
            repo,
            store,
            theme,
            overview,
            routing,
            servers,
            diagnostics,
            settings,
            journal,
            antiCheatDetector: static () => (false, []));

        await shell.InitializeAsync();

        shell.IsInitialized.Should().BeTrue();
        shell.ShowBrowserDohBanner.Should().BeTrue();
        shell.BrowserDohBrowsersText.Should().Be("Chrome, Edge");
        shell.ShowPort53ConflictBanner.Should().BeTrue();
        shell.Port53OccupantProcessId.Should().Be(4242);
        shell.ShowVpnAdvisoryBanner.Should().BeTrue();
        shell.NavigationItems.Should().HaveCount(5);

        shell.NavigateToCommand.Execute(ShellPageKind.Diagnostics);
        shell.CurrentPageViewModel.Should().BeSameAs(diagnostics);

        localization.SetLanguage("ru-RU", updateThreadCulture: false);
        shell.NavigationItems[0].Title.Should().Be("Обзор");
    }

    private static IPulseRuntimeService CreateMockRuntime()
    {
        IPulseRuntimeService runtime = Substitute.For<IPulseRuntimeService>();
        ServiceStatusSnapshot current = new() { IsConnected = false, ActiveMode = InterceptionMode.None };
        runtime.CurrentStatus.Returns(_ => current);
        runtime.RefreshStatusAsync(Arg.Any<CancellationToken>()).Returns(_ => Task.FromResult(current));
        runtime.InspectHostHealthAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(new HostNetworkHealthSnapshot()));
        runtime.GetRecentTelemetryAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<IReadOnlyList<DnsQueryTelemetryEvent>>([]));

        runtime.ConnectAsync(
            Arg.Any<DnsServerEntry?>(),
            Arg.Any<DnsServerEntry?>(),
            Arg.Any<IReadOnlyList<DnsServerEntry>?>(),
            Arg.Any<PulseAppSettings?>(),
            Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                current = new ServiceStatusSnapshot
                {
                    IsConnected = true,
                    IsHealthy = true,
                    ActiveMode = InterceptionMode.LocalProxyPacOnly
                };
                return Task.FromResult(current);
            });

        runtime.DisconnectAsync(Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                current = new ServiceStatusSnapshot
                {
                    IsConnected = false,
                    IsHealthy = false,
                    ActiveMode = InterceptionMode.None
                };
                return Task.FromResult(current);
            });

        return runtime;
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

internal static class ServerEntryTestExtensions
{
    public static bool HostNameOrEndpointMatches(this DnsServerEntry entry, string host)
    {
        return entry.EndpointLabel.Contains(host, StringComparison.OrdinalIgnoreCase) ||
            entry.Name.Contains(host, StringComparison.OrdinalIgnoreCase);
    }
}
