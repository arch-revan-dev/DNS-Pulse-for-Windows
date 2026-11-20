using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using DnsPulse.App.Converters;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.App.ViewModels;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Feeds;
using DnsPulse.Engine.Pipeline;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Ipc;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Recovery;
using DnsPulse.Platform.Windows.Updates;
using FluentAssertions;
using NSubstitute;

namespace DnsPulse.App.Tests.ViewModels;

public sealed class ViewModelsTests : IDisposable
{
    private static readonly JsonSerializerOptions CamelCaseJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };
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
        vm.LanGateway!.PacUrl.Should().Be("http://192.168.1.42:18754/proxy.pac");
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
    public async Task SettingsSafetyViewModel_CheckAndDownloadAndInstallUpdate_TransitionsStateCleanly()
    {
        AppSettingsStore store = new(_tempDir, _tempDir);
        WindowsAutostartService autostart = new(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest");
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        localization.SetLanguage("ru-RU", updateThreadCulture: false);
        ThemeAppearanceService theme = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal = new(_tempDir);

        byte[] packageBytes = Encoding.UTF8.GetBytes("PK-simulated-portable-or-setup-binary");
        string shaHex = Convert.ToHexStringLower(SHA256.HashData(packageBytes));
        string sumsText =
            $"{shaHex}  DNS-Pulse-win-x64-setup.exe\n" +
            $"{shaHex}  DNS-Pulse-win-x64-portable.zip\n" +
            $"{shaHex}  DNS-Pulse-win-arm64-setup.exe\n" +
            $"{shaHex}  DNS-Pulse-win-arm64-portable.zip\n";

        const string releaseJson = """
            {
              "tag_name": "v2.0.2",
              "prerelease": false,
              "body": "Release 2.0.2",
              "html_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/tag/v2.0.2",
              "assets": [
                {
                  "name": "DNS-Pulse-win-x64-setup.exe",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v2.0.2/DNS-Pulse-win-x64-setup.exe"
                },
                {
                  "name": "DNS-Pulse-win-x64-portable.zip",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v2.0.2/DNS-Pulse-win-x64-portable.zip"
                },
                {
                  "name": "DNS-Pulse-win-arm64-setup.exe",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v2.0.2/DNS-Pulse-win-arm64-setup.exe"
                },
                {
                  "name": "DNS-Pulse-win-arm64-portable.zip",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v2.0.2/DNS-Pulse-win-arm64-portable.zip"
                },
                {
                  "name": "SHA256SUMS.txt",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v2.0.2/SHA256SUMS.txt"
                }
              ]
            }
            """;

        using MockUpdateHttpHandler mockHandler = new(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.EndsWith("/releases/latest", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(releaseJson, Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/SHA256SUMS.txt", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes(sumsText))
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(packageBytes)
            };
        });

        VerifiedUpdateResult? appliedResult = null;
        SettingsSafetyViewModel vm = new(
            store,
            autostart,
            runtime,
            localization,
            theme,
            journal,
            static () => (false, []),
            updateServiceFactory: () => new VerifiedAppUpdateService(
                runtime.BootstrapResolver,
                mockHandler,
                mockHandler,
                currentVersionOverride: new Version(2, 0, 0)),
            applyUpdateHandler: (res, _) =>
            {
                appliedResult = res;
                return Task.CompletedTask;
            });

        vm.IsUpdateAvailable.Should().BeFalse();
        vm.DownloadAndInstallUpdateCommand.CanExecute(null).Should().BeFalse();

        await vm.CheckForUpdatesCommand.ExecuteAsync(null);

        vm.IsUpdateAvailable.Should().BeTrue();
        vm.LatestRelease.Should().NotBeNull();
        vm.LatestRelease!.TagName.Should().Be("v2.0.2");
        vm.UpdateStatusMessage.Should().Contain("v2.0.2");
        vm.DownloadAndInstallUpdateCommand.CanExecute(null).Should().BeTrue();

        await vm.DownloadAndInstallUpdateCommand.ExecuteAsync(null);

        appliedResult.Should().NotBeNull();
        appliedResult!.Verified.Should().BeTrue();
        appliedResult.Sha256Hex.Should().Be(shaHex);
        vm.UpdateProgressPercent.Should().Be(100);
        vm.IsUpdating.Should().BeFalse();
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

    [Fact]
    public void OverviewViewModel_EnsureDefaultUpstreamsSelected_NeverPicksXboxDnsUdp53ForAi_And_QuickServicesDefaultsToAiStudio()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        using OverviewViewModel vm = new(runtime, localization);

        vm.SelectedQuickService.Should().NotBeNull();
        vm.SelectedQuickService!.Id.Should().Be("google_ai_studio");
        vm.EffectiveTargetDomain.Should().Be("aistudio.google.com");

        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();
        DnsServerEntry xboxUdp = flagships.Single(static s => s.Id == "smart_xbox_dns_udp") with
        {
            Verdict = DiagnosticVerdict.Healthy,
            LatencyP50Ms = 4.0
        };
        DnsServerEntry comssDoh = flagships.Single(static s => s.Id == "smart_comss_doh") with
        {
            Verdict = DiagnosticVerdict.Unknown,
            LatencyP50Ms = null
        };
        DnsServerEntry cloudflare = flagships.Single(static s => s.Id == "global_cloudflare_1111");

        // Even when Xbox-DNS UDP 53 appears first and has lower latency, AI Geo-Unlock must pick an AI-capable server.
        vm.EnsureDefaultUpstreamsSelected([xboxUdp, comssDoh, cloudflare]);

        vm.SelectedTrustedUpstream.Should().NotBeNull();
        vm.SelectedTrustedUpstream!.Id.Should().Be("global_cloudflare_1111");
        vm.SelectedGeoUnlockUpstream.Should().NotBeNull();
        vm.SelectedGeoUnlockUpstream!.Id.Should().Be("smart_comss_doh");

        // Even if Xbox-DNS UDP 53 was previously selected, re-validating for AI target replaces it.
        vm.SelectedGeoUnlockUpstream = xboxUdp;
        vm.EnsureDefaultUpstreamsSelected([xboxUdp, comssDoh, cloudflare]);
        vm.SelectedGeoUnlockUpstream!.Id.Should().Be("smart_comss_doh");

        // Custom quick service normalizes URLs down to the hostname.
        vm.SelectedQuickService = vm.QuickServices.Single(static q => q.Id == "custom");
        vm.CustomQuickDomain = "https://aistudio.google.com/prompts/new_chat";
        vm.IsCustomQuickServiceSelected.Should().BeTrue();
        vm.EffectiveTargetDomain.Should().Be("aistudio.google.com");
    }

    [Fact]
    public void OverviewViewModel_LatencyP50Ms_UpdatesFromSnapshotAndTelemetryEvents()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        using OverviewViewModel vm = new(runtime, localization);

        vm.LatencyP50Ms.Should().Be(0);
        vm.P50SparklineSamples.Should().BeEmpty();

        // StatusChanged with connected snapshot and real LatencyP50Ms updates LatencyP50Ms and sparkline.
        runtime.StatusChanged += Raise.EventWith(new RuntimeStatusChangedEventArgs(new ServiceStatusSnapshot
        {
            IsConnected = true,
            IsHealthy = true,
            ActiveMode = InterceptionMode.AdapterDns,
            LatencyP50Ms = 23.6
        }));

        vm.IsConnected.Should().BeTrue();
        vm.LatencyP50Ms.Should().BeApproximately(23.6, 0.01);
        vm.P50SparklineSamples.Should().ContainSingle().Which.Should().BeApproximately(23.6, 0.01);

        // TelemetryReceived events compute median latency when snapshot LatencyP50Ms is absent.
        runtime.TelemetryReceived += Raise.EventWith(new DnsQueryTelemetryEventArgs(new DnsQueryTelemetryEvent(
            DateTimeOffset.UtcNow,
            "aistudio.google.com",
            DnsRecordType.A,
            RouteZone.Zone3GeoUnlock,
            "Comss.one DNS",
            DnsProtocol.DoH,
            18.4,
            false,
            false,
            DnsResponseCode.NoError,
            "GeoUnlock")));

        vm.LatencyP50Ms.Should().BeApproximately(18.4, 0.01);
        vm.P50SparklineSamples.Should().HaveCount(2);

        runtime.TelemetryReceived += Raise.EventWith(new DnsQueryTelemetryEventArgs(new DnsQueryTelemetryEvent(
            DateTimeOffset.UtcNow,
            "gemini.google.com",
            DnsRecordType.A,
            RouteZone.Zone3GeoUnlock,
            "Comss.one DNS",
            DnsProtocol.DoH,
            26.4,
            false,
            false,
            DnsResponseCode.NoError,
            "GeoUnlock")));

        vm.LatencyP50Ms.Should().BeApproximately(22.4, 0.01);
        vm.P50SparklineSamples.Should().HaveCount(3);

        // Disconnecting resets LatencyP50Ms back to 0.
        runtime.StatusChanged += Raise.EventWith(new RuntimeStatusChangedEventArgs(new ServiceStatusSnapshot
        {
            IsConnected = false,
            IsHealthy = false,
            ActiveMode = InterceptionMode.None
        }));

        vm.IsConnected.Should().BeFalse();
        vm.LatencyP50Ms.Should().Be(0);
    }

    [Fact]
    public async Task OverviewViewModel_AutoConnectBestAndVerifyAccess_ProbesCandidates_ActivatesAiPreset_And_SetsVerificationHeadline()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        IBootstrapResolver bootstrap = Substitute.For<IBootstrapResolver>();
        IDnsUpstreamClient probeClient = Substitute.For<IDnsUpstreamClient>();
        probeClient.QueryAsync(
            Arg.Any<DnsMessage>(),
            Arg.Any<DnsServerEntry>(),
            Arg.Any<CancellationToken>())
            .Returns<UpstreamQueryResult>(_ => throw new SocketException((int)SocketError.ConnectionRefused));

        SixLayerDiagnosticEngine probeEngine = new(bootstrap, probeClient);
        runtime.CreateDiagnosticEngine().Returns(probeEngine);

        LocalizationService localization = new();
        RoutingInspectorViewModel routing = new(runtime, localization);
        ServicePresetToggleItem aiPreset = routing.ServicePresets.Single(static p => p.Id == "google_ai_studio");
        aiPreset.IsEnabled = false;

        using OverviewViewModel vm = new(runtime, localization);

        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();
        DnsServerEntry xboxUdp = flagships.Single(static s => s.Id == "smart_xbox_dns_udp") with
        {
            Verdict = DiagnosticVerdict.Healthy,
            LatencyP50Ms = 4.0
        };
        DnsServerEntry comssDoh = flagships.Single(static s => s.Id == "smart_comss_doh");
        DnsServerEntry cloudflare = flagships.Single(static s => s.Id == "global_cloudflare_1111");

        vm.ConfigureContextProviders(
            () => [xboxUdp, comssDoh, cloudflare],
            () => new PulseAppSettings { ProbeTimeoutMs = 1200 });

        string? activatedPresetId = null;
        vm.ConfigureOverviewCoordinators(
            ensureRoutingPresetHandler: async (presetId, _, ct) =>
            {
                activatedPresetId = presetId;
                await routing.EnablePresetByIdAsync(presetId, ct);
            });

        // 1. AutoConnectBest probes AI candidates (never Xbox-DNS UDP 53), activates AI preset, and reports offline probe failure truthfully.
        await vm.AutoConnectBestCommand.ExecuteAsync(null);

        activatedPresetId.Should().Be("google_ai_studio");
        aiPreset.IsEnabled.Should().BeTrue();
        aiPreset.Domains.Should().BeEquivalentTo(BuiltInCatalogPresets.BuiltinAiDomains);
        vm.SelectedGeoUnlockUpstream.Should().NotBeNull();
        vm.SelectedGeoUnlockUpstream!.Id.Should().Be("smart_comss_doh");
        vm.HasVerificationResult.Should().BeTrue();
        vm.IsTargetVerifiedWorking.Should().BeFalse();
        vm.VerificationHeadline.Should().Be(localization["Overview_Step_Failed"]);
        vm.AutoSetupProgress.Should().Be(100);

        await probeClient.Received(2).QueryAsync(
            Arg.Any<DnsMessage>(),
            Arg.Is<DnsServerEntry>(s => s.Id == "smart_comss_doh"),
            Arg.Any<CancellationToken>());
        await probeClient.DidNotReceive().QueryAsync(
            Arg.Any<DnsMessage>(),
            Arg.Is<DnsServerEntry>(s => s.Id == "smart_xbox_dns_udp"),
            Arg.Any<CancellationToken>());

        // 2. When connected and healthy without Browser DoH override, VerifyAccessNow sets VerificationHeadline to success.
        runtime.CreateDiagnosticEngine().Returns((SixLayerDiagnosticEngine)null!);
        await vm.ToggleConnectionCommand.ExecuteAsync(null);
        vm.IsConnected.Should().BeTrue();

        await vm.VerifyAccessNowCommand.ExecuteAsync(null);
        vm.HasVerificationResult.Should().BeTrue();
        vm.IsTargetVerifiedWorking.Should().BeTrue();
        vm.VerificationHeadline.Should().Be(localization["Overview_Step_Success"]);
        vm.HasDegradedCondition.Should().BeFalse();
    }

    [Fact]
    public void RoutingInspectorViewModel_EnablePresetById_EnablesPresetSynchronously()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        RoutingInspectorViewModel routing = new(runtime, localization);

        ServicePresetToggleItem aiPreset = routing.ServicePresets.Single(static p => p.Id == "google_ai_studio");
        aiPreset.Domains.Should().BeEquivalentTo(BuiltInCatalogPresets.BuiltinAiDomains);

        aiPreset.IsEnabled = false;
        routing.EnablePresetById("non_existent_preset").Should().BeFalse();
        routing.EnablePresetById("google_ai_studio").Should().BeTrue();
        aiPreset.IsEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task RoutingInspectorViewModel_EnablePresetByIdAsync_EnablesAllBuiltinAiDomainsAndPushesConfig()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        RoutingInspectorViewModel routing = new(runtime, localization);

        ServicePresetToggleItem aiPreset = routing.ServicePresets.Single(static p => p.Id == "google_ai_studio");
        aiPreset.Domains.Should().BeEquivalentTo(BuiltInCatalogPresets.BuiltinAiDomains);

        aiPreset.IsEnabled = false;
        (await routing.EnablePresetByIdAsync("non_existent_preset")).Should().BeFalse();
        bool asyncResult = await routing.EnablePresetByIdAsync("aistudio");
        asyncResult.Should().BeTrue();
        aiPreset.IsEnabled.Should().BeTrue();

        await runtime.Received().UpdateRoutingConfigAsync(
            Arg.Is<SplitNamespaceRouterConfig>(cfg =>
                BuiltInCatalogPresets.BuiltinAiDomains.All(d =>
                    cfg.GeoUnlockRules.Any(r => string.Equals(r.Pattern, d, StringComparison.OrdinalIgnoreCase)))),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task MainShellViewModel_DismissAndRestoreBanners_PersistsFlagsAcrossRefresh()
    {
        LocalizationService localization = new();
        IPulseRuntimeService runtime = CreateMockRuntime();
        runtime.InspectHostHealthAsync(Arg.Any<CancellationToken>()).Returns(new HostNetworkHealthSnapshot
        {
            ActiveInterfaceNames = ["Ethernet", "WireGuard"],
            Port53OccupantName = "ag_dns",
            Port53OccupantProcessId = 7171,
            IsSmhnrDisabled = false,
            DetectedBrowserDohBypassBrowsers = ["Chrome"]
        });

        using PulseCatalogRepository repo = new(_dbPath);
        AppSettingsStore store = new(_tempDir, _tempDir);
        ThemeAppearanceService theme = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal = new(_tempDir);
        WindowsAutostartService autostart = new(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest");

        using OverviewViewModel overview = new(runtime, localization);
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

        shell.ShowBrowserDohBanner.Should().BeTrue();
        shell.ShowPort53ConflictBanner.Should().BeTrue();
        shell.ShowVpnAdvisoryBanner.Should().BeTrue();
        shell.DismissedBannerCount.Should().Be(0);
        shell.HasDismissedBanners.Should().BeFalse();

        await shell.DismissBrowserDohBannerCommand.ExecuteAsync(null);
        await shell.DismissPort53ConflictBannerCommand.ExecuteAsync(null);
        await shell.DismissVpnAdvisoryBannerCommand.ExecuteAsync(null);

        shell.ShowBrowserDohBanner.Should().BeFalse();
        shell.ShowPort53ConflictBanner.Should().BeFalse();
        shell.ShowVpnAdvisoryBanner.Should().BeFalse();
        shell.DismissedBannerCount.Should().Be(3);
        shell.HasDismissedBanners.Should().BeTrue();

        PulseAppSettings persisted = await store.LoadAsync();
        persisted.DismissedBrowserDohBanner.Should().BeTrue();
        persisted.DismissedPort53Banner.Should().BeTrue();
        persisted.DismissedVpnBanner.Should().BeTrue();

        // Refreshing host advisories must keep dismissed banners hidden.
        await shell.RefreshHostAdvisoriesAsync();
        shell.ShowBrowserDohBanner.Should().BeFalse();
        shell.ShowPort53ConflictBanner.Should().BeFalse();
        shell.ShowVpnAdvisoryBanner.Should().BeFalse();

        // Restoring dismissed banners persists cleared flags and shows banners again.
        await shell.RestoreDismissedBannersCommand.ExecuteAsync(null);
        shell.DismissedBannerCount.Should().Be(0);
        shell.HasDismissedBanners.Should().BeFalse();
        shell.ShowBrowserDohBanner.Should().BeTrue();
        shell.ShowPort53ConflictBanner.Should().BeTrue();
        shell.ShowVpnAdvisoryBanner.Should().BeTrue();

        PulseAppSettings restored = await store.LoadAsync();
        restored.DismissedBrowserDohBanner.Should().BeFalse();
        restored.DismissedPort53Banner.Should().BeFalse();
        restored.DismissedVpnBanner.Should().BeFalse();
    }

    [Fact]
    public async Task ServersCatalogViewModel_CategoryFiltering_UpdatesFilteredServersAndCountsCleanly()
    {
        using PulseCatalogRepository repo = new(_dbPath);
        await repo.InitializeAsync();

        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        using ServersCatalogViewModel vm = new(repo, runtime, localization);
        await vm.LoadCatalogAsync();

        vm.SelectedCategoryFilter.Should().BeNull();
        vm.AllCount.Should().Be(vm.AllServers.Count);
        vm.AiGeoCount.Should().BeGreaterThan(0);
        vm.FastEncryptedCount.Should().BeGreaterThan(0);
        vm.StreamingGamingCount.Should().BeGreaterThan(0);
        vm.AutoProxyCount.Should().BeGreaterThan(0);
        vm.CustomCount.Should().BeGreaterThan(0);
        (vm.AiGeoCount + vm.FastEncryptedCount + vm.StreamingGamingCount + vm.AutoProxyCount + vm.CustomCount).Should().Be(vm.AllCount);
        vm.FilteredServers.Should().HaveCount(vm.AllCount);

        vm.CategoryFilterOptions.Should().HaveCount(6);
        vm.CategoryFilterOptions.Single(static o => o.Category is null).Count.Should().Be(vm.AllCount);
        vm.CategoryFilterOptions.Single(static o => o.Category == ServerDisplayCategory.AiAndGeoUnlock).Count.Should().Be(vm.AiGeoCount);
        vm.CategoryFilterOptions.Single(static o => o.Category == ServerDisplayCategory.FastEncrypted).Count.Should().Be(vm.FastEncryptedCount);
        vm.CategoryFilterOptions.Single(static o => o.Category == ServerDisplayCategory.StreamingAndGaming).Count.Should().Be(vm.StreamingGamingCount);
        vm.CategoryFilterOptions.Single(static o => o.Category == ServerDisplayCategory.AutoProxy).Count.Should().Be(vm.AutoProxyCount);
        vm.CategoryFilterOptions.Single(static o => o.Category == ServerDisplayCategory.CustomAndDiscovered).Count.Should().Be(vm.CustomCount);

        vm.SelectedCategoryFilter = ServerDisplayCategory.AutoProxy;
        vm.FilteredServers.Should().HaveCount(vm.AutoProxyCount);
        vm.FilteredServers.Should().OnlyContain(static s => ServerCategoryClassifier.Classify(s) == ServerDisplayCategory.AutoProxy);
        vm.FilteredServers.Should().Contain(static s => s.Protocol == DnsProtocol.SniProxy);

        LocalizationSource.Instance.Attach(localization);
        CategoryToLabelConverter categoryLabelConverter = new();
        categoryLabelConverter.Convert(ServerDisplayCategory.AutoProxy, typeof(string), "Short", System.Globalization.CultureInfo.InvariantCulture)
            .Should().Be(localization["Servers_Category_AutoProxy_Short"]);
        TrustTierToBadgeBrushConverter badgeConverter = new();
        badgeConverter.Convert(ServerDisplayCategory.AutoProxy, typeof(object), null, System.Globalization.CultureInfo.InvariantCulture)
            .Should().NotBeNull();

        vm.SelectedCategoryFilter = ServerDisplayCategory.AiAndGeoUnlock;
        vm.FilteredServers.Should().HaveCount(vm.AiGeoCount);
        vm.FilteredServers.Should().OnlyContain(static s => ServerCategoryClassifier.Classify(s) == ServerDisplayCategory.AiAndGeoUnlock);
        vm.FilteredServers.Should().Contain(static s => s.Id == "smart_comss_doh");
        vm.FilteredServers.Should().NotContain(static s => s.Id == "smart_xbox_dns_udp");

        vm.SelectedCategoryFilter = ServerDisplayCategory.FastEncrypted;
        vm.FilteredServers.Should().HaveCount(vm.FastEncryptedCount);
        vm.FilteredServers.Should().OnlyContain(static s => ServerCategoryClassifier.Classify(s) == ServerDisplayCategory.FastEncrypted);

        vm.SelectedCategoryFilter = ServerDisplayCategory.StreamingAndGaming;
        vm.FilteredServers.Should().HaveCount(vm.StreamingGamingCount);
        vm.FilteredServers.Should().OnlyContain(static s => ServerCategoryClassifier.Classify(s) == ServerDisplayCategory.StreamingAndGaming);
        vm.FilteredServers.Should().Contain(static s => s.Id == "smart_xbox_dns_udp");

        vm.SelectedCategoryFilter = ServerDisplayCategory.CustomAndDiscovered;
        vm.FilteredServers.Should().HaveCount(vm.CustomCount);
        vm.FilteredServers.Should().OnlyContain(static s => ServerCategoryClassifier.Classify(s) == ServerDisplayCategory.CustomAndDiscovered);

        vm.SelectedCategoryFilter = null;
        vm.FilteredServers.Should().HaveCount(vm.AllCount);
    }

    [Fact]
    public async Task MainShellViewModel_AutoSavesAndRestoresSettingsPortsStrategyAndRoutingAcrossRestart()
    {
        AppSettingsStore store = new(_tempDir, _tempDir);

        // Session 1: change UI settings, ports, strategy profile, and routing without clicking Save.
        IPulseRuntimeService runtime1 = CreateMockRuntime();
        LocalizationService loc1 = new();
        using PulseCatalogRepository repo1 = new(_dbPath);
        ThemeAppearanceService theme1 = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal1 = new(_tempDir);
        WindowsAutostartService autostart1 = new(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest");

        using OverviewViewModel overview1 = new(runtime1, loc1);
        RoutingInspectorViewModel routing1 = new(runtime1, loc1);
        using ServersCatalogViewModel servers1 = new(repo1, runtime1, loc1);
        using DiagnosticsDoctorViewModel diagnostics1 = new(runtime1, repo1, loc1);
        SettingsSafetyViewModel settings1 = new(store, autostart1, runtime1, loc1, theme1, journal1, static () => (false, []));

        MainShellViewModel shell1 = new(
            loc1, runtime1, repo1, store, theme1, overview1, routing1, servers1, diagnostics1, settings1, journal1,
            antiCheatDetector: static () => (false, []));

        await shell1.InitializeAsync();

        settings1.SelectedLanguageCode = "ru-RU";
        settings1.IsDarkTheme = false;
        settings1.SelectedAccentPreset = "Azure";
        settings1.LocalDnsPort = 5353;
        settings1.LocalDohPort = 8443;
        settings1.LocalProxyPort = 10888;
        settings1.LocalPacPort = 10889;
        await settings1.FlushPendingAutoSaveAsync();

        overview1.SelectStrategyProfile(StrategyProfileKind.AntiDpiHybrid);
        await Task.Delay(50);

        await routing1.EnablePresetByIdAsync("youtube");
        await routing1.AddCustomGeoUnlockDomainAsync("custom-ai.example");

        // Session 2: fresh ViewModels initialized from disk should restore all user changes.
        IPulseRuntimeService runtime2 = CreateMockRuntime();
        LocalizationService loc2 = new();
        using PulseCatalogRepository repo2 = new(_dbPath);
        ThemeAppearanceService theme2 = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal2 = new(_tempDir);
        WindowsAutostartService autostart2 = new(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest");

        using OverviewViewModel overview2 = new(runtime2, loc2);
        RoutingInspectorViewModel routing2 = new(runtime2, loc2);
        using ServersCatalogViewModel servers2 = new(repo2, runtime2, loc2);
        using DiagnosticsDoctorViewModel diagnostics2 = new(runtime2, repo2, loc2);
        SettingsSafetyViewModel settings2 = new(store, autostart2, runtime2, loc2, theme2, journal2, static () => (false, []));

        MainShellViewModel shell2 = new(
            loc2, runtime2, repo2, store, theme2, overview2, routing2, servers2, diagnostics2, settings2, journal2,
            antiCheatDetector: static () => (false, []));

        await shell2.InitializeAsync();

        settings2.SelectedLanguageCode.Should().Be("ru-RU");
        loc2.CurrentCulture.Name.Should().Be("ru-RU");
        settings2.IsDarkTheme.Should().BeFalse();
        settings2.SelectedAccentPreset.Should().Be("Azure");
        settings2.LocalDnsPort.Should().Be(5353);
        settings2.LocalDohPort.Should().Be(8443);
        settings2.LocalProxyPort.Should().Be(10888);
        settings2.LocalPacPort.Should().Be(10889);
        overview2.SelectedStrategyProfile.Should().Be(StrategyProfileKind.AntiDpiHybrid);
        routing2.ServicePresets.Single(static p => p.Id == "youtube").IsEnabled.Should().BeTrue();
        routing2.CustomGeoUnlockDomains.Should().Contain("custom-ai.example");
    }

    [Fact]
    public async Task HybridPulseRuntimeService_BindsConfiguredCustomPorts_AndNormalizesBounds()
    {
        PulseAppSettings outOfRange = new()
        {
            LocalDnsPort = -5,
            LocalDohPort = 70000,
            LocalProxyPort = 10808,
            LocalPacPort = 0
        };
        AppSettingsStore.Normalize(outOfRange);
        outOfRange.LocalDnsPort.Should().Be(0);
        outOfRange.LocalDohPort.Should().Be(65535);
        outOfRange.LocalProxyPort.Should().Be(10808);
        outOfRange.LocalPacPort.Should().Be(0);

        int dnsPort = FindAvailableDualPort();
        int dohPort = FindAvailableTcpPort();
        int proxyPort = FindAvailableTcpPort();
        int pacPort = FindAvailableTcpPort();

        NetworkSnapshotJournal journal = new(_tempDir);
        HostNetworkHealthProvider health = new(enableOsProbes: false);
        PulsePipeIpcClient unavailableIpc = new(string.Concat("DnsPulse_TestUnavailable_", Guid.NewGuid().ToString("N")), TimeSpan.FromMilliseconds(50));
        await using HybridPulseRuntimeService runtime = new(unavailableIpc, journal, health);

        PulseAppSettings customSettings = new()
        {
            InterceptionMode = InterceptionMode.LocalProxyPacOnly,
            LocalDnsPort = dnsPort,
            LocalDohPort = dohPort,
            LocalProxyPort = proxyPort,
            LocalPacPort = pacPort
        };

        ServiceStatusSnapshot connected = await runtime.ConnectAsync(null, null, null, customSettings);
        try
        {
            connected.IsConnected.Should().BeTrue();
            connected.BoundDnsPort.Should().Be(dnsPort);
            connected.BoundDoHPort.Should().Be(dohPort);
            connected.BoundProxyPort.Should().Be(proxyPort);
            connected.BoundPacPort.Should().Be(pacPort);
        }
        finally
        {
            await runtime.DisconnectAsync();
        }
    }

    [Fact]
    public async Task OverviewViewModel_IncludesSniProxyNodes_And_ChecklistEnforcesActiveInterception()
    {
        IPulseRuntimeService runtime = Substitute.For<IPulseRuntimeService>();
        SplitNamespaceRouter router = new();
        ServiceStatusSnapshot current = new()
        {
            IsConnected = true,
            IsHealthy = false,
            ActiveMode = InterceptionMode.None,
            InterceptionActive = false
        };
        runtime.Router.Returns(router);
        runtime.CurrentStatus.Returns(_ => current);
        runtime.RefreshStatusAsync(Arg.Any<CancellationToken>()).Returns(_ => Task.FromResult(current));
        runtime.GetRecentTelemetryAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<IReadOnlyList<DnsQueryTelemetryEvent>>([]));
        runtime.InspectHostHealthAsync(Arg.Any<CancellationToken>()).Returns(new HostNetworkHealthSnapshot
        {
            Port53OccupantName = "ag_dns.exe",
            Port53OccupantProcessId = 4242
        });

        DnsServerEntry sniProxyAi = new()
        {
            Id = "test_sni_ai",
            Name = "SmartProxy AI Edge",
            Protocol = DnsProtocol.SniProxy,
            TrustTier = TrustTier.Tier4ExperimentalLab,
            PrimaryIp = "198.51.100.77",
            Port = 443,
            SupportsBypass = true,
            Tags = ["AI", "AutoProxy"]
        };
        DnsServerEntry trusted = new()
        {
            Id = "global_cf",
            Name = "Cloudflare",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            PrimaryIp = "1.1.1.1",
            DohUrl = "https://1.1.1.1/dns-query"
        };

        LocalizationService localization = new();
        using OverviewViewModel vm = new(runtime, localization);
        vm.ConfigureContextProviders(() => [sniProxyAi, trusted], () => new PulseAppSettings());

        bool switchToPacInvoked = false;
        vm.ConfigureOverviewCoordinators(switchToSafeProxyModeHandler: _ =>
        {
            switchToPacInvoked = true;
            return Task.CompletedTask;
        });

        // SniProxy / Auto Proxy nodes are no longer filtered out of Geo-Unlock upstream selection.
        vm.EnsureDefaultUpstreamsSelected([sniProxyAi, trusted]);
        vm.SelectedGeoUnlockUpstream.Should().NotBeNull();
        vm.SelectedGeoUnlockUpstream!.Id.Should().Be("test_sni_ai");

        // Connected socket with ActiveMode == InterceptionMode.None must NOT claim Protected/Working.
        await vm.VerifyAccessNowCommand.ExecuteAsync(null);
        vm.IsChecklistDnsHooked.Should().BeFalse();
        vm.IsTargetVerifiedWorking.Should().BeFalse();
        vm.HasDegradedCondition.Should().BeTrue();
        vm.NeedsPort53FallbackAction.Should().BeTrue();
        vm.Port53ConflictSummaryText.Should().Contain("ag_dns.exe");

        await vm.SwitchToSafeProxyModeCommand.ExecuteAsync(null);
        switchToPacInvoked.Should().BeTrue();
    }

    [Fact]
    public async Task MainShellViewModel_ConsolidatedBanner_Expands_And_DismissAllClearsAllActiveBanners()
    {
        LocalizationService localization = new();
        IPulseRuntimeService runtime = CreateMockRuntime();
        runtime.InspectHostHealthAsync(Arg.Any<CancellationToken>()).Returns(new HostNetworkHealthSnapshot
        {
            DetectedBrowserDohBypassBrowsers = ["Edge"],
            Port53OccupantName = "ag_dns.exe",
            Port53OccupantProcessId = 3131,
            IsSmhnrDisabled = false,
            ActiveInterfaceNames = ["Ethernet", "WireGuard Tunnel"]
        });

        using PulseCatalogRepository repo = new(_dbPath);
        AppSettingsStore store = new(_tempDir, _tempDir);
        await store.SaveAsync(new PulseAppSettings { AutoSyncFeedsOnStartup = false });
        ThemeAppearanceService theme = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal = new(_tempDir);

        OverviewViewModel overview = new(runtime, localization, repo);
        RoutingInspectorViewModel routing = new(runtime, localization);
        ServersCatalogViewModel servers = new(repo, runtime, localization);
        DiagnosticsDoctorViewModel diagnostics = new(runtime, repo, localization);
        SettingsSafetyViewModel settings = new(store, new WindowsAutostartService(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest"), runtime, localization, theme, journal);

        MainShellViewModel shell = new(
            localization, runtime, repo, store, theme, overview, routing, servers, diagnostics, settings, journal,
            antiCheatDetector: static () => (false, []));

        await shell.InitializeAsync();

        shell.ActiveBannerCount.Should().Be(3);
        shell.HasActiveBanners.Should().BeTrue();
        shell.HasMultipleActiveBanners.Should().BeTrue();
        shell.IsNotificationPanelExpanded.Should().BeFalse();

        shell.ToggleNotificationPanelExpandedCommand.Execute(null);
        shell.IsNotificationPanelExpanded.Should().BeTrue();

        await shell.DismissAllActiveBannersCommand.ExecuteAsync(null);

        shell.ActiveBannerCount.Should().Be(0);
        shell.HasActiveBanners.Should().BeFalse();
        shell.HasMultipleActiveBanners.Should().BeFalse();
        shell.IsNotificationPanelExpanded.Should().BeFalse();
        shell.DismissedBannerCount.Should().Be(3);
    }

    [Fact]
    public async Task MainShellViewModel_StartupFeedSync_LoadsOfflineCacheSnapshot_And_RoutesDiscoveredDomains()
    {
        LocalizationService localization = new();
        IPulseRuntimeService runtime = CreateMockRuntime();
        using PulseCatalogRepository repo = new(_dbPath);
        AppSettingsStore store = new(_tempDir, _tempDir);
        await store.SaveAsync(new PulseAppSettings { AutoSyncFeedsOnStartup = false });

        DnsServerEntry cachedServer = new()
        {
            Id = "feed_cached_comss",
            Name = "Cached Community AI DNS",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier2VerifiedGeoUnlock,
            PrimaryIp = "198.51.100.88",
            DohUrl = "https://198.51.100.88/dns-query",
            SupportsBypass = true,
            Tags = ["AI"]
        };

        FeedCacheSnapshot cacheSnapshot = new(
            DateTimeOffset.UtcNow,
            ["cached-ai.example"],
            [cachedServer]);

        string cachePath = Path.Combine(Path.GetDirectoryName(store.SettingsFilePath)!, "dynamic_bypass_domains_cache.json");
        await File.WriteAllTextAsync(cachePath, JsonSerializer.Serialize(cacheSnapshot, CamelCaseJsonOptions));

        ThemeAppearanceService theme = new(static () => false, static () => 22631);
        NetworkSnapshotJournal journal = new(_tempDir);
        OverviewViewModel overview = new(runtime, localization, repo);
        RoutingInspectorViewModel routing = new(runtime, localization);
        ServersCatalogViewModel servers = new(repo, runtime, localization);
        DiagnosticsDoctorViewModel diagnostics = new(runtime, repo, localization);
        SettingsSafetyViewModel settings = new(store, new WindowsAutostartService(@"SOFTWARE\DnsPulseTests_NonExistentRun", "DnsPulseTest"), runtime, localization, theme, journal);

        MainShellViewModel shell = new(
            localization, runtime, repo, store, theme, overview, routing, servers, diagnostics, settings, journal,
            antiCheatDetector: static () => (false, []));

        await shell.InitializeAsync();
        if (shell.LastStartupFeedSyncTask is not null)
        {
            await shell.LastStartupFeedSyncTask;
        }

        shell.Servers.AllServers.Should().Contain(static s => s.Id == "feed_cached_comss");
        shell.Routing.CustomGeoUnlockDomains.Should().Contain("cached-ai.example");
    }

    [Fact]
    public async Task HybridPulseRuntimeService_ForwardsFullConnectAndRoutingRequests_OverNamedPipe()
    {
        string pipeName = string.Concat("DnsPulse_TestPipe_", Guid.NewGuid().ToString("N"));
        ServiceConnectRequest? capturedConnect = null;
        ServiceRoutingConfigRequest? capturedRouting = null;

        await using PulsePipeIpcServer server = new((req, _) =>
        {
            if (req.Command == PipeCommandNames.Connect && !string.IsNullOrWhiteSpace(req.PayloadJson))
            {
                capturedConnect = JsonSerializer.Deserialize<ServiceConnectRequest>(req.PayloadJson, CamelCaseJsonOptions);
                ServiceStatusSnapshot connected = new()
                {
                    IsConnected = true,
                    IsHealthy = true,
                    ActiveMode = InterceptionMode.AdapterDns,
                    InterceptionActive = true,
                    BoundDnsPort = 53,
                    ActiveTrustedUpstreamId = capturedConnect?.ActiveTrustedUpstreamId,
                    ActiveGeoUnlockUpstreamId = capturedConnect?.ActiveGeoUnlockUpstreamId
                };
                return Task.FromResult(new PipeRpcResponse(req.RequestId, true, PayloadJson: JsonSerializer.Serialize(connected, CamelCaseJsonOptions)));
            }

            if (req.Command == PipeCommandNames.UpdateRoutingConfig && !string.IsNullOrWhiteSpace(req.PayloadJson))
            {
                capturedRouting = JsonSerializer.Deserialize<ServiceRoutingConfigRequest>(req.PayloadJson, CamelCaseJsonOptions);
                ServiceStatusSnapshot updated = new()
                {
                    IsConnected = true,
                    IsHealthy = true,
                    ActiveMode = InterceptionMode.AdapterDns,
                    InterceptionActive = true,
                    ActiveGeoUnlockRulesCount = capturedRouting?.RoutingConfig?.GeoUnlockRules.Count ?? 0
                };
                return Task.FromResult(new PipeRpcResponse(req.RequestId, true, PayloadJson: JsonSerializer.Serialize(updated, CamelCaseJsonOptions)));
            }

            if (req.Command == PipeCommandNames.Disconnect)
            {
                ServiceStatusSnapshot disconnected = new() { IsConnected = false, IsHealthy = false, ActiveMode = InterceptionMode.None };
                return Task.FromResult(new PipeRpcResponse(req.RequestId, true, PayloadJson: JsonSerializer.Serialize(disconnected, CamelCaseJsonOptions)));
            }

            return Task.FromResult(new PipeRpcResponse(req.RequestId, true, PayloadJson: "{}"));
        }, pipeName: pipeName);
        await server.StartAsync();

        PulsePipeIpcClient client = new(pipeName, TimeSpan.FromSeconds(2));
        NetworkSnapshotJournal journal = new(_tempDir);
        HostNetworkHealthProvider health = new(enableOsProbes: false);
        await using HybridPulseRuntimeService runtime = new(client, journal, health);

        DnsServerEntry trusted = new()
        {
            Id = "cf_trusted",
            Name = "Cloudflare",
            Protocol = DnsProtocol.DoH,
            TrustTier = TrustTier.Tier1EncryptedTrusted,
            PrimaryIp = "1.1.1.1",
            DohUrl = "https://1.1.1.1/dns-query"
        };
        DnsServerEntry geo = new()
        {
            Id = "sni_geo",
            Name = "AutoProxy Edge",
            Protocol = DnsProtocol.SniProxy,
            TrustTier = TrustTier.Tier4ExperimentalLab,
            PrimaryIp = "198.51.100.77",
            Port = 443,
            SupportsBypass = true,
            Tags = ["AI"]
        };

        await runtime.UpdateRoutingConfigAsync(new SplitNamespaceRouterConfig
        {
            GeoUnlockRules = [new GeoUnlockRule("aistudio.google.com")]
        });

        ServiceStatusSnapshot status = await runtime.ConnectAsync(
            trusted,
            geo,
            fallbackTrustedPool: [trusted],
            settings: new PulseAppSettings
            {
                InterceptionMode = InterceptionMode.AdapterDns,
                StrategyProfile = "SmartSplitDnsGeo",
                BlockIpv6OnBypass = true,
                EnableLocalTlsSplitPac = true
            });

        status.IsConnected.Should().BeTrue();
        runtime.IsServiceMode.Should().BeTrue();
        capturedConnect.Should().NotBeNull();
        capturedConnect!.InterceptionMode.Should().Be(InterceptionMode.AdapterDns);
        capturedConnect.StrategyProfile.Should().Be("SmartSplitDnsGeo");
        capturedConnect.ActiveTrustedUpstreamId.Should().Be("cf_trusted");
        capturedConnect.ActiveGeoUnlockUpstreamId.Should().Be("sni_geo");
        capturedConnect.GeoUnlockUpstreams.Should().Contain(static s => s.Id == "sni_geo");
        capturedConnect.RoutingConfig!.GeoUnlockRules.Should().ContainSingle(static r => r.Pattern == "aistudio.google.com");

        await runtime.UpdateRoutingConfigAsync(new SplitNamespaceRouterConfig
        {
            GeoUnlockRules = [new GeoUnlockRule("aistudio.google.com"), new GeoUnlockRule("chatgpt.com")]
        });

        capturedRouting.Should().NotBeNull();
        capturedRouting!.RoutingConfig!.GeoUnlockRules.Should().HaveCount(2);

        await runtime.DisconnectAsync();
    }

    [Fact]
    public void ThemeAppearanceService_AppliesDarkLightHighContrastAndCompactTokens()
    {
        ResourceDictionary resources = [];

        ThemeAppearanceService.ApplyResourceTokenOverrides(resources, Wpf.Ui.Appearance.ApplicationTheme.Dark, ThemeAccentPreset.Emerald, highContrast: false);
        resources["PulseInnerPanelBrush"].Should().NotBeNull();
        resources["PulseHeaderSurfaceBrush"].Should().NotBeNull();

        ThemeAppearanceService.ApplyResourceTokenOverrides(resources, Wpf.Ui.Appearance.ApplicationTheme.Light, ThemeAccentPreset.Azure, highContrast: false);
        System.Windows.Media.SolidColorBrush lightInner = (System.Windows.Media.SolidColorBrush)resources["PulseInnerPanelBrush"]!;
        lightInner.Color.R.Should().BeGreaterThan(200);

        ThemeAppearanceService.ApplyResourceTokenOverrides(resources, Wpf.Ui.Appearance.ApplicationTheme.HighContrast, ThemeAccentPreset.Emerald, highContrast: true);
        ((System.Windows.Media.SolidColorBrush)resources["PulseSuccessSubtleBrush"]!).Color.Should().Be(System.Windows.SystemColors.WindowColor);

        ThemeAppearanceService.ApplyCompactTokens(resources, isCompact: true);
        ((Thickness)resources["PulsePagePadding"]!).Left.Should().Be(16);

        ThemeAppearanceService.ApplyCompactTokens(resources, isCompact: false);
        ((Thickness)resources["PulsePagePadding"]!).Left.Should().Be(24);
    }

    [Fact]
    public async Task OverviewViewModel_ActivateServerAndConnectAsync_ImmediatelyConnectsCustomPhoneDns()
    {
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();
        using OverviewViewModel vm = new(runtime, localization);

        DnsServerEntry phoneCustomDns = new()
        {
            Id = "custom_phone_dns",
            Name = "My Phone Working DNS",
            Provider = "Custom",
            Protocol = DnsProtocol.DoT,
            TrustTier = TrustTier.Tier3CustomOrSelfHosted,
            PrimaryIp = "94.140.14.14",
            DotHost = "dns.adguard-dns.com",
            SupportsBypass = true
        };

        await vm.ActivateServerAndConnectAsync(phoneCustomDns);

        vm.SelectedGeoUnlockUpstream.Should().BeSameAs(phoneCustomDns);
        vm.SelectedTrustedUpstream.Should().BeSameAs(phoneCustomDns);
        await runtime.Received(1).ConnectAsync(
            Arg.Is<DnsServerEntry?>(s => s != null && s.Id == "custom_phone_dns"),
            Arg.Is<DnsServerEntry?>(s => s != null && s.Id == "custom_phone_dns"),
            Arg.Any<IReadOnlyList<DnsServerEntry>?>(),
            Arg.Any<PulseAppSettings?>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RoutingAndServersViewModels_ExposeSubTabsKpisAndCuratedGitHubFeeds()
    {
        using PulseCatalogRepository repo = new(_dbPath);
        await repo.InitializeAsync();
        IPulseRuntimeService runtime = CreateMockRuntime();
        LocalizationService localization = new();

        using ServersCatalogViewModel servers = new(repo, runtime, localization);
        servers.AvailableFeeds.Should().HaveCountGreaterThanOrEqualTo(15);
        servers.IsCatalogTabSelected.Should().BeTrue();
        servers.SelectSubTabCommand.Execute(1);
        servers.IsDatabasesTabSelected.Should().BeTrue();

        RoutingInspectorViewModel routing = new(runtime, localization);
        routing.IsServicesTabSelected.Should().BeTrue();
        routing.IsLogEmpty.Should().BeTrue();
        routing.SelectSubTabCommand.Execute(1);
        routing.IsLogTabSelected.Should().BeTrue();

        routing.ApplyImportedIpRanges(["104.18.0.0/16", "172.64.0.0/13"]);
        routing.ImportedIpRangesCount.Should().Be(2);
    }

    private static int FindAvailableDualPort()
    {
        using System.Net.Sockets.Socket udp = new(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
        udp.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        return ((System.Net.IPEndPoint)udp.LocalEndPoint!).Port;
    }

    private static int FindAvailableTcpPort()
    {
        using System.Net.Sockets.Socket tcp = new(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
        tcp.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        return ((System.Net.IPEndPoint)tcp.LocalEndPoint!).Port;
    }

    private static IPulseRuntimeService CreateMockRuntime()
    {
        IPulseRuntimeService runtime = Substitute.For<IPulseRuntimeService>();
        SplitNamespaceRouter router = new();
        ServiceStatusSnapshot current = new() { IsConnected = false, ActiveMode = InterceptionMode.None };
        runtime.Router.Returns(router);
        runtime.CurrentStatus.Returns(_ => current);
        runtime.RefreshStatusAsync(Arg.Any<CancellationToken>()).Returns(_ => Task.FromResult(current));
        runtime.InspectHostHealthAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(new HostNetworkHealthSnapshot()));
        runtime.GetRecentTelemetryAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<IReadOnlyList<DnsQueryTelemetryEvent>>([]));
        runtime.UpdateRoutingConfigAsync(Arg.Any<SplitNamespaceRouterConfig>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                router.UpdateConfiguration(callInfo.ArgAt<SplitNamespaceRouterConfig>(0));
                return Task.CompletedTask;
            });

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

internal sealed class MockUpdateHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        Task.FromResult(responder(request));
}
