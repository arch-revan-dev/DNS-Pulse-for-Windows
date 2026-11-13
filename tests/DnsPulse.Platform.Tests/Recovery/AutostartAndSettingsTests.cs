using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Updates;
using FluentAssertions;
using Microsoft.Win32;
using NSubstitute;

namespace DnsPulse.Platform.Tests.Recovery;

public sealed class AutostartAndSettingsTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _testRegistrySubKey;

    public AutostartAndSettingsTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DnsPulseTests", "AutostartSettings", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _testRegistrySubKey = $@"SOFTWARE\DnsPulseTests\{Guid.NewGuid():N}";
    }

    [Fact]
    public void WindowsAutostartService_BuildExtractRoundtripAndEnableDisableRepair_WorksAndRejectsDotNetHost()
    {
        string fakeExe = Path.Combine(_tempDir, "My App", "DnsPulse.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(fakeExe)!);
        File.WriteAllBytes(fakeExe, [0x4D, 0x5A]);

        string cmdMinimized = WindowsAutostartService.BuildQuotedLaunchCommand(fakeExe, startMinimized: true);
        cmdMinimized.Should().Be($"\"{fakeExe}\" --autostart --minimized");
        WindowsAutostartService.ExtractExecutablePath(cmdMinimized).Should().Be(fakeExe);

        string cmdNormal = WindowsAutostartService.BuildQuotedLaunchCommand(fakeExe, startMinimized: false);
        cmdNormal.Should().Be($"\"{fakeExe}\" --autostart");
        WindowsAutostartService.ExtractExecutablePath(cmdNormal).Should().Be(fakeExe);

        // Guard against dotnet.exe host paths
        string fakeDotnet = Path.Combine(_tempDir, "dotnet.exe");
        File.WriteAllBytes(fakeDotnet, [0x4D, 0x5A]);
        WindowsAutostartService dotnetAutostart = new(_testRegistrySubKey, "DnsPulse", () => fakeDotnet);
        dotnetAutostart.Enable(startMinimized: true).Should().BeFalse();
        dotnetAutostart.IsEnabled().Should().BeFalse();

        // Real enable + readback + repair + disable in isolated HKCU test key
        string activePath = fakeExe;
        WindowsAutostartService autostart = new(_testRegistrySubKey, "DnsPulse", () => activePath);
        autostart.Enable(startMinimized: true).Should().BeTrue();
        autostart.IsEnabled().Should().BeTrue();

        // Repair heals stale executable path
        string movedExe = Path.Combine(_tempDir, "Updated", "DnsPulse.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(movedExe)!);
        File.WriteAllBytes(movedExe, [0x4D, 0x5A]);
        activePath = movedExe;

        autostart.RepairIfEnabled(startMinimized: false).Should().BeTrue();
        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(_testRegistrySubKey, writable: false))
        {
            string? regValue = key?.GetValue("DnsPulse") as string;
            regValue.Should().Be($"\"{movedExe}\" --autostart");
        }

        autostart.Disable().Should().BeTrue();
        autostart.IsEnabled().Should().BeFalse();
    }

    [Fact]
    public void AppSettingsStore_DefaultsClampingAndLegacyCompatibility_Works()
    {
        string primaryDir = Path.Combine(_tempDir, "DnsPulse");
        string legacyDir = Path.Combine(_tempDir, "DNS-Pulse");
        Directory.CreateDirectory(legacyDir);

        // Legacy v1.5.3 JSON without any PulseCore v2.0 properties
        const string legacyJson = """
            {
              "IsDarkTheme": false,
              "AccentPreset": "Violet",
              "CompactMode": true,
              "StartWithWindows": true,
              "ProbeTimeoutMs": 99999,
              "BenchmarkConcurrency": 1,
              "BootstrapDnsProvider": "8.8.8.8",
              "GitHubToken": "  ghp_legacytoken123456  "
            }
            """;
        File.WriteAllText(Path.Combine(legacyDir, "settings.json"), legacyJson);

        AppSettingsStore store = new(primaryDir, legacyDir);
        PulseAppSettings migrated = store.Load();

        migrated.IsDarkTheme.Should().BeFalse();
        migrated.AccentPreset.Should().Be("Violet");
        migrated.CompactMode.Should().BeTrue();
        migrated.StartWithWindows.Should().BeTrue();
        migrated.BootstrapDnsProvider.Should().Be("8.8.8.8");
        migrated.GitHubToken.Should().Be("ghp_legacytoken123456");

        // Clamping & PulseCore defaults
        migrated.ProbeTimeoutMs.Should().Be(6000);
        migrated.BenchmarkConcurrency.Should().Be(2);
        migrated.UiLanguage.Should().Be("en-US");
        migrated.UpdateChannel.Should().Be(UpdateChannel.Stable);
        migrated.InterceptionMode.Should().Be(InterceptionMode.AdapterDns);
        migrated.ZeroDiskQueryLogging.Should().BeTrue();
        migrated.DnsRebindingProtectionEnabled.Should().BeTrue();

        // Save clamps lower/upper bounds & invalid presets atomically
        migrated.ProbeTimeoutMs = 200;
        migrated.BenchmarkConcurrency = 64;
        migrated.AccentPreset = "Unknown";
        migrated.BootstrapDnsProvider = "Invalid";
        migrated.UpdateChannel = UpdateChannel.Beta;
        store.Save(migrated);

        File.Exists(store.SettingsFilePath).Should().BeTrue();
        File.Exists(string.Concat(store.SettingsFilePath, ".tmp")).Should().BeFalse();

        PulseAppSettings reloaded = store.Load();
        reloaded.ProbeTimeoutMs.Should().Be(1000);
        reloaded.BenchmarkConcurrency.Should().Be(16);
        reloaded.AccentPreset.Should().Be("Emerald");
        reloaded.BootstrapDnsProvider.Should().Be("Auto");
        reloaded.UpdateChannel.Should().Be(UpdateChannel.Beta);
    }

    [Fact]
    public async Task DiagnosticBundleExporter_RedactsTokensPathsAndZerosTelemetryUnlessOptedIn()
    {
        string logDir = Path.Combine(_tempDir, "logs");
        Directory.CreateDirectory(logDir);
        string logFile = Path.Combine(logDir, "pulse.log");
        await File.WriteAllTextAsync(
            logFile,
            "2026-11-14 INFO User file C:\\Users\\Alice\\AppData\\Roaming\\DnsPulse\\settings.json\r\n" +
            "2026-11-14 WARN Authorization: Bearer super-secret-jwt-value\r\n" +
            "2026-11-14 WARN Token ghp_1234567890abcdef leaked\r\n");

        PulseAppSettings settings = new()
        {
            GitHubToken = "ghp_secretTokenValue987654321",
            ZeroDiskQueryLogging = true
        };

        PrePulseNetworkSnapshot snapshot = new()
        {
            DirtyShutdown = false,
            ActiveMode = InterceptionMode.AdapterDns,
            LoopbackIpUsed = "127.0.53.1"
        };

        HostNetworkHealthSnapshot hostHealth = new()
        {
            ActiveInterfaceNames = ["Ethernet"],
            HasIpv4Connectivity = true,
            IsSmhnrDisabled = true
        };

        string zipPath = Path.Combine(_tempDir, "bundle-no-optin.zip");
        await DiagnosticBundleExporter.ExportRedactedBundleAsync(
            zipPath,
            settings,
            snapshot,
            hostHealth,
            eventsIfOptedIn: null,
            logDirectory: logDir,
            CancellationToken.None);

        File.Exists(zipPath).Should().BeTrue();

        using (ZipArchive archive = ZipFile.OpenRead(zipPath))
        {
            archive.Entries.Select(static e => e.FullName).Should().Contain(
                ["manifest.json", "settings.json", "telemetry.json", "network_snapshot.json", "host_health.json", "logs/pulse.log"]);

            string settingsText = await ReadZipEntryTextAsync(archive.GetEntry("settings.json")!);
            settingsText.Should().NotContain("ghp_secretTokenValue987654321");
            settingsText.Should().Contain("[REDACTED]");

            string telemetryText = await ReadZipEntryTextAsync(archive.GetEntry("telemetry.json")!);
            telemetryText.Should().Contain("\"optedIn\": false");
            telemetryText.Should().Contain("\"events\": []");

            string scrubbedLog = await ReadZipEntryTextAsync(archive.GetEntry("logs/pulse.log")!);
            scrubbedLog.Should().NotContain("Alice");
            scrubbedLog.Should().NotContain("super-secret-jwt-value");
            scrubbedLog.Should().NotContain("ghp_1234567890abcdef");
            scrubbedLog.Should().Contain("[REDACTED]");
        }

        // Also test opted-in telemetry still scrubs secrets from DecisionNote
        string zipOptInPath = Path.Combine(_tempDir, "bundle-optin.zip");
        DnsQueryTelemetryEvent[] events =
        [
            new DnsQueryTelemetryEvent(
                DateTimeOffset.UtcNow,
                "gemini.google.com",
                DnsRecordType.A,
                RouteZone.Zone3GeoUnlock,
                "GeoUnlock",
                DnsProtocol.DoH,
                14.2,
                CacheHit: false,
                RewrittenSvcb: true,
                DnsResponseCode.NoError,
                "Resolved via Bearer topsecret123")
        ];

        await DiagnosticBundleExporter.ExportRedactedBundleAsync(
            zipOptInPath,
            settings,
            snapshot: null,
            hostHealth: null,
            eventsIfOptedIn: events,
            logDirectory: null,
            CancellationToken.None);

        using ZipArchive optInArchive = ZipFile.OpenRead(zipOptInPath);
        string optInTelemetry = await ReadZipEntryTextAsync(optInArchive.GetEntry("telemetry.json")!);
        optInTelemetry.Should().Contain("gemini.google.com");
        optInTelemetry.Should().NotContain("topsecret123");
        optInTelemetry.Should().Contain("Bearer [REDACTED]");
    }

    [Fact]
    public async Task VerifiedAppUpdateService_ParsesReleaseJsonAndVerifiesSha256_FailClosedOnTamper()
    {
        const string releaseJson = """
            {
              "tag_name": "v9.9.1",
              "prerelease": false,
              "body": "PulseCore release notes",
              "html_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/tag/v9.9.1",
              "assets": [
                {
                  "name": "DNS-Pulse-win-x64-setup.exe",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v9.9.1/DNS-Pulse-win-x64-setup.exe"
                },
                {
                  "name": "DnsPulse.exe",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v9.9.1/DnsPulse.exe"
                },
                {
                  "name": "SHA256SUMS.txt",
                  "browser_download_url": "https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/download/v9.9.1/SHA256SUMS.txt"
                }
              ]
            }
            """;

        ReleaseInfo? parsed = VerifiedAppUpdateService.ParseReleaseJson(releaseJson);
        parsed.Should().NotBeNull();
        parsed!.TagName.Should().Be("v9.9.1");
        parsed.ParsedVersion.Should().Be(new Version(9, 9, 1));
        parsed.SetupExeUrl.Should().EndWith("DNS-Pulse-win-x64-setup.exe");
        parsed.PortableExeUrl.Should().EndWith("DnsPulse.exe");
        parsed.Sha256SumsUrl.Should().EndWith("SHA256SUMS.txt");

        byte[] validBinary = Encoding.UTF8.GetBytes("MZ-fake-portable-binary-content");
        string validHashHex = Convert.ToHexStringLower(SHA256.HashData(validBinary));
        string validSumsText = $"{validHashHex}  DnsPulse.exe\n";

        using StubHttpMessageHandler validHandler = new(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.EndsWith("/releases/latest", StringComparison.Ordinal))
            {
                return StubHttpMessageHandler.JsonResponse(releaseJson);
            }

            if (url.EndsWith("/SHA256SUMS.txt", StringComparison.Ordinal))
            {
                return StubHttpMessageHandler.BytesResponse(Encoding.UTF8.GetBytes(validSumsText));
            }

            if (url.EndsWith("/DnsPulse.exe", StringComparison.Ordinal) ||
                url.EndsWith("/DNS-Pulse-win-x64-setup.exe", StringComparison.Ordinal))
            {
                return StubHttpMessageHandler.BytesResponse(validBinary);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        IBootstrapResolver resolver = Substitute.For<IBootstrapResolver>();
        using VerifiedAppUpdateService updateService = new(resolver, validHandler, validHandler);

        UpdateCheckResult check = await updateService.CheckForUpdateAsync(UpdateChannel.Stable);
        check.UpdateAvailable.Should().BeTrue();
        check.LatestRelease.Should().NotBeNull();

        string stageRoot = Path.Combine(_tempDir, "stage-valid");
        VerifiedUpdateResult verifiedResult = await updateService.DownloadAndVerifyUpdateAsync(
            check.LatestRelease!,
            stagingRootDirectory: stageRoot);

        verifiedResult.Verified.Should().BeTrue();
        verifiedResult.Sha256Hex.Should().Be(validHashHex);
        verifiedResult.AuthenticodePresent.Should().BeFalse();
        File.Exists(verifiedResult.PreparedFilePath).Should().BeTrue();

        // Tampered binary must fail closed and delete staged file
        byte[] tamperedBinary = Encoding.UTF8.GetBytes("MZ-tampered-binary");
        using StubHttpMessageHandler tamperedHandler = new(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.EndsWith("/SHA256SUMS.txt", StringComparison.Ordinal))
            {
                return StubHttpMessageHandler.BytesResponse(Encoding.UTF8.GetBytes(validSumsText));
            }

            return StubHttpMessageHandler.BytesResponse(tamperedBinary);
        });

        using VerifiedAppUpdateService tamperedService = new(resolver, tamperedHandler, tamperedHandler);
        string tamperedStageRoot = Path.Combine(_tempDir, "stage-tampered");

        Func<Task> act = async () => await tamperedService.DownloadAndVerifyUpdateAsync(
            parsed,
            stagingRootDirectory: tamperedStageRoot);

        await act.Should().ThrowAsync<CryptographicException>();
        Directory.GetFiles(tamperedStageRoot, "*", SearchOption.AllDirectories).Should().BeEmpty();
    }

    private static async Task<string> ReadZipEntryTextAsync(ZipArchiveEntry entry)
    {
        await using Stream s = entry.Open();
        using StreamReader reader = new(s, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    public void Dispose()
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(_testRegistrySubKey, throwOnMissingSubKey: false);
        }
        catch (UnauthorizedAccessException)
        {
        }

        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(responder(request));
        }

        public static HttpResponseMessage JsonResponse(string json)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        }

        public static HttpResponseMessage BytesResponse(byte[] payload)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(payload)
            };
        }
    }
}
