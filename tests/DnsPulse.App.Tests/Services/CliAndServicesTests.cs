using System.IO;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Recovery;
using FluentAssertions;
using Serilog.Core;
using Wpf.Ui.Controls;

namespace DnsPulse.App.Tests.Services;

public sealed class CliAndServicesTests : IDisposable
{
    private readonly string _tempDir;

    public CliAndServicesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DnsPulseCliTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void CliArgumentHandler_ParsesAllSupportedFlags()
    {
        CliLaunchOptions parsed = CliArgumentHandler.Parse(
        [
            "--restore-network",
            "--autostart",
            "--minimized",
            "--apply-tunnel",
            "--connect-id",
            "cf-doh"
        ]);

        parsed.RestoreNetwork.Should().BeTrue();
        parsed.Autostart.Should().BeTrue();
        parsed.Minimized.Should().BeTrue();
        parsed.ApplyTunnel.Should().BeTrue();
        parsed.ConnectServerId.Should().Be("cf-doh");

        CliLaunchOptions equalsForm = CliArgumentHandler.Parse(["--connect-id=quad9-dot"]);
        equalsForm.ConnectServerId.Should().Be("quad9-dot");
        equalsForm.RestoreNetwork.Should().BeFalse();
    }

    [Fact]
    public async Task CliArgumentHandler_RestoreNetwork_ExecutesRecoveryAndExitsZero()
    {
        NetworkSnapshotJournal journal = new(_tempDir);
        await journal.BeginTransactionAsync(
            InterceptionMode.AdapterDns,
            System.Net.IPAddress.Loopback,
            [],
            priorSmhnrDisabled: false,
            priorNrptRules: []);

        bool restoreInvoked = false;
        CliLaunchOptions options = CliArgumentHandler.Parse(["--restore-network"]);

        int? exitCode = await CliArgumentHandler.TryHandleEarlyExitAsync(
            options,
            journal,
            snapshot =>
            {
                restoreInvoked = true;
                return new NetworkRestoredResult(snapshot is not null, 0, true, "Mock restore ok");
            });

        exitCode.Should().Be(0);
        restoreInvoked.Should().BeTrue();

        PrePulseNetworkSnapshot? after = journal.TryLoadVerifiedSnapshot(out _);
        after.Should().NotBeNull();
        after!.DirtyShutdown.Should().BeFalse();
    }

    [Fact]
    public void ThemeAppearanceService_ResolvesMicaOnWin11_And_SolidOnWin10OrHighContrast()
    {
        ThemeAppearanceService.ResolveBackdrop(isHighContrast: false, osBuildNumber: 22631).Should().Be(WindowBackdropType.Mica);
        ThemeAppearanceService.ResolveBackdrop(isHighContrast: false, osBuildNumber: 19045).Should().Be(WindowBackdropType.None);
        ThemeAppearanceService.ResolveBackdrop(isHighContrast: true, osBuildNumber: 22631).Should().Be(WindowBackdropType.None);

        ThemeAppearanceService service = new(
            highContrastProvider: () => true,
            windowsBuildProvider: () => 22631);
        service.ApplyTheme(isDarkTheme: true, "Azure");

        service.IsHighContrastActive.Should().BeTrue();
        service.CurrentBackdrop.Should().Be(WindowBackdropType.None);
        service.CurrentTheme.Should().Be(Wpf.Ui.Appearance.ApplicationTheme.HighContrast);
    }

    [Fact]
    public void LoggingSetupService_ZeroDiskQueryLogging_PreventsDomainPiiWrittenToDisk()
    {
        string logDir = Path.Combine(_tempDir, "logs");
        DnsQueryTelemetryEvent query = new(
            DateTimeOffset.UtcNow,
            "secret-private-domain.example",
            DnsRecordType.A,
            RouteZone.Zone4EncryptedTrusted,
            "Cloudflare",
            DnsProtocol.DoH,
            12.3,
            false,
            false,
            DnsResponseCode.NoError,
            "Resolved");

        using (Logger logger = LoggingSetupService.CreateFileLogger(logDir))
        {
            logger.Information("PulseCore runtime initialized cleanly");
            LoggingSetupService.LogQueryIfOptedIn(logger, query, zeroDiskQueryLogging: true);
        }

        string logFile = Directory.GetFiles(logDir, "pulse-*.log").Single();
        string initialContents = File.ReadAllText(logFile);
        initialContents.Should().Contain("PulseCore runtime initialized cleanly");
        initialContents.Should().NotContain("secret-private-domain.example");

        using (Logger logger = LoggingSetupService.CreateFileLogger(logDir))
        {
            LoggingSetupService.LogQueryIfOptedIn(logger, query, zeroDiskQueryLogging: false);
        }

        string optedInContents = File.ReadAllText(logFile);
        optedInContents.Should().Contain("secret-private-domain.example");
    }

    [Fact]
    public void TrayIconService_HonorsAutostartAndMinimizeSettings()
    {
        PulseAppSettings settings = new()
        {
            StartMinimizedToTray = true,
            MinimizeToTrayOnClose = true
        };

        TrayIconService.ShouldStartMinimized(settings, new CliLaunchOptions(Autostart: true)).Should().BeTrue();
        TrayIconService.ShouldStartMinimized(settings, new CliLaunchOptions(Autostart: false, Minimized: false)).Should().BeFalse();
        TrayIconService.ShouldStartMinimized(settings, new CliLaunchOptions(Minimized: true)).Should().BeTrue();
        TrayIconService.ShouldMinimizeToTrayOnClose(settings).Should().BeTrue();

        LocalizationService localization = new();
        using TrayIconService tray = new(localization);
        tray.IsInitialized.Should().BeFalse();
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
