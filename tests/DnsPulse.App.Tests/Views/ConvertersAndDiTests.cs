using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
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
using DnsPulse.Engine.Sidecar;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Recovery;
using DnsPulse.Platform.Windows.Updates;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace DnsPulse.App.Tests.Views;

public sealed class ConvertersAndDiTests : IDisposable
{
    private static readonly double[] SingleSparklineSample = [25.0];

    private readonly string _tempDir;

    public ConvertersAndDiTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DnsPulseViewsTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void QrMatrixToImageSourceConverter_RendersSharpFrozenBitmapSourceWithQuietZone()
    {
        bool[,] matrix = QrMatrixGenerator.Generate("http://192.168.1.42:10809/proxy.pac");
        int matrixDim = matrix.GetLength(0);
        matrixDim.Should().BeGreaterThanOrEqualTo(21);

        QrMatrixToImageSourceConverter converter = new()
        {
            PixelsPerModule = 6,
            QuietZoneModules = 4
        };

        object? result = converter.Convert(matrix, typeof(ImageSource), null, CultureInfo.InvariantCulture);

        BitmapSource bitmap = result.Should().BeAssignableTo<BitmapSource>().Subject;
        bitmap.IsFrozen.Should().BeTrue();

        int expectedPixels = (matrixDim + 8) * 6;
        bitmap.PixelWidth.Should().Be(expectedPixels);
        bitmap.PixelHeight.Should().Be(expectedPixels);

        int stride = bitmap.PixelWidth * 4;
        byte[] pixels = new byte[stride * bitmap.PixelHeight];
        bitmap.CopyPixels(pixels, stride, 0);

        // Top-left quiet zone pixel must be pure white (#FFFFFFFF).
        pixels[0].Should().Be(0xFF);
        pixels[1].Should().Be(0xFF);
        pixels[2].Should().Be(0xFF);
        pixels[3].Should().Be(0xFF);

        // Finder pattern top-left module (row=0, col=0 => quietOffset=4*6=24) must be pure black (#FF000000).
        int finderOffset = (24 * stride) + (24 * 4);
        pixels[finderOffset].Should().Be(0x00);
        pixels[finderOffset + 1].Should().Be(0x00);
        pixels[finderOffset + 2].Should().Be(0x00);
        pixels[finderOffset + 3].Should().Be(0xFF);
    }

    [Fact]
    public void SparklinePointsConverter_ComputesBoundedPoints_ForSingleFlatAndVaryingSeries()
    {
        SparklinePointsConverter converter = new()
        {
            Width = 200,
            Height = 40,
            Padding = 4
        };

        object emptyResult = converter.Convert(Array.Empty<double>(), typeof(PointCollection), null, CultureInfo.InvariantCulture);
        PointCollection emptyPoints = emptyResult.Should().BeOfType<PointCollection>().Subject;
        emptyPoints.Should().BeEmpty();

        object singleResult = converter.Convert(SingleSparklineSample, typeof(PointCollection), null, CultureInfo.InvariantCulture);
        PointCollection singlePoints = singleResult.Should().BeOfType<PointCollection>().Subject;
        singlePoints.Should().HaveCount(2);
        singlePoints[0].X.Should().Be(4);
        singlePoints[1].X.Should().Be(196);
        singlePoints[0].Y.Should().BeApproximately(20, 0.01);

        double[] samples = [10.0, 20.0, 30.0, 15.0];
        object multiResult = converter.Convert(
            [samples, samples.Length, 15.0],
            typeof(PointCollection),
            null,
            CultureInfo.InvariantCulture);
        PointCollection points = multiResult.Should().BeOfType<PointCollection>().Subject;
        points.Should().HaveCount(4);

        foreach (System.Windows.Point point in points)
        {
            point.X.Should().BeInRange(4, 196);
            point.Y.Should().BeInRange(4, 36);
        }

        // Minimum sample (10) sits at bottom (36), maximum sample (30) sits at top (4).
        points[0].Y.Should().BeApproximately(36, 0.01);
        points[2].Y.Should().BeApproximately(4, 0.01);
    }

    [Fact]
    public void SemanticConverters_MapVerdictsTrustTiersAndLocalizationCleanly()
    {
        LocalizationSource.Instance.Service.SetLanguage("en-US", updateThreadCulture: false);

        VerdictToBrushConverter verdictConverter = new();
        SolidColorBrush healthyBrush = verdictConverter.Convert(DiagnosticVerdict.Healthy, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        SolidColorBrush failedBrush = verdictConverter.Convert(DiagnosticVerdict.TlsSniDpiReset, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        healthyBrush.Color.Should().NotBe(failedBrush.Color);

        TrustTierToBadgeBrushConverter tierConverter = new();
        tierConverter.Convert(TrustTier.Tier1EncryptedTrusted, typeof(string), "Label", CultureInfo.InvariantCulture)
            .Should().Be("Encrypted");
        tierConverter.Convert(TrustTier.Tier2VerifiedGeoUnlock, typeof(string), "Label", CultureInfo.InvariantCulture)
            .Should().Be("Geo-Unblock");
        tierConverter.Convert(TrustTier.Tier3CustomOrSelfHosted, typeof(string), "Label", CultureInfo.InvariantCulture)
            .Should().Be("Custom");
        tierConverter.Convert(TrustTier.Tier4ExperimentalLab, typeof(string), "Label", CultureInfo.InvariantCulture)
            .Should().Be("Test Node");
        tierConverter.Convert(TrustTier.Tier4ExperimentalLab, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>();

        BooleanToVisibilityConverter boolToVis = new() { Invert = true };
        boolToVis.Convert(true, typeof(Visibility), null, CultureInfo.InvariantCulture).Should().Be(Visibility.Collapsed);
        boolToVis.Convert(false, typeof(Visibility), null, CultureInfo.InvariantCulture).Should().Be(Visibility.Visible);

        LocalizationService localization = new();
        LocConverter locConverter = new();
        locConverter.Convert(localization, typeof(string), "Nav_Overview", CultureInfo.InvariantCulture).Should().Be("Overview");
        localization.SetLanguage("ru-RU", updateThreadCulture: false);
        locConverter.Convert(localization, typeof(string), "Nav_Overview", CultureInfo.InvariantCulture).Should().Be("Обзор");
    }

    [Fact]
    public void LatencyFormatConverter_FormatsPositiveValues_AndRendersDashForNonPositiveOrInvalid()
    {
        LatencyFormatConverter converter = new();

        converter.Convert(0.0, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");
        converter.Convert(-1.5, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");
        converter.Convert(null, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");
        converter.Convert(double.NaN, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");
        converter.Convert(double.PositiveInfinity, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");
        converter.Convert(double.NegativeInfinity, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");
        converter.Convert(TimeSpan.Zero, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("—");

        converter.Convert(42.3, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("42.3 ms");
        converter.Convert(15.75f, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("15.8 ms");
        converter.Convert(TimeSpan.FromMilliseconds(0.5), typeof(string), null, CultureInfo.InvariantCulture).Should().Be("<1 ms");
        converter.Convert(TimeSpan.FromMilliseconds(18), typeof(string), null, CultureInfo.InvariantCulture).Should().Be("18 ms");
    }

    [Fact]
    public void CategoryConverters_MapCategoriesAndServersToLocalizedLabelsAndBrushes()
    {
        LocalizationSource.Instance.Service.SetLanguage("en-US", updateThreadCulture: false);

        CategoryToLabelConverter labelConverter = new();
        CategoryToBadgeBrushConverter brushConverter = new();

        labelConverter.Convert((object?)null, typeof(string), null, CultureInfo.InvariantCulture)
            .Should().Be("All Servers");
        labelConverter.Convert(ServerDisplayCategory.AiAndGeoUnlock, typeof(string), null, CultureInfo.InvariantCulture)
            .Should().Be("AI & Geo-Unblock");
        labelConverter.Convert(ServerDisplayCategory.AiAndGeoUnlock, typeof(string), "Short", CultureInfo.InvariantCulture)
            .Should().Be("AI & Geo");
        labelConverter.Convert(ServerDisplayCategory.FastEncrypted, typeof(string), null, CultureInfo.InvariantCulture)
            .Should().Be("Fast Encrypted DNS");
        labelConverter.Convert(ServerDisplayCategory.FastEncrypted, typeof(string), "Short", CultureInfo.InvariantCulture)
            .Should().Be("Encrypted");
        labelConverter.Convert(ServerDisplayCategory.StreamingAndGaming, typeof(string), null, CultureInfo.InvariantCulture)
            .Should().Be("Streaming & Gaming");
        labelConverter.Convert(ServerDisplayCategory.StreamingAndGaming, typeof(string), "Short", CultureInfo.InvariantCulture)
            .Should().Be("Games & Media");
        labelConverter.Convert(ServerDisplayCategory.CustomAndDiscovered, typeof(string), null, CultureInfo.InvariantCulture)
            .Should().Be("Custom / Discovered");
        labelConverter.Convert(ServerDisplayCategory.CustomAndDiscovered, typeof(string), "Short", CultureInfo.InvariantCulture)
            .Should().Be("Custom");

        IReadOnlyList<DnsServerEntry> flagships = BuiltInCatalogPresets.BuildFlagshipServers();
        DnsServerEntry xboxServer = flagships.Single(static s => s.Id == "smart_xbox_dns_udp");
        DnsServerEntry comssServer = flagships.Single(static s => s.Id == "smart_comss_doh");

        labelConverter.Convert(xboxServer, typeof(string), "Short", CultureInfo.InvariantCulture)
            .Should().Be("Games & Media");
        labelConverter.Convert(comssServer, typeof(string), "Short", CultureInfo.InvariantCulture)
            .Should().Be("AI & Geo");
        labelConverter.Convert([comssServer], typeof(string), null, CultureInfo.InvariantCulture)
            .Should().Be("AI & Geo-Unblock");

        SolidColorBrush aiBrush = brushConverter.Convert(ServerDisplayCategory.AiAndGeoUnlock, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        SolidColorBrush fastBrush = brushConverter.Convert(ServerDisplayCategory.FastEncrypted, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        SolidColorBrush gamingBrush = brushConverter.Convert(xboxServer, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        SolidColorBrush customBrush = brushConverter.Convert(ServerDisplayCategory.CustomAndDiscovered, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;

        aiBrush.IsFrozen.Should().BeTrue();
        System.Windows.Media.Color[] distinctColors = [aiBrush.Color, fastBrush.Color, gamingBrush.Color, customBrush.Color];
        distinctColors.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void EnumLocalizationConverter_LocalizesZonesRcodesSortOrdersAndModes()
    {
        LocalizationSource.Instance.Service.SetLanguage("en-US", updateThreadCulture: false);
        EnumLocalizationConverter converter = new();

        converter.Convert((object?)null, typeof(string), null, CultureInfo.InvariantCulture).Should().Be(string.Empty);

        // Route zones
        converter.Convert(RouteZone.None, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Default");
        converter.Convert(RouteZone.Zone1LocalBypass, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Local / LAN");
        converter.Convert(RouteZone.Zone2BlockOrProtect, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Protected");
        converter.Convert(RouteZone.Zone3GeoUnlock, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Unblock");
        converter.Convert(RouteZone.Zone4EncryptedTrusted, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Encrypted");

        // DNS response codes
        converter.Convert(DnsResponseCode.NoError, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("OK");
        converter.Convert(DnsResponseCode.NxDomain, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Not found");
        converter.Convert(DnsResponseCode.ServFail, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Server error");
        converter.Convert(DnsResponseCode.Refused, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Refused");
        converter.Convert(DnsResponseCode.FormErr, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Bad query");
        converter.Convert(DnsResponseCode.NotImp, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Unsupported");
        converter.Convert(DnsResponseCode.NotAuth, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Error");

        // Sort orders
        converter.Convert(ServerSortOrder.P50Latency, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Sort: Speed (Fastest)");
        converter.Convert(ServerSortOrder.Protocol, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Sort: Protocol");
        converter.Convert(ServerSortOrder.TrustTier, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Sort: Category");
        converter.Convert(ServerSortOrder.Name, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Sort: Name");

        // Interception modes & settings enums
        converter.Convert(InterceptionMode.AdapterDns, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Adapter DNS (Recommended)");
        converter.Convert(InterceptionMode.SplitNrpt, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Windows Routing Policy (NRPT)");
        converter.Convert(InterceptionMode.LocalProxyPacOnly, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Local Proxy / PAC (No Admin Rights)");
        converter.Convert(InterceptionMode.WfpDivertPlugin, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Packet Driver (Disabled during Anti-Cheat)");
        converter.Convert(InterceptionMode.None, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Disconnected");

        converter.Convert(PoolSelectionStrategy.Fastest, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Fastest response");
        converter.Convert(UpdateChannel.Beta, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Beta");
        converter.Convert(RuleFormatKind.AdGuard, typeof(string), null, CultureInfo.InvariantCulture).Should().Be("AdGuard List");
        converter.Convert("Azure", typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Cobalt Blue");
        converter.Convert("Auto", typeof(string), null, CultureInfo.InvariantCulture).Should().Be("Automatic");
    }

    [Fact]
    public void AppBuildServiceProvider_ResolvesAllSixViewModels_HeadlessWithoutError()
    {
        string dbPath = Path.Combine(_tempDir, "catalog.db");
        string settingsDir = Path.Combine(_tempDir, "settings");
        string journalDir = Path.Combine(_tempDir, "journal");

        using ServiceProvider provider = App.BuildServiceProvider(services =>
        {
            services.AddSingleton(new PulseCatalogRepository(dbPath));
            services.AddSingleton(new AppSettingsStore(settingsDir, settingsDir));
            services.AddSingleton(new NetworkSnapshotJournal(journalDir));
            services.AddSingleton(new ThemeAppearanceService(static () => false, static () => 22631));
            services.AddSingleton(new WindowsAutostartService(@"SOFTWARE\DnsPulseTests_Headless", "DnsPulseTest"));
        });

        MainShellViewModel shell = provider.GetRequiredService<MainShellViewModel>();
        OverviewViewModel overview = provider.GetRequiredService<OverviewViewModel>();
        RoutingInspectorViewModel routing = provider.GetRequiredService<RoutingInspectorViewModel>();
        ServersCatalogViewModel servers = provider.GetRequiredService<ServersCatalogViewModel>();
        DiagnosticsDoctorViewModel diagnostics = provider.GetRequiredService<DiagnosticsDoctorViewModel>();
        SettingsSafetyViewModel settings = provider.GetRequiredService<SettingsSafetyViewModel>();

        shell.Should().NotBeNull();
        shell.Overview.Should().BeSameAs(overview);
        shell.Routing.Should().BeSameAs(routing);
        shell.Servers.Should().BeSameAs(servers);
        shell.Diagnostics.Should().BeSameAs(diagnostics);
        shell.Settings.Should().BeSameAs(settings);

        provider.GetRequiredService<IPulseRuntimeService>().Should().NotBeNull();
        provider.GetRequiredService<LocalizationService>().Should().NotBeNull();
        provider.GetRequiredService<ThemeAppearanceService>().Should().NotBeNull();
        provider.GetRequiredService<TrayIconService>().Should().NotBeNull();
    }

    [Fact]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Captures any STA thread exception cleanly for test assertion.")]
    public void LocalizationExtension_RefreshesBoundTextBlock_WhenLanguageSwitchesAtRuntime()
    {
        Exception? threadException = null;
        string? russianText = null;
        string? englishText = null;

        Thread sta = new(() =>
        {
            try
            {
                LocalizationService localization = new();
                localization.SetLanguage("ru-RU", updateThreadCulture: false);
                LocalizationSource.Instance.Attach(localization);

                const string xaml = """
                    <StackPanel xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                                xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml"
                                xmlns:conv="clr-namespace:DnsPulse.App.Converters;assembly=DnsPulse">
                        <TextBlock x:Name="PlainLabel" Text="{conv:Localization Overview_QuickConnect_Title}" />
                        <ui:TextBlock x:Name="UiLabel" Text="{conv:Localization Settings_PoolStrategy}" />
                        <ui:CardControl x:Name="CardLabel" Header="{conv:Localization Settings_Language}" />
                        <TextBlock><Run x:Name="RunLabel" Text="{conv:Localization Overview_QuickConnect_Title}" /></TextBlock>
                    </StackPanel>
                    """;

                System.Windows.Controls.StackPanel panel = (System.Windows.Controls.StackPanel)System.Windows.Markup.XamlReader.Parse(xaml);
                System.Windows.Controls.TextBlock plain = (System.Windows.Controls.TextBlock)panel.FindName("PlainLabel")!;
                Wpf.Ui.Controls.TextBlock uiLabel = (Wpf.Ui.Controls.TextBlock)panel.FindName("UiLabel")!;
                Wpf.Ui.Controls.CardControl cardLabel = (Wpf.Ui.Controls.CardControl)panel.FindName("CardLabel")!;
                System.Windows.Documents.Run runLabel = (System.Windows.Documents.Run)panel.FindName("RunLabel")!;
                russianText = plain.Text;

                localization.SetLanguage("en-US", updateThreadCulture: false);
                englishText = $"{plain.Text}|{uiLabel.Text}|{cardLabel.Header}|{runLabel.Text}";
            }
            catch (Exception ex)
            {
                threadException = ex;
            }
        });

        sta.SetApartmentState(ApartmentState.STA);
        sta.Start();
        sta.Join();

        threadException.Should().BeNull();
        russianText.Should().NotBeNullOrWhiteSpace();
        englishText.Should().Be("What do you want to open?|Server Selection Mode|Display Language|What do you want to open?");
    }

    [Fact]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Captures any STA thread exception cleanly for test assertion.")]
    public void MainWindowAndPages_RefreshLocalizationAndThemeBrushes_AtRuntime()
    {
        Exception? threadException = null;
        string? overviewQuickBefore = null;
        string? overviewQuickAfter = null;
        string? settingsPoolAfter = null;
        System.Windows.Media.Color darkSecondaryColor = default;
        System.Windows.Media.Color lightSecondaryColor = default;

        Thread sta = new(() =>
        {
            try
            {
                string dbPath = Path.Combine(_tempDir, "ui-switch-catalog.db");
                string settingsDir = Path.Combine(_tempDir, "ui-switch-settings");
                string journalDir = Path.Combine(_tempDir, "ui-switch-journal");

                using ServiceProvider provider = App.BuildServiceProvider(services =>
                {
                    services.AddSingleton(new PulseCatalogRepository(dbPath));
                    services.AddSingleton(new AppSettingsStore(settingsDir, settingsDir));
                    services.AddSingleton(new NetworkSnapshotJournal(journalDir));
                    services.AddSingleton(new ThemeAppearanceService(static () => false, static () => 22631));
                    services.AddSingleton(new WindowsAutostartService(@"SOFTWARE\DnsPulseTests_Headless", "DnsPulseTest"));
                });

                LocalizationService localization = provider.GetRequiredService<LocalizationService>();
                localization.SetLanguage("ru-RU", updateThreadCulture: false);
                LocalizationSource.Instance.Attach(localization);

                System.Windows.Application.ResourceAssembly ??= typeof(App).Assembly;
                if (System.Windows.Application.Current is null)
                {
                    App app = new(suppressStartup: true)
                    {
                        ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown
                    };
                    app.InitializeComponent();
                }

                ThemeAppearanceService theme = provider.GetRequiredService<ThemeAppearanceService>();
                theme.ApplyTheme(isDarkTheme: true, "Emerald");

                MainShellViewModel shell = provider.GetRequiredService<MainShellViewModel>();
                DnsPulse.App.Views.MainWindow mainWindow = provider.GetRequiredService<DnsPulse.App.Views.MainWindow>();
                mainWindow.Width = 1100;
                mainWindow.Height = 760;
                mainWindow.ShowInTaskbar = false;
                mainWindow.WindowStyle = System.Windows.WindowStyle.None;
                mainWindow.Show();
                PumpDispatcher();
                shell.NavigateTo(ShellPageKind.Settings);
                PumpDispatcher();

                DnsPulse.App.Views.OverviewPage overviewPage = provider.GetRequiredService<DnsPulse.App.Views.OverviewPage>();
                DnsPulse.App.Views.SettingsSafetyPage settingsPage = provider.GetRequiredService<DnsPulse.App.Views.SettingsSafetyPage>();

                System.Windows.Controls.TextBlock? overviewTitle = FindVisualOrLogicalText(overviewPage, "Что нужно открыть?");
                System.Windows.Controls.TextBlock? poolLabel = FindVisualOrLogicalText(settingsPage, "Выбор сервера из списка");
                overviewQuickBefore = overviewTitle?.Text;
                darkSecondaryColor = ((System.Windows.Media.SolidColorBrush)poolLabel!.Foreground).Color;

                theme.ApplyTheme(isDarkTheme: false, "Emerald");
                localization.SetLanguage("en-US", updateThreadCulture: false);
                PumpDispatcher();

                overviewQuickAfter = overviewTitle?.Text;
                settingsPoolAfter = poolLabel.Text;
                lightSecondaryColor = ((System.Windows.Media.SolidColorBrush)poolLabel.Foreground).Color;
                mainWindow.AllowClose();
                mainWindow.Close();
                PumpDispatcher();
            }
            catch (Exception ex)
            {
                threadException = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });

        sta.SetApartmentState(ApartmentState.STA);
        sta.Start();
        sta.Join();

        threadException.Should().BeNull();
        overviewQuickBefore.Should().Be("Что нужно открыть?");
        overviewQuickAfter.Should().Be("What do you want to open?");
        settingsPoolAfter.Should().Be("Server Selection Mode");
        darkSecondaryColor.R.Should().BeGreaterThan(200);
        lightSecondaryColor.R.Should().Be(0);
        lightSecondaryColor.A.Should().BeGreaterThan(120);
    }

    private static void PumpDispatcher()
    {
        System.Windows.Threading.DispatcherFrame frame = new();
        System.Windows.Threading.Dispatcher.CurrentDispatcher.BeginInvoke(
            System.Windows.Threading.DispatcherPriority.Background,
            new System.Windows.Threading.DispatcherOperationCallback(static state =>
            {
                ((System.Windows.Threading.DispatcherFrame)state).Continue = false;
                return null;
            }),
            frame);
        System.Windows.Threading.Dispatcher.PushFrame(frame);
    }

    private static System.Windows.Controls.TextBlock? FindVisualOrLogicalText(System.Windows.DependencyObject root, string text)
    {
        if (root is System.Windows.Controls.TextBlock tb && string.Equals(tb.Text, text, StringComparison.Ordinal))
        {
            return tb;
        }

        foreach (object child in System.Windows.LogicalTreeHelper.GetChildren(root))
        {
            if (child is System.Windows.DependencyObject depChild)
            {
                System.Windows.Controls.TextBlock? found = FindVisualOrLogicalText(depChild, text);
                if (found is not null)
                {
                    return found;
                }
            }
        }

        return null;
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
