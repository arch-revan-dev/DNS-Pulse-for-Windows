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
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Sidecar;
using DnsPulse.Platform.Windows.Autostart;
using DnsPulse.Platform.Windows.Recovery;
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
        VerdictToBrushConverter verdictConverter = new();
        SolidColorBrush healthyBrush = verdictConverter.Convert(DiagnosticVerdict.Healthy, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        SolidColorBrush failedBrush = verdictConverter.Convert(DiagnosticVerdict.TlsSniDpiReset, typeof(System.Windows.Media.Brush), null, CultureInfo.InvariantCulture)
            .Should().BeOfType<SolidColorBrush>().Subject;
        healthyBrush.Color.Should().NotBe(failedBrush.Color);

        TrustTierToBadgeBrushConverter tierConverter = new();
        tierConverter.Convert(TrustTier.Tier1EncryptedTrusted, typeof(string), "Label", CultureInfo.InvariantCulture)
            .Should().Be("Tier 1");
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
