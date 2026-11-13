using System.Collections;
using System.Globalization;
using System.Resources;
using DnsPulse.App.Localization;
using FluentAssertions;

namespace DnsPulse.App.Tests.Localization;

public sealed class LocalizationServiceTests
{
    [Fact]
    public void StringsResx_And_RussianResx_Have100PercentKeyParityAndNonEmptyValues()
    {
        ResourceManager manager = new("DnsPulse.App.Localization.Strings", typeof(LocalizationService).Assembly);

        using ResourceSet? enSet = manager.GetResourceSet(CultureInfo.InvariantCulture, createIfNotExists: true, tryParents: false);
        using ResourceSet? ruSet = manager.GetResourceSet(CultureInfo.GetCultureInfo("ru-RU"), createIfNotExists: true, tryParents: false);

        enSet.Should().NotBeNull();
        ruSet.Should().NotBeNull();

        Dictionary<string, string> enEntries = [];
        foreach (DictionaryEntry entry in enSet!)
        {
            enEntries[(string)entry.Key] = entry.Value?.ToString() ?? string.Empty;
        }

        Dictionary<string, string> ruEntries = [];
        foreach (DictionaryEntry entry in ruSet!)
        {
            ruEntries[(string)entry.Key] = entry.Value?.ToString() ?? string.Empty;
        }

        enEntries.Should().NotBeEmpty();
        ruEntries.Keys.Should().BeEquivalentTo(enEntries.Keys, "every canonical en-US key must exist in Strings.ru-RU.resx");

        foreach (KeyValuePair<string, string> pair in enEntries)
        {
            pair.Value.Should().NotBeNullOrWhiteSpace($"en-US key '{pair.Key}' must have a non-empty translation");
            ruEntries[pair.Key].Should().NotBeNullOrWhiteSpace($"ru-RU key '{pair.Key}' must have a non-empty Russian translation");
        }
    }

    [Fact]
    public void SetLanguage_UpdatesIndexerAndFiresEventsWithoutRestart()
    {
        LocalizationService service = new();
        List<string?> changedProperties = [];
        List<CultureInfo> observedCultures = [];

        service.PropertyChanged += (_, args) => changedProperties.Add(args.PropertyName);
        service.CultureChanged += (_, args) => observedCultures.Add(args.Culture);

        string englishConnect = service["Overview_CTA_Connect"];
        englishConnect.Should().Be("Connect");
        service.FlowDirection.Should().Be(System.Windows.FlowDirection.LeftToRight);

        service.SetLanguage("ru-RU", updateThreadCulture: false);

        service.CurrentLanguageCode.Should().Be("ru-RU");
        service["Overview_CTA_Connect"].Should().Be("Подключить");
        service.FlowDirection.Should().Be(System.Windows.FlowDirection.LeftToRight);
        observedCultures.Should().ContainSingle().Which.Name.Should().Be("ru-RU");
        changedProperties.Should().Contain("Item[]");
        changedProperties.Should().Contain(nameof(LocalizationService.FlowDirection));
    }

    [Fact]
    public void SetLanguage_PersianRtl_ExposesRightToLeftFlowDirectionAndGracefulFallback()
    {
        LocalizationService service = new();

        service.SetLanguage("fa-IR", updateThreadCulture: false);

        service.CurrentLanguageCode.Should().Be("fa-IR");
        service.IsRightToLeft.Should().BeTrue();
        service.FlowDirection.Should().Be(System.Windows.FlowDirection.RightToLeft);
        service["Overview_CTA_Connect"].Should().Be("Connect");

        service.SetLanguage("en-US", updateThreadCulture: false);
        service.IsRightToLeft.Should().BeFalse();
        service.FlowDirection.Should().Be(System.Windows.FlowDirection.LeftToRight);
    }
}
