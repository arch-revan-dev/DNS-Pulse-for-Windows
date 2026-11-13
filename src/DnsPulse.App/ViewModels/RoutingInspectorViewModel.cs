using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Engine.Pipeline;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Supported custom routing rule import/export formats.
/// </summary>
public enum RuleFormatKind
{
    Json = 0,
    AdGuard = 1,
    Hosts = 2
}

/// <summary>
/// Live telemetry inspector filter chips.
/// </summary>
public enum TelemetryFilterChip
{
    All = 0,
    GeoUnlocked = 1,
    DpiSplit = 2,
    Blocked = 3,
    Errors = 4
}

/// <summary>
/// Selectable service preset toggle item controlling Zone 3 Geo-Unlock rules.
/// </summary>
public sealed partial class ServicePresetToggleItem : ObservableObject
{
    [ObservableProperty]
    private string _displayName = string.Empty;

    [ObservableProperty]
    private bool _isEnabled;

    public ServicePresetToggleItem(
        string id,
        string resourceKey,
        string displayName,
        IReadOnlyList<string> domains,
        bool isEnabled)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceKey);
        ArgumentNullException.ThrowIfNull(domains);

        Id = id;
        ResourceKey = resourceKey;
        _displayName = displayName;
        Domains = domains;
        _isEnabled = isEnabled;
    }

    public string Id { get; }

    public string ResourceKey { get; }

    public IReadOnlyList<string> Domains { get; }

    public int DomainCount => Domains.Count;
}

internal sealed record RuleSetJsonDto(
    List<string>? GeoUnlock,
    List<string>? Block,
    List<string>? Allow);

/// <summary>
/// ViewModel for the Routing &amp; Inspector page: Service Geo-Unlock preset toggles,
/// JSON/AdGuard/HOSTS rule import/export, and bounded (cap 2000) live query telemetry inspector.
/// </summary>
public sealed partial class RoutingInspectorViewModel : ObservableObject
{
    public const int MaxTelemetryRows = 2000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly IPulseRuntimeService _runtimeService;
    private readonly LocalizationService _localization;
    private readonly List<string> _customGeoUnlockDomains = [];
    private readonly List<string> _customBlockRules = [];
    private readonly List<string> _customAllowRules = [];
    private bool _suppressPresetPush;

    [ObservableProperty]
    private RuleFormatKind _selectedRuleFormat = RuleFormatKind.Json;

    [ObservableProperty]
    private string _customRulesInputText = string.Empty;

    [ObservableProperty]
    private string _ruleImportStatusMessage = string.Empty;

    [ObservableProperty]
    private TelemetryFilterChip _selectedFilterChip = TelemetryFilterChip.All;

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    public RoutingInspectorViewModel(
        IPulseRuntimeService runtimeService,
        LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(localization);

        _runtimeService = runtimeService;
        _localization = localization;

        _runtimeService.TelemetryReceived += OnTelemetryReceived;
        _localization.CultureChanged += OnCultureChanged;

        InitializeServicePresets();
    }

    public LocalizationService Localization => _localization;

    public ObservableCollection<ServicePresetToggleItem> ServicePresets { get; } = [];

    public ObservableCollection<DnsQueryTelemetryEvent> TelemetryEvents { get; } = [];

    public ObservableCollection<DnsQueryTelemetryEvent> FilteredTelemetryEvents { get; } = [];

    public IReadOnlyList<RuleFormatKind> AvailableRuleFormats { get; } =
    [
        RuleFormatKind.Json,
        RuleFormatKind.AdGuard,
        RuleFormatKind.Hosts
    ];

    public IReadOnlyList<TelemetryFilterChip> AvailableFilterChips { get; } =
    [
        TelemetryFilterChip.All,
        TelemetryFilterChip.GeoUnlocked,
        TelemetryFilterChip.DpiSplit,
        TelemetryFilterChip.Blocked,
        TelemetryFilterChip.Errors
    ];

    public IReadOnlyList<string> CustomGeoUnlockDomains => _customGeoUnlockDomains;

    public IReadOnlyList<string> CustomBlockRules => _customBlockRules;

    public IReadOnlyList<string> CustomAllowRules => _customAllowRules;

    /// <summary>
    /// Adds a domain to Zone 3 Geo-Unlock custom rules and pushes the updated router config.
    /// </summary>
    public async Task AddCustomGeoUnlockDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        string normalized = domain.Trim().TrimStart('*').TrimStart('.');
        if (!_customGeoUnlockDomains.Contains(normalized, StringComparer.OrdinalIgnoreCase))
        {
            _customGeoUnlockDomains.Add(normalized);
        }

        ServicePresetToggleItem? customToggle = ServicePresets.FirstOrDefault(static p => p.Id == "custom");
        if (customToggle is not null && !customToggle.IsEnabled)
        {
            customToggle.IsEnabled = true;
        }

        await PushRouterConfigurationAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies a strategy profile preset (e.g., <see cref="StrategyProfileKind.EncryptedDnsOnly"/> disables Geo-Unlock toggles).
    /// </summary>
    public async Task ApplyStrategyProfileAsync(StrategyProfileKind profile, CancellationToken cancellationToken = default)
    {
        _suppressPresetPush = true;
        try
        {
            if (profile == StrategyProfileKind.EncryptedDnsOnly)
            {
                foreach (ServicePresetToggleItem item in ServicePresets)
                {
                    item.IsEnabled = false;
                }
            }
            else if (profile is StrategyProfileKind.SmartSplitDnsGeo or StrategyProfileKind.AntiDpiHybrid)
            {
                foreach (ServicePresetToggleItem item in ServicePresets)
                {
                    if (item.Id is "google_ai_studio" or "openai" or "claude" or "copilot" or "spotify")
                    {
                        item.IsEnabled = true;
                    }
                }
            }
        }
        finally
        {
            _suppressPresetPush = false;
        }

        await PushRouterConfigurationAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Appends a telemetry event while enforcing the strict 2000-row in-memory cap.
    /// </summary>
    public void AddTelemetryEvent(DnsQueryTelemetryEvent telemetryEvent)
    {
        ArgumentNullException.ThrowIfNull(telemetryEvent);

        while (TelemetryEvents.Count >= MaxTelemetryRows)
        {
            TelemetryEvents.RemoveAt(TelemetryEvents.Count - 1);
        }

        TelemetryEvents.Insert(0, telemetryEvent);

        if (MatchesCurrentFilter(telemetryEvent))
        {
            while (FilteredTelemetryEvents.Count >= MaxTelemetryRows)
            {
                FilteredTelemetryEvents.RemoveAt(FilteredTelemetryEvents.Count - 1);
            }

            FilteredTelemetryEvents.Insert(0, telemetryEvent);
        }
    }

    /// <summary>
    /// Parses and imports custom routing rules from JSON, AdGuard filter syntax, or HOSTS format.
    /// </summary>
    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Import errors are surfaced as localized validation status.")]
    public async Task ImportRulesAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(CustomRulesInputText))
        {
            RuleImportStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Routing_Rules_ImportError"],
                "Empty input");
            return;
        }

        try
        {
            int importedCount = ImportRulesFromText(CustomRulesInputText, SelectedRuleFormat);
            await PushRouterConfigurationAsync(cancellationToken).ConfigureAwait(false);
            RuleImportStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Routing_Rules_ImportSuccess"],
                importedCount,
                SelectedRuleFormat);
        }
        catch (Exception ex)
        {
            RuleImportStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Routing_Rules_ImportError"],
                ex.Message);
        }
    }

    /// <summary>
    /// Parses rules synchronously into the ViewModel's custom lists and returns the count of imported entries.
    /// </summary>
    public int ImportRulesFromText(string content, RuleFormatKind format)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(content);

        int count = 0;
        switch (format)
        {
            case RuleFormatKind.Json:
                count = ImportJsonRules(content);
                break;

            case RuleFormatKind.AdGuard:
                IReadOnlyList<AdGuardRule> adGuardRules = RuleParsers.ParseAdGuardRules(content);
                foreach (AdGuardRule rule in adGuardRules)
                {
                    string formatted = rule.IsException
                        ? string.Concat("@@||", rule.Domain, "^")
                        : string.Concat("||", rule.Domain, "^");

                    if (rule.IsException)
                    {
                        if (!_customAllowRules.Contains(formatted, StringComparer.OrdinalIgnoreCase))
                        {
                            _customAllowRules.Add(formatted);
                            count++;
                        }
                    }
                    else if (!_customBlockRules.Contains(formatted, StringComparer.OrdinalIgnoreCase))
                    {
                        _customBlockRules.Add(formatted);
                        count++;
                    }
                }

                break;

            case RuleFormatKind.Hosts:
                IReadOnlyList<HostEntry> hostEntries = RuleParsers.ParseHostsFile(content);
                foreach (HostEntry entry in hostEntries)
                {
                    string ip = entry.Address.ToString();
                    if (ip is "0.0.0.0" or "127.0.0.1" or "::" or "::1")
                    {
                        if (!_customBlockRules.Contains(entry.Domain, StringComparer.OrdinalIgnoreCase))
                        {
                            _customBlockRules.Add(entry.Domain);
                            count++;
                        }
                    }
                    else if (!_customGeoUnlockDomains.Contains(entry.Domain, StringComparer.OrdinalIgnoreCase))
                    {
                        _customGeoUnlockDomains.Add(entry.Domain);
                        count++;
                    }
                }

                break;
        }

        OnPropertyChanged(nameof(CustomGeoUnlockDomains));
        OnPropertyChanged(nameof(CustomBlockRules));
        OnPropertyChanged(nameof(CustomAllowRules));
        return count;
    }

    /// <summary>
    /// Exports active custom rules in the selected format into <see cref="CustomRulesInputText"/>.
    /// </summary>
    [RelayCommand]
    public void ExportRules()
    {
        CustomRulesInputText = ExportRulesToText(SelectedRuleFormat);
    }

    /// <summary>
    /// Formats current custom rules in <paramref name="format"/>.
    /// </summary>
    public string ExportRulesToText(RuleFormatKind format)
    {
        switch (format)
        {
            case RuleFormatKind.Json:
                RuleSetJsonDto dto = new(
                    [.. _customGeoUnlockDomains],
                    [.. _customBlockRules],
                    [.. _customAllowRules]);
                return JsonSerializer.Serialize(dto, JsonOptions);

            case RuleFormatKind.AdGuard:
                StringBuilder adBuilder = new();
                foreach (string block in _customBlockRules)
                {
                    adBuilder.AppendLine(block.StartsWith("||", StringComparison.Ordinal) ? block : string.Concat("||", block, "^"));
                }

                foreach (string allow in _customAllowRules)
                {
                    adBuilder.AppendLine(allow.StartsWith("@@", StringComparison.Ordinal) ? allow : string.Concat("@@||", allow, "^"));
                }

                return adBuilder.ToString().TrimEnd();

            case RuleFormatKind.Hosts:
                StringBuilder hostBuilder = new();
                foreach (string block in _customBlockRules)
                {
                    string cleanDomain = block.TrimStart('|').TrimEnd('^');
                    hostBuilder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"0.0.0.0 {cleanDomain}"));
                }

                return hostBuilder.ToString().TrimEnd();

            default:
                return string.Empty;
        }
    }

    [RelayCommand]
    public void SelectFilterChip(TelemetryFilterChip chip)
    {
        SelectedFilterChip = chip;
        RebuildFilteredTelemetry();
    }

    [RelayCommand]
    public void ClearTelemetry()
    {
        TelemetryEvents.Clear();
        FilteredTelemetryEvents.Clear();
    }

    public async Task RefreshRecentTelemetryAsync(int maxCount = 200, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<DnsQueryTelemetryEvent> recent = await _runtimeService.GetRecentTelemetryAsync(maxCount, cancellationToken).ConfigureAwait(false);
        TelemetryEvents.Clear();
        foreach (DnsQueryTelemetryEvent evt in recent.Take(MaxTelemetryRows))
        {
            TelemetryEvents.Add(evt);
        }

        RebuildFilteredTelemetry();
    }

    public async Task PushRouterConfigurationAsync(CancellationToken cancellationToken = default)
    {
        List<GeoUnlockRule> geoRules = [];
        foreach (ServicePresetToggleItem preset in ServicePresets)
        {
            if (!preset.IsEnabled)
            {
                continue;
            }

            if (preset.Id == "custom")
            {
                foreach (string domain in _customGeoUnlockDomains)
                {
                    geoRules.Add(new GeoUnlockRule(domain));
                }
            }
            else
            {
                foreach (string domain in preset.Domains)
                {
                    geoRules.Add(new GeoUnlockRule(domain));
                }
            }
        }

        SplitNamespaceRouterConfig config = new()
        {
            GeoUnlockRules = geoRules,
            BlockRules = [.. _customBlockRules],
            AllowExceptionRules = [.. _customAllowRules]
        };

        await _runtimeService.UpdateRoutingConfigAsync(config, cancellationToken).ConfigureAwait(false);
    }

    partial void OnSelectedFilterChipChanged(TelemetryFilterChip value)
    {
        RebuildFilteredTelemetry();
    }

    partial void OnSearchQueryChanged(string value)
    {
        RebuildFilteredTelemetry();
    }

    private int ImportJsonRules(string json)
    {
        string trimmed = json.Trim();
        int added = 0;

        if (trimmed.StartsWith('['))
        {
            List<string>? domains = JsonSerializer.Deserialize<List<string>>(trimmed, JsonOptions);
            if (domains is null)
            {
                return 0;
            }

            foreach (string domain in domains)
            {
                string clean = domain?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(clean) &&
                    !_customGeoUnlockDomains.Contains(clean, StringComparer.OrdinalIgnoreCase))
                {
                    _customGeoUnlockDomains.Add(clean);
                    added++;
                }
            }

            return added;
        }

        RuleSetJsonDto? dto = JsonSerializer.Deserialize<RuleSetJsonDto>(trimmed, JsonOptions);
        if (dto is null)
        {
            return 0;
        }

        if (dto.GeoUnlock is not null)
        {
            foreach (string domain in dto.GeoUnlock)
            {
                string clean = domain?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(clean) &&
                    !_customGeoUnlockDomains.Contains(clean, StringComparer.OrdinalIgnoreCase))
                {
                    _customGeoUnlockDomains.Add(clean);
                    added++;
                }
            }
        }

        if (dto.Block is not null)
        {
            foreach (string rule in dto.Block)
            {
                string clean = rule?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(clean) &&
                    !_customBlockRules.Contains(clean, StringComparer.OrdinalIgnoreCase))
                {
                    _customBlockRules.Add(clean);
                    added++;
                }
            }
        }

        if (dto.Allow is not null)
        {
            foreach (string rule in dto.Allow)
            {
                string clean = rule?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(clean) &&
                    !_customAllowRules.Contains(clean, StringComparer.OrdinalIgnoreCase))
                {
                    _customAllowRules.Add(clean);
                    added++;
                }
            }
        }

        return added;
    }

    private void RebuildFilteredTelemetry()
    {
        FilteredTelemetryEvents.Clear();
        foreach (DnsQueryTelemetryEvent evt in TelemetryEvents)
        {
            if (MatchesCurrentFilter(evt))
            {
                FilteredTelemetryEvents.Add(evt);
            }
        }
    }

    private bool MatchesCurrentFilter(DnsQueryTelemetryEvent evt)
    {
        bool chipMatch = SelectedFilterChip switch
        {
            TelemetryFilterChip.All => true,
            TelemetryFilterChip.GeoUnlocked => evt.Zone == RouteZone.Zone3GeoUnlock,
            TelemetryFilterChip.DpiSplit => evt.RewrittenSvcb ||
                evt.DecisionNote.Contains("Split", StringComparison.OrdinalIgnoreCase) ||
                evt.DecisionNote.Contains("DPI", StringComparison.OrdinalIgnoreCase) ||
                evt.DecisionNote.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
                evt.DecisionNote.Contains("SNI", StringComparison.OrdinalIgnoreCase),
            TelemetryFilterChip.Blocked => evt.Zone == RouteZone.Zone2BlockOrProtect,
            TelemetryFilterChip.Errors => (evt.ResponseCode != DnsResponseCode.NoError && evt.ResponseCode != DnsResponseCode.NxDomain) ||
                evt.DecisionNote.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
                evt.DecisionNote.Contains("Fail", StringComparison.OrdinalIgnoreCase),
            _ => true
        };

        if (!chipMatch)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(SearchQuery))
        {
            return true;
        }

        string query = SearchQuery.Trim();
        return evt.Domain.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            evt.UpstreamName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            evt.DecisionNote.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void InitializeServicePresets()
    {
        AddPreset("google_ai_studio", "Routing_Preset_GoogleAiStudio",
        [
            "gemini.google.com", "aistudio.google.com", "ai.studio",
            "alkalimakersuite-pa.clients6.google.com", "generativelanguage.googleapis.com",
            "notebooklm.google.com", "labs.google", "deepmind.google"
        ], enabled: true);

        AddPreset("openai", "Routing_Preset_OpenAi",
        [
            "chatgpt.com", "openai.com", "api.openai.com", "auth.openai.com", "oaistatic.com", "oaiusercontent.com"
        ], enabled: true);

        AddPreset("claude", "Routing_Preset_Claude",
        [
            "claude.ai", "anthropic.com", "api.anthropic.com"
        ], enabled: true);

        AddPreset("copilot", "Routing_Preset_Copilot",
        [
            "copilot-proxy.githubusercontent.com", "copilot.microsoft.com", "sydney.bing.com"
        ], enabled: true);

        AddPreset("spotify", "Routing_Preset_Spotify",
        [
            "spotify.com", "open.spotify.com", "spclient.wg.spotify.com", "apresolve.spotify.com"
        ], enabled: true);

        AddPreset("youtube", "Routing_Preset_YouTube",
        [
            "youtube.com", "www.youtube.com", "youtu.be", "googlevideo.com"
        ], enabled: false);

        AddPreset("twitch", "Routing_Preset_Twitch",
        [
            "twitch.tv", "www.twitch.tv", "gql.twitch.tv"
        ], enabled: false);

        AddPreset("gaming", "Routing_Preset_Gaming",
        [
            "xboxlive.com", "xbox.com", "login.live.com",
            "playstation.com", "playstation.net",
            "brawlstars.com", "supercell.com", "game.brawlstarsgame.com"
        ], enabled: false);

        AddPreset("discord", "Routing_Preset_Discord",
        [
            "discord.com", "discord.gg", "gateway.discord.gg", "cdn.discordapp.com"
        ], enabled: false);

        AddPreset("custom", "Routing_Preset_Custom", [], enabled: true);
    }

    private void AddPreset(string id, string resourceKey, IReadOnlyList<string> domains, bool enabled)
    {
        ServicePresetToggleItem item = new(id, resourceKey, _localization[resourceKey], domains, enabled);
        item.PropertyChanged += async (_, args) =>
        {
            if (!_suppressPresetPush && string.Equals(args.PropertyName, nameof(ServicePresetToggleItem.IsEnabled), StringComparison.Ordinal))
            {
                await PushRouterConfigurationAsync().ConfigureAwait(false);
            }
        };

        ServicePresets.Add(item);
    }

    private void OnTelemetryReceived(object? sender, DnsQueryTelemetryEventArgs e)
    {
        AddTelemetryEvent(e.TelemetryEvent);
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        foreach (ServicePresetToggleItem preset in ServicePresets)
        {
            preset.DisplayName = _localization[preset.ResourceKey];
        }
    }
}
