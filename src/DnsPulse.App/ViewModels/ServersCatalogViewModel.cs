using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Data;
using DnsPulse.App.Localization;
using DnsPulse.App.Services;
using DnsPulse.Core.Models;
using DnsPulse.Engine.Diagnostics;
using DnsPulse.Engine.Discovery;
using DnsPulse.Engine.Feeds;
using DnsPulse.Platform.Windows.Autostart;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Event arguments carrying the <see cref="DnsServerEntry"/> activated from the catalog.
/// </summary>
public sealed class ServerActivatedEventArgs(DnsServerEntry server) : EventArgs
{
    public DnsServerEntry Server { get; } = server ?? throw new ArgumentNullException(nameof(server));
}

/// <summary>
/// Event arguments carrying bypass domains discovered via signed feed synchronization.
/// </summary>
public sealed class FeedBypassDomainsDiscoveredEventArgs(IReadOnlyList<string> domains) : EventArgs
{
    public IReadOnlyList<string> Domains { get; } = domains ?? throw new ArgumentNullException(nameof(domains));
}

/// <summary>
/// Sort modes available for the DNS server catalog.
/// </summary>
public enum ServerSortOrder
{
    P50Latency = 0,
    Protocol = 1,
    TrustTier = 2,
    Name = 3
}

/// <summary>
/// Localized Trust Tier section metadata and server items.
/// </summary>
public sealed class TrustTierSectionInfo
{
    public TrustTierSectionInfo(TrustTier tier, string title, string description)
    {
        Tier = tier;
        Title = title;
        Description = description;
    }

    public TrustTier Tier { get; }

    public string Title { get; }

    public string Description { get; }

    public ObservableCollection<DnsServerEntry> Servers { get; } = [];
}

/// <summary>
/// Localized task-category chip metadata for the unified server catalog filter bar.
/// </summary>
public sealed partial class ServerCategoryFilterOption : ObservableObject
{
    [ObservableProperty]
    private string _title = string.Empty;

    [ObservableProperty]
    private string _description = string.Empty;

    [ObservableProperty]
    private int _count;

    public ServerCategoryFilterOption(
        ServerDisplayCategory? category,
        string titleResourceKey,
        string descriptionResourceKey,
        string title,
        string description,
        int count = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(titleResourceKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(descriptionResourceKey);

        Category = category;
        TitleResourceKey = titleResourceKey;
        DescriptionResourceKey = descriptionResourceKey;
        _title = title;
        _description = description;
        _count = count;
    }

    public ServerDisplayCategory? Category { get; }

    public string TitleResourceKey { get; }

    public string DescriptionResourceKey { get; }
}

/// <summary>
/// ViewModel for Servers &amp; Catalog: 4-tier trust categorization, section BenchmarkRunner,
/// <c>sdns://</c>/profile import, Self-Hosted VPS Wizard, and Signed Feed Sync.
/// </summary>
public sealed partial class ServersCatalogViewModel : ObservableObject, IDisposable
{
    private static readonly char[] CommaSeparators = [',', ';', '\r', '\n'];

    private readonly PulseCatalogRepository _repository;
    private readonly IPulseRuntimeService _runtimeService;
    private readonly LocalizationService _localization;
    private readonly SelfHostedVpsGenerator _vpsGenerator = new();
    private readonly List<DnsServerEntry> _allServers = [];

    private CancellationTokenSource? _benchmarkCts;
    private bool _disposed;

    [ObservableProperty]
    private TrustTier? _selectedTrustTierFilter;

    [ObservableProperty]
    private ServerDisplayCategory? _selectedCategoryFilter;

    [ObservableProperty]
    private int _allCount;

    [ObservableProperty]
    private int _aiGeoCount;

    [ObservableProperty]
    private int _fastEncryptedCount;

    [ObservableProperty]
    private int _streamingGamingCount;

    [ObservableProperty]
    private int _customCount;

    [ObservableProperty]
    private bool _showFavoritesOnly;

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private ServerSortOrder _selectedSortOrder = ServerSortOrder.P50Latency;

    [ObservableProperty]
    private DnsServerEntry? _selectedServer;

    [ObservableProperty]
    private bool _isBenchmarkRunning;

    [ObservableProperty]
    private double _benchmarkProgressPercent;

    [ObservableProperty]
    private int _benchmarkCompletedCount;

    [ObservableProperty]
    private int _benchmarkTotalCount;

    [ObservableProperty]
    private string _benchmarkTargetDomain = "aistudio.google.com";

    [ObservableProperty]
    private string _importInputText = string.Empty;

    [ObservableProperty]
    private string _importCustomName = string.Empty;

    [ObservableProperty]
    private string _importStatusMessage = string.Empty;

    [ObservableProperty]
    private string _vpsHostName = string.Empty;

    [ObservableProperty]
    private string _vpsServerIp = string.Empty;

    [ObservableProperty]
    private string _vpsAllowedCidrs = string.Empty;

    [ObservableProperty]
    private string _vpsGeoDomains = "gemini.google.com, aistudio.google.com, chatgpt.com";

    [ObservableProperty]
    private int _vpsHttpsPort = 443;

    [ObservableProperty]
    private int _vpsDotPort = 853;

    [ObservableProperty]
    private string _vpsProfileName = "My Self-Hosted DNS Pulse VPS";

    [ObservableProperty]
    private SelfHostedVpsBundle? _generatedVpsBundle;

    [ObservableProperty]
    private string? _vpsValidationError;

    [ObservableProperty]
    private bool _allowUnsignedFeeds;

    [ObservableProperty]
    private bool _isSyncingFeeds;

    [ObservableProperty]
    private string _feedSyncStatusMessage = string.Empty;

    [ObservableProperty]
    private FeedSyncSummary? _lastFeedSyncSummary;

    public ServersCatalogViewModel(
        PulseCatalogRepository repository,
        IPulseRuntimeService runtimeService,
        LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(runtimeService);
        ArgumentNullException.ThrowIfNull(localization);

        _repository = repository;
        _runtimeService = runtimeService;
        _localization = localization;

        _localization.CultureChanged += OnCultureChanged;
        InitializeCategoryFilterOptions();
        RebuildTierSections();
    }

    public event EventHandler<ServerActivatedEventArgs>? ServerActivated;

    public event EventHandler<FeedBypassDomainsDiscoveredEventArgs>? FeedBypassDomainsDiscovered;

    public LocalizationService Localization => _localization;

    public IReadOnlyList<DnsServerEntry> AllServers => _allServers;

    public ObservableCollection<DnsServerEntry> FilteredServers { get; } = [];

    public ObservableCollection<ServerCategoryFilterOption> CategoryFilterOptions { get; } = [];

    public string ActiveCategoryDescription => SelectedCategoryFilter switch
    {
        ServerDisplayCategory.AiAndGeoUnlock => _localization["Servers_Category_AiGeo_Desc"],
        ServerDisplayCategory.FastEncrypted => _localization["Servers_Category_FastEncrypted_Desc"],
        ServerDisplayCategory.StreamingAndGaming => _localization["Servers_Category_StreamingGaming_Desc"],
        ServerDisplayCategory.CustomAndDiscovered => _localization["Servers_Category_Custom_Desc"],
        _ => _localization["Servers_Category_All"]
    };

    public ObservableCollection<DnsServerEntry> Tier1Servers { get; } = [];

    public ObservableCollection<DnsServerEntry> Tier2Servers { get; } = [];

    public ObservableCollection<DnsServerEntry> Tier3Servers { get; } = [];

    public ObservableCollection<DnsServerEntry> Tier4Servers { get; } = [];

    public ObservableCollection<TrustTierSectionInfo> TrustTierSections { get; } = [];

    public IReadOnlyList<ServerSortOrder> AvailableSortOrders { get; } =
    [
        ServerSortOrder.P50Latency,
        ServerSortOrder.Protocol,
        ServerSortOrder.TrustTier,
        ServerSortOrder.Name
    ];

    public async Task LoadCatalogAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<DnsServerEntry> loaded = await _repository.GetAllAsync(cancellationToken).ConfigureAwait(false);
        _allServers.Clear();
        _allServers.AddRange(loaded);
        if (_runtimeService is HybridPulseRuntimeService hybridRuntime)
        {
            hybridRuntime.SetCatalogSnapshot(_allServers);
        }

        ApplyFilterAndSort();
    }

    public void ApplyProbedServerUpdate(DnsServerEntry updatedServer)
    {
        ArgumentNullException.ThrowIfNull(updatedServer);
        UpsertInMemory(updatedServer);
        ApplyFilterAndSort();
    }

    [RelayCommand]
    public Task RefreshFromRepositoryAsync(CancellationToken cancellationToken = default)
    {
        return LoadCatalogAsync(cancellationToken);
    }

    [RelayCommand]
    public void SelectCategory(ServerDisplayCategory? category)
    {
        bool hadTierFilter = SelectedTrustTierFilter is not null;
        SelectedTrustTierFilter = null;
        if (SelectedCategoryFilter == category && hadTierFilter)
        {
            ApplyFilterAndSort();
            return;
        }

        SelectedCategoryFilter = category;
    }

    [RelayCommand]
    public void SelectTrustTierFilter(TrustTier? tier)
    {
        bool hadCategoryFilter = SelectedCategoryFilter is not null;
        SelectedCategoryFilter = null;
        if (SelectedTrustTierFilter == tier && hadCategoryFilter)
        {
            ApplyFilterAndSort();
            return;
        }

        SelectedTrustTierFilter = tier;
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Import validation errors are surfaced to the user via ImportStatusMessage.")]
    public async Task ImportEndpointAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ImportInputText))
        {
            ImportStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Error_InvalidInput"],
                "Empty endpoint");
            return;
        }

        try
        {
            string trimmed = ImportInputText.Trim();
            IReadOnlyList<DnsServerEntry> imported;
            if (trimmed.Contains('\n', StringComparison.Ordinal) || trimmed.StartsWith('[') || trimmed.StartsWith('{'))
            {
                imported = await _repository.ImportFromTextAsync(trimmed, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                DnsServerEntry single = await _repository.UpsertFromEndpointOrStampAsync(
                    trimmed,
                    string.IsNullOrWhiteSpace(ImportCustomName) ? null : ImportCustomName.Trim(),
                    overrideTier: null,
                    cancellationToken).ConfigureAwait(false);
                imported = [single];
            }

            foreach (DnsServerEntry entry in imported)
            {
                UpsertInMemory(entry);
            }

            ApplyFilterAndSort();
            ImportInputText = string.Empty;
            ImportCustomName = string.Empty;
            ImportStatusMessage = string.Create(CultureInfo.InvariantCulture, $"+{imported.Count}");
        }
        catch (Exception ex)
        {
            ImportStatusMessage = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Error_InvalidInput"],
                ex.Message);
        }
    }

    [RelayCommand]
    public async Task ToggleFavoriteAsync(DnsServerEntry? entry, CancellationToken cancellationToken = default)
    {
        if (entry is null)
        {
            return;
        }

        bool newFav = !entry.IsFavorite;
        await _repository.SetFavoriteAsync(entry.Id, newFav, cancellationToken).ConfigureAwait(false);

        DnsServerEntry updated = entry with { IsFavorite = newFav };
        UpsertInMemory(updated);
        ApplyFilterAndSort();
    }

    [RelayCommand]
    public void SelectActiveServer(DnsServerEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        SelectedServer = entry;
        ServerActivated?.Invoke(this, new ServerActivatedEventArgs(entry));
    }

    [RelayCommand]
    public async Task RunSectionBenchmarkAsync(PulseAppSettings? settings = null, CancellationToken cancellationToken = default)
    {
        if (IsBenchmarkRunning)
        {
            return;
        }

        List<DnsServerEntry> targets = [.. FilteredServers];
        if (targets.Count == 0)
        {
            return;
        }

        _benchmarkCts?.Dispose();
        _benchmarkCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        IsBenchmarkRunning = true;
        BenchmarkCompletedCount = 0;
        BenchmarkTotalCount = targets.Count;
        BenchmarkProgressPercent = 0;

        string domain = string.IsNullOrWhiteSpace(BenchmarkTargetDomain) ? "aistudio.google.com" : BenchmarkTargetDomain.Trim();
        PulseAppSettings effectiveSettings = settings ?? new PulseAppSettings();
        bool runFullSixLayer = SelectedCategoryFilter is ServerDisplayCategory.AiAndGeoUnlock
            or ServerDisplayCategory.StreamingAndGaming
            or ServerDisplayCategory.CustomAndDiscovered
            || (SelectedCategoryFilter is null && targets.Any(static s => s.SupportsBypass));

        BenchmarkOptions options = new()
        {
            MaxConcurrency = Math.Clamp(effectiveSettings.BenchmarkConcurrency, 2, 16),
            SamplesPerServer = 3,
            ProbeTimeout = TimeSpan.FromMilliseconds(Math.Clamp(effectiveSettings.ProbeTimeoutMs, 1000, 6000)),
            RunFullSixLayerDiagnostics = runFullSixLayer
        };

        try
        {
            BenchmarkRunner runner = _runtimeService.CreateBenchmarkRunner();
            await foreach (BenchmarkProgressUpdate update in runner.StreamAsync(targets, domain, options, _benchmarkCts.Token).ConfigureAwait(false))
            {
                await _repository.UpdateProbeMetricsAsync(update.UpdatedServer, _benchmarkCts.Token).ConfigureAwait(false);
                UpsertInMemory(update.UpdatedServer);

                BenchmarkCompletedCount = update.CompletedCount;
                BenchmarkProgressPercent = Math.Round((double)update.CompletedCount / update.TotalCount * 100.0, 1);
            }

            ApplyFilterAndSort();
        }
        catch (OperationCanceledException)
        {
            // Benchmark cancelled by user.
        }
        finally
        {
            IsBenchmarkRunning = false;
        }
    }

    [RelayCommand]
    public void CancelBenchmark()
    {
        _benchmarkCts?.Cancel();
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "VPS wizard validation errors are presented inline via VpsValidationError.")]
    public void GenerateVpsBundle()
    {
        VpsValidationError = null;
        try
        {
            string[] cidrs = [.. VpsAllowedCidrs.Split(CommaSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
            string[] geoDomains = [.. VpsGeoDomains.Split(CommaSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

            SelfHostedVpsOptions options = new()
            {
                HostName = VpsHostName,
                ServerIpAddress = VpsServerIp,
                AllowedClientCidrs = cidrs,
                TargetGeoUnlockDomains = geoDomains,
                HttpsPort = VpsHttpsPort,
                DotPort = VpsDotPort,
                ProfileName = VpsProfileName
            };

            GeneratedVpsBundle = _vpsGenerator.Generate(options);
        }
        catch (Exception ex)
        {
            GeneratedVpsBundle = null;
            VpsValidationError = string.Format(
                CultureInfo.CurrentCulture,
                _localization["Error_InvalidInput"],
                ex.Message);
        }
    }

    [RelayCommand]
    public async Task AddGeneratedVpsToCatalogAsync(CancellationToken cancellationToken = default)
    {
        if (GeneratedVpsBundle is null)
        {
            return;
        }

        DnsServerEntry entry = GeneratedVpsBundle.ServerEntry with
        {
            TrustTier = TrustTier.Tier3CustomOrSelfHosted,
            IsFavorite = true
        };

        await _repository.UpsertServerAsync(entry, cancellationToken).ConfigureAwait(false);
        UpsertInMemory(entry);
        ApplyFilterAndSort();
    }

    [RelayCommand]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Feed sync errors are surfaced via FeedSyncStatusMessage.")]
    public async Task SyncFeedsAsync(CancellationToken cancellationToken = default)
    {
        if (IsSyncingFeeds)
        {
            return;
        }

        IsSyncingFeeds = true;
        try
        {
            using SignedFeedSyncService feedService = new(_runtimeService.BootstrapResolver);
            FeedVerificationMode mode = AllowUnsignedFeeds
                ? FeedVerificationMode.AllowUnsignedFeeds
                : FeedVerificationMode.RequireSigned;

            FeedSyncSummary summary = await feedService.SyncAllAsync(mode, cancellationToken: cancellationToken).ConfigureAwait(false);
            LastFeedSyncSummary = summary;

            if (summary.AggregatedServers.Count > 0)
            {
                await _repository.UpsertServersAsync(summary.AggregatedServers, cancellationToken).ConfigureAwait(false);
                foreach (DnsServerEntry server in summary.AggregatedServers)
                {
                    UpsertInMemory(server);
                }

                ApplyFilterAndSort();
            }

            if (summary.AggregatedBypassDomains.Count > 0)
            {
                FeedBypassDomainsDiscovered?.Invoke(this, new FeedBypassDomainsDiscoveredEventArgs(summary.AggregatedBypassDomains));
            }

            FeedSyncStatusMessage = string.Create(
                CultureInfo.InvariantCulture,
                $"{summary.AggregatedServers.Count} servers, {summary.AggregatedBypassDomains.Count} domains ({mode})");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            FeedSyncStatusMessage = ex.Message;
        }
        finally
        {
            IsSyncingFeeds = false;
        }
    }

    public void ApplyFilterAndSort()
    {
        IEnumerable<DnsServerEntry> baseQuery = _allServers;

        if (ShowFavoritesOnly)
        {
            baseQuery = baseQuery.Where(static s => s.IsFavorite);
        }

        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            string search = SearchQuery.Trim();
            baseQuery = baseQuery.Where(s =>
                s.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                s.Provider.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                s.EndpointLabel.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                s.Country.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        List<DnsServerEntry> sortedAll = [.. SortEntries(baseQuery)];

        int aiGeoCount = 0;
        int fastEncryptedCount = 0;
        int streamingGamingCount = 0;
        int customCount = 0;

        List<DnsServerEntry> nextFiltered = [];
        List<DnsServerEntry> nextTier1 = [];
        List<DnsServerEntry> nextTier2 = [];
        List<DnsServerEntry> nextTier3 = [];
        List<DnsServerEntry> nextTier4 = [];

        foreach (DnsServerEntry entry in sortedAll)
        {
            ServerDisplayCategory displayCategory = ServerCategoryClassifier.Classify(entry);
            switch (displayCategory)
            {
                case ServerDisplayCategory.AiAndGeoUnlock:
                    aiGeoCount++;
                    break;
                case ServerDisplayCategory.FastEncrypted:
                    fastEncryptedCount++;
                    break;
                case ServerDisplayCategory.StreamingAndGaming:
                    streamingGamingCount++;
                    break;
                case ServerDisplayCategory.CustomAndDiscovered:
                    customCount++;
                    break;
            }

            switch (entry.TrustTier)
            {
                case TrustTier.Tier1EncryptedTrusted:
                    nextTier1.Add(entry);
                    break;
                case TrustTier.Tier2VerifiedGeoUnlock:
                    nextTier2.Add(entry);
                    break;
                case TrustTier.Tier3CustomOrSelfHosted:
                    nextTier3.Add(entry);
                    break;
                case TrustTier.Tier4ExperimentalLab:
                    nextTier4.Add(entry);
                    break;
            }

            bool matchesCategory = SelectedCategoryFilter is not ServerDisplayCategory categoryFilter || displayCategory == categoryFilter;
            bool matchesTier = SelectedCategoryFilter is not null || SelectedTrustTierFilter is not TrustTier tierFilter || entry.TrustTier == tierFilter;
            if (matchesCategory && matchesTier)
            {
                nextFiltered.Add(entry);
            }
        }

        RunOnUiThread(() =>
        {
            FilteredServers.Clear();
            foreach (DnsServerEntry entry in nextFiltered)
            {
                FilteredServers.Add(entry);
            }

            Tier1Servers.Clear();
            foreach (DnsServerEntry entry in nextTier1)
            {
                Tier1Servers.Add(entry);
            }

            Tier2Servers.Clear();
            foreach (DnsServerEntry entry in nextTier2)
            {
                Tier2Servers.Add(entry);
            }

            Tier3Servers.Clear();
            foreach (DnsServerEntry entry in nextTier3)
            {
                Tier3Servers.Add(entry);
            }

            Tier4Servers.Clear();
            foreach (DnsServerEntry entry in nextTier4)
            {
                Tier4Servers.Add(entry);
            }

            foreach (TrustTierSectionInfo section in TrustTierSections)
            {
                section.Servers.Clear();
                List<DnsServerEntry> bucket = section.Tier switch
                {
                    TrustTier.Tier1EncryptedTrusted => nextTier1,
                    TrustTier.Tier2VerifiedGeoUnlock => nextTier2,
                    TrustTier.Tier3CustomOrSelfHosted => nextTier3,
                    TrustTier.Tier4ExperimentalLab => nextTier4,
                    _ => []
                };

                foreach (DnsServerEntry entry in bucket)
                {
                    section.Servers.Add(entry);
                }
            }

            AllCount = sortedAll.Count;
            AiGeoCount = aiGeoCount;
            FastEncryptedCount = fastEncryptedCount;
            StreamingGamingCount = streamingGamingCount;
            CustomCount = customCount;
            UpdateCategoryFilterCounts();
        });
    }

    private static void RunOnUiThread(Action action)
    {
        Dispatcher? dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is not null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(action);
            return;
        }

        action();
    }

    private IOrderedEnumerable<DnsServerEntry> SortEntries(IEnumerable<DnsServerEntry> query)
    {
        return SelectedSortOrder switch
        {
            ServerSortOrder.P50Latency => query
                .OrderByDescending(static s => s.IsFavorite)
                .ThenBy(static s => s.Verdict switch
                {
                    DiagnosticVerdict.Healthy => 0,
                    DiagnosticVerdict.TlsSniDpiReset => 1,
                    DiagnosticVerdict.Unknown => 2,
                    _ => 3
                })
                .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue)
                .ThenBy(static s => s.Name, StringComparer.OrdinalIgnoreCase),
            ServerSortOrder.Protocol => query
                .OrderBy(static s => s.Protocol.ToString(), StringComparer.OrdinalIgnoreCase)
                .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue),
            ServerSortOrder.TrustTier => query
                .OrderBy(static s => (int)ServerCategoryClassifier.Classify(s))
                .ThenBy(static s => (int)s.TrustTier)
                .ThenBy(static s => s.LatencyP50Ms ?? s.LastLatencyMs ?? double.MaxValue),
            _ => query.OrderBy(static s => s.Name, StringComparer.OrdinalIgnoreCase)
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _localization.CultureChanged -= OnCultureChanged;
        _benchmarkCts?.Cancel();
        _benchmarkCts?.Dispose();
        _benchmarkCts = null;
    }

    partial void OnSelectedTrustTierFilterChanged(TrustTier? value) => ApplyFilterAndSort();

    partial void OnSelectedCategoryFilterChanged(ServerDisplayCategory? value)
    {
        ApplyFilterAndSort();
        OnPropertyChanged(nameof(ActiveCategoryDescription));
    }

    partial void OnShowFavoritesOnlyChanged(bool value) => ApplyFilterAndSort();

    partial void OnSearchQueryChanged(string value) => ApplyFilterAndSort();

    partial void OnSelectedSortOrderChanged(ServerSortOrder value) => ApplyFilterAndSort();

    private void UpsertInMemory(DnsServerEntry entry)
    {
        int existingIndex = _allServers.FindIndex(s => string.Equals(s.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
        if (existingIndex >= 0)
        {
            _allServers[existingIndex] = entry;
        }
        else
        {
            _allServers.Add(entry);
        }

        if (_runtimeService is HybridPulseRuntimeService hybridRuntime)
        {
            hybridRuntime.SetCatalogSnapshot(_allServers);
        }
    }

    private void InitializeCategoryFilterOptions()
    {
        CategoryFilterOptions.Clear();
        CategoryFilterOptions.Add(new ServerCategoryFilterOption(
            null,
            "Servers_Category_All",
            "Servers_Category_All",
            _localization["Servers_Category_All"],
            _localization["Servers_Category_All"]));
        CategoryFilterOptions.Add(new ServerCategoryFilterOption(
            ServerDisplayCategory.AiAndGeoUnlock,
            "Servers_Category_AiGeo",
            "Servers_Category_AiGeo_Desc",
            _localization["Servers_Category_AiGeo"],
            _localization["Servers_Category_AiGeo_Desc"]));
        CategoryFilterOptions.Add(new ServerCategoryFilterOption(
            ServerDisplayCategory.FastEncrypted,
            "Servers_Category_FastEncrypted",
            "Servers_Category_FastEncrypted_Desc",
            _localization["Servers_Category_FastEncrypted"],
            _localization["Servers_Category_FastEncrypted_Desc"]));
        CategoryFilterOptions.Add(new ServerCategoryFilterOption(
            ServerDisplayCategory.StreamingAndGaming,
            "Servers_Category_StreamingGaming",
            "Servers_Category_StreamingGaming_Desc",
            _localization["Servers_Category_StreamingGaming"],
            _localization["Servers_Category_StreamingGaming_Desc"]));
        CategoryFilterOptions.Add(new ServerCategoryFilterOption(
            ServerDisplayCategory.CustomAndDiscovered,
            "Servers_Category_Custom",
            "Servers_Category_Custom_Desc",
            _localization["Servers_Category_Custom"],
            _localization["Servers_Category_Custom_Desc"]));
    }

    private void UpdateCategoryFilterCounts()
    {
        foreach (ServerCategoryFilterOption option in CategoryFilterOptions)
        {
            option.Count = option.Category switch
            {
                null => AllCount,
                ServerDisplayCategory.AiAndGeoUnlock => AiGeoCount,
                ServerDisplayCategory.FastEncrypted => FastEncryptedCount,
                ServerDisplayCategory.StreamingAndGaming => StreamingGamingCount,
                ServerDisplayCategory.CustomAndDiscovered => CustomCount,
                _ => 0
            };
        }
    }

    private void RebuildTierSections()
    {
        TrustTierSections.Clear();
        TrustTierSections.Add(new TrustTierSectionInfo(
            TrustTier.Tier1EncryptedTrusted,
            _localization["Servers_Tier1_Title"],
            _localization["Servers_Tier1_Desc"]));
        TrustTierSections.Add(new TrustTierSectionInfo(
            TrustTier.Tier2VerifiedGeoUnlock,
            _localization["Servers_Tier2_Title"],
            _localization["Servers_Tier2_Desc"]));
        TrustTierSections.Add(new TrustTierSectionInfo(
            TrustTier.Tier3CustomOrSelfHosted,
            _localization["Servers_Tier3_Title"],
            _localization["Servers_Tier3_Desc"]));
        TrustTierSections.Add(new TrustTierSectionInfo(
            TrustTier.Tier4ExperimentalLab,
            _localization["Servers_Tier4_Title"],
            _localization["Servers_Tier4_Desc"]));

        ApplyFilterAndSort();
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        foreach (ServerCategoryFilterOption option in CategoryFilterOptions)
        {
            option.Title = _localization[option.TitleResourceKey];
            option.Description = _localization[option.DescriptionResourceKey];
        }

        OnPropertyChanged(nameof(ActiveCategoryDescription));
        RebuildTierSections();
    }
}
