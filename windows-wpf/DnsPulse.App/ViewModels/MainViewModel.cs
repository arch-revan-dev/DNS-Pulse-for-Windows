using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;
using DnsPulse.App.Services;

namespace DnsPulse.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly DnsDatabaseRepository _repo;
    private readonly FourStageProber _prober = new();
    private readonly LocalDnsTunnelServer _tunnel = new();
    private readonly WindowsNetworkAdapterService _adapter;
    private readonly OnlineFeedSyncService _feedSync = new();
    private readonly AppUpdateService _updater = new();
    private readonly AppSettingsService _settingsService;
    private readonly SubnetScannerService _scanner = new();
    private readonly Action<Action> _dispatchToUi;

    private AppSettings _settings;
    private bool _isApplyingSettings;
    private List<DnsServerEntry> _allServers = [];
    private List<DnsServerEntry> _filteredServers = [];
    private AppReleaseInfo? _availableRelease;
    private CancellationTokenSource? _liveCts;
    private CancellationTokenSource? _benchmarkCts;
    private CancellationTokenSource? _autoModeCts;
    private CancellationTokenSource? _searchDebounceCts;
    private bool _startupSyncStarted;
    private DateTime _lastAutoFailoverCheckUtc = DateTime.MinValue;

    public event Action<bool, string>? OnVisualSettingsChanged;

    public static IReadOnlyList<string> BootstrapDnsOptions { get; } = ["Auto", "1.1.1.1", "8.8.8.8", "9.9.9.9"];

    private static readonly IReadOnlyList<DomainPresetItem> AllPresets =
    [
        new("gemini", "ai", "Gemini", "gemini.google.com", true, true),
        new("aistudio", "ai", "AI Studio", "aistudio.google.com", true, false),
        new("chatgpt", "ai", "ChatGPT", "chatgpt.com", true, false),
        new("claude", "ai", "Claude", "claude.ai", true, false),
        new("copilot", "ai", "Copilot", "copilot.microsoft.com", true, false),

        new("spotify", "streaming", "Spotify", "open.spotify.com", true, false),
        new("youtube", "streaming", "YouTube", "www.youtube.com", true, false),
        new("twitch", "streaming", "Twitch", "www.twitch.tv", true, false),
        new("netflix", "streaming", "Netflix", "www.netflix.com", true, false),

        new("xbox", "gaming", "Xbox Live", "login.live.com", true, false),
        new("brawlstars", "gaming", "Brawl Stars", "game.brawlstarsgame.com", true, false),
        new("steam", "gaming", "Steam", "store.steampowered.com", true, false),
        new("epic", "gaming", "Epic Games", "store.epicgames.com", true, false),

        new("cfping", "all", "Cloudflare Ping", "one.one.one.one", false, false),
        new("google", "all", "Google Search", "www.google.com", false, false)
    ];

    private static readonly string[] CategoryNames =
    [
        "Все",
        "Smart-DNS",
        "Скоростные",
        "Антиреклама",
        "Игры и Регионы",
        "Магистральные",
        "Свои / Найденные"
    ];

    public ObservableCollection<DnsServerEntry> VisibleServers { get; } = [];
    public ObservableCollection<CategoryFilterItem> Categories { get; } = [];
    public ObservableCollection<PresetGroupItem> PresetGroups { get; } = [];
    public ObservableCollection<DomainPresetItem> ActivePresets { get; } = [];

    [ObservableProperty]
    private int _activeTabIndex;

    [ObservableProperty]
    private string _targetDomain = "gemini.google.com";

    [ObservableProperty]
    private bool _requiresBypass = true;

    [ObservableProperty]
    private string _selectedPresetGroup = "ai";

    [ObservableProperty]
    private string _activeGroupLabel = "ИИ";

    [ObservableProperty]
    private string _selectedCategory = "Все";

    [ObservableProperty]
    private SortMode _selectedSortMode = SortMode.BEST;

    [ObservableProperty]
    private bool _bypassOnly;

    [ObservableProperty]
    private bool _favoritesOnly;

    [ObservableProperty]
    private bool _encryptedOnly;

    [ObservableProperty]
    private bool _freeOnly;

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private int _visibleLimit = 120;

    [ObservableProperty]
    private bool _isLiveRunning;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusMessage = "Готово к диагностике";

    [ObservableProperty]
    private DnsServerEntry? _selectedServer;

    [ObservableProperty]
    private bool _isInspectorOpen;

    [ObservableProperty]
    private bool _isDarkTheme = true;

    [ObservableProperty]
    private string _accentPreset = "Emerald";

    [ObservableProperty]
    private bool _compactMode;

    [ObservableProperty]
    private bool _startWithWindows;

    [ObservableProperty]
    private bool _startMinimizedToTray = true;

    [ObservableProperty]
    private bool _minimizeToTrayOnClose = true;

    [ObservableProperty]
    private bool _autoModeEnabled;

    [ObservableProperty]
    private bool _autoFailoverOnDrop = true;

    [ObservableProperty]
    private bool _isAutoModeRunning;

    [ObservableProperty]
    private bool _autoCheckUpdates = true;

    [ObservableProperty]
    private string _gitHubToken = string.Empty;

    [ObservableProperty]
    private bool _autoSyncFeedsOnStartup = true;

    [ObservableProperty]
    private bool _blockIpv6OnBypass = true;

    [ObservableProperty]
    private string _bootstrapDnsProvider = "Auto";

    [ObservableProperty]
    private int _probeTimeoutMs = 2600;

    [ObservableProperty]
    private int _benchmarkConcurrency = 6;

    [ObservableProperty]
    private string _autostartStatusText = "Автозапуск отключён";

    [ObservableProperty]
    private string _importEditorText =
        "https://dns.bezmezhau.com/dns-query Bezmezhau Public\r\n" +
        "https://dns.magicdns.ru/dns-query MagicDNS\r\n" +
        "176.99.11.77 Xbox-DNS";

    [ObservableProperty]
    private string _configFeedback = string.Empty;

    [ObservableProperty]
    private int _cachedHostsCount;

    [ObservableProperty]
    private bool _splitTunnelEnabled = true;

    [ObservableProperty]
    private bool _isBenchmarkRunning;

    [ObservableProperty]
    private int _benchmarkDone;

    [ObservableProperty]
    private int _benchmarkTotal;

    [ObservableProperty]
    private int _benchmarkWorkingCount;

    [ObservableProperty]
    private string _benchmarkScopeLabel = "Проверка";

    [ObservableProperty]
    private bool _hasAvailableUpdate;

    [ObservableProperty]
    private bool _isCheckingUpdates;

    [ObservableProperty]
    private bool _isUpdatingApp;

    [ObservableProperty]
    private double _updateProgressPercent;

    [ObservableProperty]
    private string _updateStatusText = $"Версия {AppUpdateService.GetCurrentVersion()} (нажмите для проверки)";

    [ObservableProperty]
    private string _availableVersionText = string.Empty;

    public string CurrentVersionText => $"v{AppUpdateService.GetCurrentVersion()}";
    public string UpdateBannerText => HasAvailableUpdate
        ? $"Доступна новая версия DNS Pulse {AvailableVersionText} (текущая {CurrentVersionText}) — обновление прямо внутри программы"
        : string.Empty;

    public bool IsElevated => WindowsNetworkAdapterService.IsElevated();
    public bool NeedsElevationForSystemDns => !IsElevated;
    public string BenchmarkProgressText => IsBenchmarkRunning && BenchmarkTotal > 0
        ? $"{BenchmarkScopeLabel}: {BenchmarkDone} / {BenchmarkTotal} · Рабочих: {BenchmarkWorkingCount}"
        : string.Empty;
    public double BenchmarkProgressPercent => BenchmarkTotal > 0
        ? BenchmarkDone * 100.0 / BenchmarkTotal
        : 0;
    public string ModeExplanationText => RequiresBypass
        ? $"Режим обхода (4 этапа): 1) DNS-ответ -> 2) Фильтр прямого IP ({TargetDomain}) -> 3) TLS порт 443 -> 4) Проверка блока региона (403/available-regions)"
        : $"Чистый пинг: проверка скорости и стабильности DNS для {TargetDomain} без требования Smart-DNS обхода";

    public bool IsTesterTab => ActiveTabIndex == 0;
    public bool IsCatalogTab => ActiveTabIndex == 1;
    public bool IsConfigsTab => ActiveTabIndex == 2;
    public bool IsSettingsTab => ActiveTabIndex == 3;
    public bool IsCustomPresetGroup => SelectedPresetGroup == "custom";
    public bool HasActiveFilters =>
        SelectedCategory != "Все" || BypassOnly || FavoritesOnly || EncryptedOnly || FreeOnly || !string.IsNullOrWhiteSpace(SearchQuery);

    public string BenchmarkButtonText => FilteredCount > 0
        ? $"Тест раздела ({FilteredCount})"
        : "Тест раздела";

    public System.Windows.Thickness ServerRowPadding => CompactMode
        ? new System.Windows.Thickness(12, 6, 12, 6)
        : new System.Windows.Thickness(14, 10, 14, 10);

    public string AutoModeLabel => IsAutoModeRunning
        ? "Автоподбор..."
        : AutoModeEnabled
            ? "Авторежим ВКЛ"
            : "Авторежим";

    public bool IsTunnelActive => _tunnel.IsRunning;
    public DnsServerEntry? ActiveTunnelServer => _tunnel.ActiveServer;
    public string? ActiveTunnelServerId => _tunnel.ActiveServer?.Id;
    public string ThemeLabel => IsDarkTheme ? "Светлая тема" : "Тёмная тема";
    public long TunnelQueries => _tunnel.QueriesHandled;
    public long TunnelCacheHits => _tunnel.CacheHits;

    public string TunnelSummaryTitle => _tunnel.IsRunning && _tunnel.ActiveServer is { } srv
        ? $"Активен туннель: {srv.Name}"
        : string.Empty;

    public string TunnelSummarySubtitle => _tunnel.IsRunning && _tunnel.ActiveServer is { } srv
        ? $"{srv.EndpointLabel}  ·  127.0.0.1:53  ·  Запросов: {_tunnel.QueriesHandled} (кэш: {_tunnel.CacheHits})"
        : string.Empty;

    public int TotalCatalogCount => _allServers.Count;
    public int FilteredCount => _filteredServers.Count;
    public bool CanShowMore => VisibleServers.Count < _filteredServers.Count;
    public bool IsEmptyResult => VisibleServers.Count == 0;
    public string VisibleSummaryText => $"Показано {VisibleServers.Count} из {_filteredServers.Count} (всего в базе: {_allServers.Count})";

    public MainViewModel(
        DnsDatabaseRepository repo,
        Action<Action>? dispatchToUi = null,
        AppSettingsService? settingsService = null)
    {
        _repo = repo;
        _dispatchToUi = dispatchToUi ?? (action => action());
        _settingsService = settingsService ?? new AppSettingsService();
        _settings = _settingsService.Load();

        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse");
        _adapter = new WindowsNetworkAdapterService(appData);
        DynamicBypassRegistry.LoadOfflineCache(appData);
        _repo.SeedMissingBuiltins(CatalogSeeder.LoadFullCatalog());
        var cachedHosts = _repo.LoadHostsCache();
        if (cachedHosts.Count > 0)
            DynamicBypassRegistry.ClassifyAndAddDomains(cachedHosts);
        CachedHostsCount = Math.Max(cachedHosts.Count, DynamicBypassRegistry.GetAllProtectedDomains().Count);
        _tunnel.UpdateBypassDomains(DynamicBypassRegistry.GetAllProtectedDomains());
        _tunnel.SetActiveTargetDomain(TargetDomain);

        ApplyLoadedSettings(_settings);
        RefreshPresetGroupsAndItems();
        ReloadFromDb();
    }

    private void ApplyLoadedSettings(AppSettings s)
    {
        _isApplyingSettings = true;
        try
        {
            IsDarkTheme = s.IsDarkTheme;
            AccentPreset = s.AccentPreset;
            CompactMode = s.CompactMode;
            StartWithWindows = s.StartWithWindows;
            StartMinimizedToTray = s.StartMinimizedToTray;
            MinimizeToTrayOnClose = s.MinimizeToTrayOnClose;
            AutoModeEnabled = s.AutoModeEnabled;
            AutoFailoverOnDrop = s.AutoFailoverOnDrop;
            AutoCheckUpdates = s.AutoCheckUpdates;
            GitHubToken = s.GitHubToken;
            AutoSyncFeedsOnStartup = s.AutoSyncFeedsOnStartup;
            SplitTunnelEnabled = s.SplitTunnelEnabled;
            BlockIpv6OnBypass = s.BlockIpv6OnBypass;
            BootstrapDnsProvider = s.BootstrapDnsProvider;
            ProbeTimeoutMs = s.ProbeTimeoutMs;
            BenchmarkConcurrency = s.BenchmarkConcurrency;

            _tunnel.SplitTunnelBypassOnly = SplitTunnelEnabled;
            _tunnel.BlockIpv6OnBypass = BlockIpv6OnBypass;
            _prober.ProbeTimeoutMs = ProbeTimeoutMs;
            BootstrapDnsResolver.PreferredBootstrapProvider = BootstrapDnsProvider;

            if (OperatingSystem.IsWindows())
            {
                WindowsAutostartService.RepairIfEnabled(StartWithWindows, StartMinimizedToTray);
                var (_, detail) = WindowsAutostartService.GetStatus();
                AutostartStatusText = detail;
            }
        }
        finally
        {
            _isApplyingSettings = false;
        }
    }

    private void PersistSettings()
    {
        if (_isApplyingSettings) return;
        _settings.IsDarkTheme = IsDarkTheme;
        _settings.AccentPreset = AccentPreset;
        _settings.CompactMode = CompactMode;
        _settings.StartWithWindows = StartWithWindows;
        _settings.StartMinimizedToTray = StartMinimizedToTray;
        _settings.MinimizeToTrayOnClose = MinimizeToTrayOnClose;
        _settings.AutoModeEnabled = AutoModeEnabled;
        _settings.AutoFailoverOnDrop = AutoFailoverOnDrop;
        _settings.AutoCheckUpdates = AutoCheckUpdates;
        _settings.GitHubToken = GitHubToken;
        _settings.AutoSyncFeedsOnStartup = AutoSyncFeedsOnStartup;
        _settings.SplitTunnelEnabled = SplitTunnelEnabled;
        _settings.BlockIpv6OnBypass = BlockIpv6OnBypass;
        _settings.BootstrapDnsProvider = BootstrapDnsProvider;
        _settings.ProbeTimeoutMs = ProbeTimeoutMs;
        _settings.BenchmarkConcurrency = BenchmarkConcurrency;
        _settingsService.Save(_settings);
    }

    partial void OnActiveTabIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsTesterTab));
        OnPropertyChanged(nameof(IsCatalogTab));
        OnPropertyChanged(nameof(IsConfigsTab));
        OnPropertyChanged(nameof(IsSettingsTab));
        if (value == 1 && VisibleLimit < 200)
        {
            VisibleLimit = 200;
        }
        ApplyFilterAndSort();
    }

    partial void OnTargetDomainChanged(string value)
    {
        _tunnel.SetActiveTargetDomain(value);
        OnPropertyChanged(nameof(ModeExplanationText));
    }

    partial void OnRequiresBypassChanged(bool value)
    {
        ApplyFilterAndSort();
        OnPropertyChanged(nameof(ModeExplanationText));
    }

    partial void OnSplitTunnelEnabledChanged(bool value)
    {
        _tunnel.SplitTunnelBypassOnly = value;
        PersistSettings();
    }

    partial void OnBlockIpv6OnBypassChanged(bool value)
    {
        _tunnel.BlockIpv6OnBypass = value;
        PersistSettings();
    }

    partial void OnBootstrapDnsProviderChanged(string value)
    {
        BootstrapDnsResolver.PreferredBootstrapProvider = value;
        BootstrapDnsResolver.ClearCache();
        PersistSettings();
    }

    partial void OnProbeTimeoutMsChanged(int value)
    {
        _prober.ProbeTimeoutMs = Math.Clamp(value, 1000, 6000);
        PersistSettings();
    }

    partial void OnBenchmarkConcurrencyChanged(int value) => PersistSettings();
    partial void OnMinimizeToTrayOnCloseChanged(bool value) => PersistSettings();
    partial void OnAutoFailoverOnDropChanged(bool value) => PersistSettings();
    partial void OnAutoCheckUpdatesChanged(bool value) => PersistSettings();
    partial void OnGitHubTokenChanged(string value) => PersistSettings();
    partial void OnAutoSyncFeedsOnStartupChanged(bool value) => PersistSettings();

    partial void OnCompactModeChanged(bool value)
    {
        OnPropertyChanged(nameof(ServerRowPadding));
        PersistSettings();
    }

    partial void OnAccentPresetChanged(string value)
    {
        PersistSettings();
        OnVisualSettingsChanged?.Invoke(IsDarkTheme, value);
    }

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (_isApplyingSettings) return;
        if (OperatingSystem.IsWindows())
        {
            var (ok, detail) = WindowsAutostartService.SetEnabled(value, StartMinimizedToTray);
            AutostartStatusText = detail;
            StatusMessage = detail;
            if (!ok && value)
            {
                _isApplyingSettings = true;
                StartWithWindows = false;
                _isApplyingSettings = false;
            }
        }
        PersistSettings();
    }

    partial void OnStartMinimizedToTrayChanged(bool value)
    {
        if (_isApplyingSettings) return;
        if (OperatingSystem.IsWindows() && StartWithWindows)
        {
            var (_, detail) = WindowsAutostartService.SetEnabled(true, value);
            AutostartStatusText = detail;
        }
        PersistSettings();
    }

    partial void OnIsAutoModeRunningChanged(bool value) => OnPropertyChanged(nameof(AutoModeLabel));

    partial void OnAutoModeEnabledChanged(bool value)
    {
        OnPropertyChanged(nameof(AutoModeLabel));
        if (_isApplyingSettings) return;
        PersistSettings();

        if (value)
        {
            _ = RunAutoModeAsync(forceRescanIfEmpty: true, CancellationToken.None);
        }
        else
        {
            _autoModeCts?.Cancel();
            StatusMessage = "Авторежим выключен";
        }
    }

    partial void OnIsBenchmarkRunningChanged(bool value) => OnPropertyChanged(nameof(BenchmarkProgressText));
    partial void OnBenchmarkDoneChanged(int value)
    {
        OnPropertyChanged(nameof(BenchmarkProgressText));
        OnPropertyChanged(nameof(BenchmarkProgressPercent));
    }
    partial void OnBenchmarkTotalChanged(int value)
    {
        OnPropertyChanged(nameof(BenchmarkProgressText));
        OnPropertyChanged(nameof(BenchmarkProgressPercent));
    }
    partial void OnBenchmarkWorkingCountChanged(int value) => OnPropertyChanged(nameof(BenchmarkProgressText));
    partial void OnBenchmarkScopeLabelChanged(string value) => OnPropertyChanged(nameof(BenchmarkProgressText));
    partial void OnHasAvailableUpdateChanged(bool value) => OnPropertyChanged(nameof(UpdateBannerText));
    partial void OnAvailableVersionTextChanged(string value) => OnPropertyChanged(nameof(UpdateBannerText));
    partial void OnSelectedCategoryChanged(string value) { RefreshCategoryChips(); ApplyFilterAndSort(); }
    partial void OnSelectedSortModeChanged(SortMode value) => ApplyFilterAndSort();
    partial void OnBypassOnlyChanged(bool value) => ApplyFilterAndSort();
    partial void OnFavoritesOnlyChanged(bool value) => ApplyFilterAndSort();
    partial void OnEncryptedOnlyChanged(bool value) => ApplyFilterAndSort();
    partial void OnFreeOnlyChanged(bool value) => ApplyFilterAndSort();

    partial void OnSelectedServerChanged(DnsServerEntry? value)
    {
        IsInspectorOpen = value is not null;
    }

    partial void OnIsDarkThemeChanged(bool value)
    {
        OnPropertyChanged(nameof(ThemeLabel));
        PersistSettings();
        OnVisualSettingsChanged?.Invoke(value, AccentPreset);
    }

    partial void OnSearchQueryChanged(string value)
    {
        _searchDebounceCts?.Cancel();
        _searchDebounceCts?.Dispose();
        _searchDebounceCts = new CancellationTokenSource();
        var token = _searchDebounceCts.Token;
        _ = Task.Delay(220, token).ContinueWith(t =>
        {
            if (!t.IsCanceled)
            {
                _dispatchToUi(ApplyFilterAndSort);
            }
        }, TaskScheduler.Default);
    }

    public void ReloadFromDb()
    {
        var previousSelectedId = SelectedServer?.Id;
        _allServers = _repo.GetAllServers();
        OnPropertyChanged(nameof(TotalCatalogCount));
        RefreshCategoryChips();
        ApplyFilterAndSort();

        if (!string.IsNullOrEmpty(previousSelectedId))
        {
            SelectedServer = _allServers.FirstOrDefault(s => s.Id == previousSelectedId);
        }
    }

    public void ApplyFilterAndSort()
    {
        _filteredServers = ServerFilterSorter.FilterAndSort(
            _allServers, SelectedCategory, BypassOnly, FavoritesOnly, EncryptedOnly, FreeOnly,
            SearchQuery ?? string.Empty, SelectedSortMode, RequiresBypass);

        VisibleServers.Clear();
        foreach (var item in _filteredServers.Take(VisibleLimit))
        {
            VisibleServers.Add(item);
        }

        OnPropertyChanged(nameof(VisibleServers));
        OnPropertyChanged(nameof(FilteredCount));
        OnPropertyChanged(nameof(BenchmarkButtonText));
        OnPropertyChanged(nameof(CanShowMore));
        OnPropertyChanged(nameof(IsEmptyResult));
        OnPropertyChanged(nameof(VisibleSummaryText));
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    private void RefreshCategoryChips()
    {
        Categories.Clear();
        foreach (var cat in CategoryNames)
        {
            int count = cat == "Все"
                ? _allServers.Count
                : _allServers.Count(s => s.Category == cat);
            Categories.Add(new CategoryFilterItem(cat, count, SelectedCategory == cat));
        }
    }

    private void RefreshPresetGroupsAndItems()
    {
        PresetGroups.Clear();
        var groups = new (string Id, string Label)[]
        {
            ("ai", "ИИ"),
            ("streaming", "Стриминг"),
            ("gaming", "Игры"),
            ("all", "Всё"),
            ("custom", "Свой")
        };

        foreach (var (id, label) in groups)
        {
            PresetGroups.Add(new PresetGroupItem(id, label, SelectedPresetGroup == id));
            if (SelectedPresetGroup == id) ActiveGroupLabel = label;
        }

        ActivePresets.Clear();
        var matches = SelectedPresetGroup switch
        {
            "all" => AllPresets,
            "custom" => Array.Empty<DomainPresetItem>(),
            _ => AllPresets.Where(p => p.GroupId == SelectedPresetGroup)
        };

        foreach (var p in matches)
        {
            ActivePresets.Add(p with { IsSelected = string.Equals(p.Domain, TargetDomain, StringComparison.OrdinalIgnoreCase) });
        }
        OnPropertyChanged(nameof(IsCustomPresetGroup));
    }

    [RelayCommand]
    private void SelectTab(string tabIndexStr)
    {
        if (int.TryParse(tabIndexStr, out int idx))
            ActiveTabIndex = idx;
    }

    [RelayCommand]
    private void SelectPresetGroup(string? groupId)
    {
        if (string.IsNullOrEmpty(groupId)) return;
        SelectedPresetGroup = groupId;
        if (groupId != "custom")
        {
            var first = groupId == "all"
                ? AllPresets.FirstOrDefault()
                : AllPresets.FirstOrDefault(p => p.GroupId == groupId);
            if (first is not null)
            {
                TargetDomain = first.Domain;
                RequiresBypass = first.RequiresBypass;
            }
        }
        else
        {
            RequiresBypass = true;
        }
        RefreshPresetGroupsAndItems();
    }

    [RelayCommand]
    private void SelectPreset(DomainPresetItem? preset)
    {
        if (preset is null) return;
        TargetDomain = preset.Domain;
        RequiresBypass = preset.RequiresBypass;
        RefreshPresetGroupsAndItems();
    }

    [RelayCommand]
    private void SelectCategory(string? category)
    {
        if (string.IsNullOrEmpty(category)) return;
        SelectedCategory = category;
    }

    [RelayCommand]
    private void ResetFilters()
    {
        SelectedCategory = "Все";
        BypassOnly = false;
        FavoritesOnly = false;
        EncryptedOnly = false;
        FreeOnly = false;
        SearchQuery = string.Empty;
        ApplyFilterAndSort();
    }

    [RelayCommand]
    private void ShowMore()
    {
        VisibleLimit += 120;
        ApplyFilterAndSort();
    }

    [RelayCommand]
    private void CloseInspector()
    {
        SelectedServer = null;
        IsInspectorOpen = false;
    }

    [RelayCommand]
    private void ClearSearch() => SearchQuery = string.Empty;

    [RelayCommand]
    private void RestartAsAdmin()
    {
        var args = ActiveTunnelServer is { } s ? $"--connect-id {s.Id}" : "--apply-tunnel";
        if (!WindowsNetworkAdapterService.RequestElevationAndRestart(args))
        {
            StatusMessage = "Перезапуск от имени администратора отменён пользователем";
        }
    }

    [RelayCommand]
    private void StopBenchmark()
    {
        _benchmarkCts?.Cancel();
        StatusMessage = "Останавливаем текущую проверку...";
    }

    [RelayCommand]
    public async Task TestSingleAsync(DnsServerEntry? server, CancellationToken ct)
    {
        if (server is null) return;
        IsBusy = true;
        StatusMessage = $"4-этапная диагностика {server.Name} ({TargetDomain})...";
        try
        {
            var res = await _prober.ProbeFourStagesAsync(server, TargetDomain, RequiresBypass, ct);
            _repo.SaveProbeResult(res);
            ReloadFromDb();
            var ipNote = res.ResolvedIps.Count > 0 ? $" [{res.ResolvedIps[0]}]" : string.Empty;
            var latNote = res.LatencyMs.HasValue ? $" · {res.LatencyMs.Value:0} мс" : string.Empty;
            StatusMessage = $"{server.Name}: {res.VerdictReason}{ipNote}{latNote}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка проверки {server.Name}: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task BenchmarkVisibleAsync(CancellationToken ct) =>
        await BenchmarkServersListAsync(_filteredServers.ToList(), ct, $"Раздел «{SelectedCategory}»");

    public async Task BenchmarkTopAsync(int count, CancellationToken ct) =>
        await BenchmarkServersListAsync(VisibleServers.Take(count).ToList(), ct, "LIVE (топ)");

    private async Task BenchmarkServersListAsync(List<DnsServerEntry> targets, CancellationToken ct, string? scopeLabel = null)
    {
        _benchmarkCts?.Cancel();
        _benchmarkCts?.Dispose();
        _benchmarkCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _benchmarkCts.Token;

        if (targets.Count == 0)
        {
            StatusMessage = "Нет серверов для проверки под текущие фильтры";
            return;
        }

        // Prioritize Smart-DNS / SNI443 / Discovered nodes so working bypass candidates show up first
        targets = targets
            .OrderByDescending(s => s.Protocol == DnsProtocol.SNI443)
            .ThenByDescending(s => s.SupportsBypass)
            .ThenBy(s => s.LastLatencyMs ?? double.MaxValue)
            .ToList();

        IsBusy = true;
        IsBenchmarkRunning = true;
        BenchmarkScopeLabel = scopeLabel ?? "Проверка";
        BenchmarkTotal = targets.Count;
        BenchmarkDone = 0;
        BenchmarkWorkingCount = 0;
        StatusMessage = $"{BenchmarkScopeLabel}: проверка {targets.Count} узлов для {TargetDomain}...";

        try
        {
            int concurrency = targets.Count > 50
                ? Math.Clamp(Math.Max(BenchmarkConcurrency, 10), 2, 16)
                : Math.Clamp(BenchmarkConcurrency, 2, 16);

            using var gate = new SemaphoreSlim(concurrency);
            int done = 0;
            int working = 0;

            var tasks = targets.Select(async srv =>
            {
                await gate.WaitAsync(token);
                try
                {
                    if (token.IsCancellationRequested) return;
                    var res = await _prober.ProbeFourStagesAsync(srv, TargetDomain, RequiresBypass, token);
                    _repo.SaveProbeResult(res);

                    int d = Interlocked.Increment(ref done);
                    int w = res.Verdict == BypassVerdict.VERIFIED_PROXY_OK
                        ? Interlocked.Increment(ref working)
                        : Volatile.Read(ref working);

                    _dispatchToUi(() =>
                    {
                        BenchmarkDone = d;
                        BenchmarkWorkingCount = w;
                        StatusMessage = $"Проверено {d}/{targets.Count}: {srv.Name} -> {res.VerdictReason}";
                        int flushStep = targets.Count > 100 ? 10 : 3;
                        if (d % flushStep == 0 || d == targets.Count)
                        {
                            ReloadFromDb();
                        }
                    });
                }
                catch (OperationCanceledException)
                {
                    // Cancelled cleanly
                }
                finally
                {
                    gate.Release();
                }
            });

            await Task.WhenAll(tasks);
            _dispatchToUi(() =>
            {
                ReloadFromDb();
                StatusMessage = $"Проверка раздела завершена: {targets.Count} узлов, рабочих: {Volatile.Read(ref working)}";
            });
        }
        catch (OperationCanceledException)
        {
            _dispatchToUi(() =>
            {
                ReloadFromDb();
                StatusMessage = $"Проверка остановлена ({BenchmarkDone}/{BenchmarkTotal}, рабочих: {BenchmarkWorkingCount})";
            });
        }
        finally
        {
            _dispatchToUi(() =>
            {
                IsBenchmarkRunning = false;
                IsBusy = false;
            });
        }
    }

    [RelayCommand]
    private void ToggleAutoMode()
    {
        AutoModeEnabled = !AutoModeEnabled;
    }

    [RelayCommand]
    private void SelectAccentPreset(string? preset)
    {
        if (!string.IsNullOrWhiteSpace(preset))
            AccentPreset = preset;
    }

    [RelayCommand]
    private void VerifyAutostart()
    {
        if (!OperatingSystem.IsWindows()) return;
        if (StartWithWindows)
        {
            var (ok, detail) = WindowsAutostartService.SetEnabled(true, StartMinimizedToTray);
            AutostartStatusText = detail;
            StatusMessage = ok ? detail : $"Ошибка автозапуска: {detail}";
        }
        else
        {
            var (_, detail) = WindowsAutostartService.GetStatus();
            AutostartStatusText = detail;
            StatusMessage = detail;
        }
    }

    [RelayCommand]
    private void ResetAllSettings()
    {
        var defaults = new AppSettings();
        ApplyLoadedSettings(defaults);
        PersistSettings();
        OnVisualSettingsChanged?.Invoke(IsDarkTheme, AccentPreset);
        StatusMessage = "Настройки сброшены на значения по умолчанию";
    }

    public async Task RunAutoModeAsync(bool forceRescanIfEmpty, CancellationToken externalCt)
    {
        _autoModeCts?.Cancel();
        _autoModeCts?.Dispose();
        _autoModeCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _autoModeCts.Token;

        IsAutoModeRunning = true;
        IsBusy = true;
        StatusMessage = $"Авторежим: диагностика лучших узлов под {TargetDomain}...";

        try
        {
            static bool IsBypassCandidate(DnsServerEntry s) =>
                !s.IsSubscription &&
                (s.SupportsBypass ||
                 s.Protocol == DnsProtocol.SNI443 ||
                 s.Category is "Smart-DNS" or "Свои / Найденные" or "Игры и Регионы");

            DnsServerEntry? winner = null;
            var testedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (RequiresBypass)
            {
                // If user opened a specific bypass section (e.g. Smart-DNS 70), check that section first so counts match & connection is fast
                if (!string.Equals(SelectedCategory, "Все", StringComparison.Ordinal))
                {
                    var scopedCandidates = _filteredServers
                        .Where(IsBypassCandidate)
                        .OrderByDescending(s => s.Protocol == DnsProtocol.SNI443)
                        .ThenBy(s => s.LastLatencyMs ?? double.MaxValue)
                        .ToList();

                    if (scopedCandidates.Count > 0)
                    {
                        foreach (var c in scopedCandidates) testedIds.Add(c.Id);
                        await BenchmarkServersListAsync(scopedCandidates, ct, $"Автоподбор ({SelectedCategory})");
                    }

                    winner = _allServers
                        .Where(s => s.Verdict == BypassVerdict.VERIFIED_PROXY_OK && !s.IsSubscription && testedIds.Contains(s.Id))
                        .OrderBy(s => s.LastLatencyMs ?? double.MaxValue)
                        .FirstOrDefault();
                }

                // If selected section had 0 working bypass nodes (or "Все" is active), check remaining bypass nodes across catalog
                if (winner is null && !ct.IsCancellationRequested)
                {
                    var globalCandidates = _allServers
                        .Where(s => IsBypassCandidate(s) && !testedIds.Contains(s.Id))
                        .OrderByDescending(s => s.Protocol == DnsProtocol.SNI443)
                        .ThenBy(s => s.LastLatencyMs ?? double.MaxValue)
                        .ToList();

                    if (globalCandidates.Count > 0)
                    {
                        await BenchmarkServersListAsync(globalCandidates, ct, "Автоподбор (вся база обхода)");
                    }

                    winner = _allServers
                        .Where(s => s.Verdict == BypassVerdict.VERIFIED_PROXY_OK && !s.IsSubscription)
                        .OrderBy(s => s.LastLatencyMs ?? double.MaxValue)
                        .FirstOrDefault();
                }
            }
            else
            {
                var pingCandidates = _filteredServers.Where(s => !s.IsSubscription).Take(25).ToList();
                if (pingCandidates.Count > 0)
                {
                    await BenchmarkServersListAsync(pingCandidates, ct, $"Автоподбор ({SelectedCategory})");
                }

                winner = _allServers
                    .Where(s => s.Verdict == BypassVerdict.VERIFIED_PROXY_OK && !s.IsSubscription)
                    .OrderBy(s => s.LastLatencyMs ?? double.MaxValue)
                    .FirstOrDefault();
            }

            if (winner is null && RequiresBypass && forceRescanIfEmpty && !ct.IsCancellationRequested)
            {
                StatusMessage = $"Авторежим: в каталоге 0 рабочих под {TargetDomain} — запускаем авто-сканер /24...";
                var scanProgress = new Progress<(int Done, int Total, int Found, string CurrentIp)>(info =>
                {
                    _dispatchToUi(() =>
                        StatusMessage = $"Авторежим (сканер {info.Done}/{info.Total}): найдено {info.Found}...");
                });

                var found = await _scanner.ScanAsync(
                    "AUTO",
                    TargetDomain,
                    requiresBypass: true,
                    scanUdp53: true,
                    checkPort443: true,
                    progress: null,
                    ct: ct,
                    detailedProgress: scanProgress);

                if (found.Count > 0)
                {
                    AddDiscoveredServers(found);
                    winner = found.OrderBy(s => s.LastLatencyMs ?? double.MaxValue).FirstOrDefault();
                }
            }

            if (winner is null && !RequiresBypass)
            {
                winner = _filteredServers.FirstOrDefault(s => !s.IsSubscription)
                         ?? _allServers.FirstOrDefault(s => !s.IsSubscription);
            }

            if (winner is null)
            {
                StatusMessage = $"Авторежим: рабочий узел под {TargetDomain} не найден — попробуйте сменить домен или подключить свой Smart-DNS";
                return;
            }

            SelectedServer = winner;
            if (IsTunnelActive && ActiveTunnelServer?.Id != winner.Id)
            {
                _tunnel.SwitchServer(winner);
                if (WindowsNetworkAdapterService.IsElevated())
                    await _adapter.FlushSystemDnsCacheAsync();
                NotifyTunnelProperties();
                StatusMessage = $"Авторежим переключил туннель на лучший узел: {winner.Name} ({winner.LatencyDisplay})";
            }
            else if (!IsTunnelActive)
            {
                await StartTunnelAsync(winner);
                if (IsTunnelActive)
                    StatusMessage = $"Авторежим подключил лучший узел: {winner.Name} ({winner.LatencyDisplay})";
            }
            else
            {
                StatusMessage = $"Авторежим подтвердил текущий лучший узел: {winner.Name} ({winner.LatencyDisplay})";
            }
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Автоподбор остановлен";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка авторежима: {ex.Message}";
        }
        finally
        {
            IsAutoModeRunning = false;
            IsBusy = false;
        }
    }

    public async Task CheckActiveTunnelHealthForFailoverAsync()
    {
        if (!AutoModeEnabled || !AutoFailoverOnDrop || !IsTunnelActive || IsAutoModeRunning || IsBenchmarkRunning)
            return;

        if ((DateTime.UtcNow - _lastAutoFailoverCheckUtc).TotalSeconds < 25)
            return;

        _lastAutoFailoverCheckUtc = DateTime.UtcNow;
        var active = ActiveTunnelServer;
        if (active is null) return;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var probe = await _prober.ProbeFourStagesAsync(active, TargetDomain, RequiresBypass, cts.Token);
            _repo.SaveProbeResult(probe);
            if (probe.Verdict != BypassVerdict.VERIFIED_PROXY_OK)
            {
                _dispatchToUi(() => StatusMessage = $"Авторежим: узел {active.Name} недоступен ({probe.VerdictReason}), ищем замену...");
                await RunAutoModeAsync(forceRescanIfEmpty: false, CancellationToken.None);
            }
        }
        catch
        {
            // Keep running on transient probe cancel
        }
    }

    [RelayCommand]
    public void ToggleLive()
    {
        if (IsLiveRunning)
        {
            _liveCts?.Cancel();
            IsLiveRunning = false;
            StatusMessage = "LIVE-мониторинг остановлен";
            return;
        }

        _liveCts = new CancellationTokenSource();
        IsLiveRunning = true;
        StatusMessage = "LIVE: автопроверка топ-6 каждые 3 сек";
        var token = _liveCts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await BenchmarkTopAsync(6, token);
                    await Task.Delay(3000, token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
            _dispatchToUi(() => IsLiveRunning = false);
        }, token);
    }

    [RelayCommand]
    private async Task ToggleStartTunnelAsync(DnsServerEntry? server)
    {
        if (server is null) return;
        if (IsTunnelActive && ActiveTunnelServer?.Id == server.Id)
        {
            await StopTunnelAsync();
            return;
        }
        await StartTunnelAsync(server);
    }

    public async Task StartTunnelAsync(DnsServerEntry server, bool applySystemAdapter = true)
    {
        try
        {
            _tunnel.SetActiveTargetDomain(TargetDomain);
            _tunnel.SplitTunnelBypassOnly = SplitTunnelEnabled;
            await _tunnel.StartAsync(server);

            if (applySystemAdapter && WindowsNetworkAdapterService.IsElevated())
            {
                await _adapter.ApplyLocalTunnelAsync("127.0.0.1", _repo.LoadHostsCache());
                StatusMessage = $"Системный туннель активен: {server.Name} (127.0.0.1:53 · DNS Windows переключён)";
            }
            else if (applySystemAdapter)
            {
                StatusMessage = $"Прокси {server.Name} на 127.0.0.1:53 запущен, но НУЖНЫ ПРАВА АДМИНА для переключения DNS Windows";
            }
            else
            {
                StatusMessage = $"Локальный туннель запущен: {server.Name} (127.0.0.1:53)";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Не удалось запустить туннель: {ex.Message}";
        }
        NotifyTunnelProperties();
    }

    [RelayCommand]
    private async Task ConnectBestAsync(CancellationToken ct)
    {
        if (IsTunnelActive)
        {
            await StopTunnelAsync();
            return;
        }

        var best = _allServers
            .Where(s => s.Verdict == BypassVerdict.VERIFIED_PROXY_OK && !s.IsSubscription)
            .OrderBy(s => s.LastLatencyMs ?? double.MaxValue)
            .FirstOrDefault();

        if (best is not null)
        {
            SelectedServer = best;
            await StartTunnelAsync(best);
            return;
        }

        await RunAutoModeAsync(forceRescanIfEmpty: true, ct);
    }

    [RelayCommand]
    public async Task RotateTunnelAsync()
    {
        var queue = ServerFilterSorter.BuildRotationQueue(_allServers, _tunnel.ActiveServer?.Id);
        var nextId = ServerFilterSorter.NextRotationId(queue, _tunnel.ActiveServer?.Id);
        var next = _allServers.FirstOrDefault(s => s.Id == nextId);
        if (next is not null)
        {
            _tunnel.SwitchServer(next);
            if (WindowsNetworkAdapterService.IsElevated())
                await _adapter.FlushSystemDnsCacheAsync();
            StatusMessage = $"Ротация на: {next.Name}";
            NotifyTunnelProperties();
        }
    }

    [RelayCommand]
    public async Task StopTunnelAsync()
    {
        _tunnel.Stop();
        if (WindowsNetworkAdapterService.IsElevated())
            await _adapter.RestorePreviousDnsIfNeededAsync();
        StatusMessage = "Туннель отключён, системные DNS восстановлены";
        NotifyTunnelProperties();
    }

    [RelayCommand]
    public void ToggleFavorite(DnsServerEntry? server)
    {
        if (server is null) return;
        _repo.ToggleFavorite(server.Id);
        ReloadFromDb();
    }

    [RelayCommand]
    public void DeleteCustomServer(DnsServerEntry? server)
    {
        if (server is null || server.IsBuiltin) return;
        if (_repo.DeleteCustomServer(server.Id))
        {
            if (SelectedServer?.Id == server.Id) SelectedServer = null;
            ReloadFromDb();
            StatusMessage = $"Удалён пользовательский сервер: {server.Name}";
        }
    }

    [RelayCommand]
    private void ImportFromEditor()
    {
        int count = ImportRawConfigs(ImportEditorText);
        ConfigFeedback = count > 0
            ? $"Импортировано в SQLite + JSON-сейф: {count}"
            : "Не найдено корректных адресов DNS";
        StatusMessage = ConfigFeedback;
    }

    public int ImportRawConfigs(string rawText)
    {
        var parsed = ImportExportCodec.ParseImportedServers(rawText);
        if (parsed.Count == 0) return 0;
        int added = _repo.UpsertCustomServers(parsed);
        ReloadFromDb();
        return added;
    }

    public void AddDiscoveredServers(IEnumerable<DnsServerEntry> discovered)
    {
        _repo.UpsertCustomServers(discovered);
        ReloadFromDb();
    }

    public void AddCustomServer(DnsServerEntry entry)
    {
        _repo.UpsertCustomServers([entry]);
        ReloadFromDb();
        SelectedServer = _allServers.FirstOrDefault(s => s.Id == entry.Id);
        StatusMessage = $"Добавлен сервер: {entry.Name}";
    }

    [RelayCommand]
    private async Task SyncFeedsAsync(CancellationToken ct)
    {
        IsBusy = true;
        StatusMessage = "Синхронизация онлайн-списков (malw.link, QuickDNS)...";
        try
        {
            var (hosts, servers) = await SyncOnlineFeedsAsync(ct);
            ConfigFeedback = $"Синхронизировано: {hosts} доменов, {servers} DNS";
            StatusMessage = ConfigFeedback;
        }
        catch (Exception ex)
        {
            ConfigFeedback = $"Ошибка синхронизации: {ex.Message}";
            StatusMessage = ConfigFeedback;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task<(int HostsCount, int ServersCount)> SyncOnlineFeedsAsync(CancellationToken ct)
    {
        var (hosts, servers) = await _feedSync.SyncAsync(ct);
        if (hosts.Count > 0)
        {
            var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse");
            DynamicBypassRegistry.ClassifyAndAddDomains(hosts);
            DynamicBypassRegistry.SaveOfflineCache(appData);
            _repo.SaveHostsCache(hosts);
            _tunnel.UpdateBypassDomains(hosts);
            CachedHostsCount = hosts.Count;
        }
        if (servers.Count > 0)
        {
            _repo.UpsertCustomServers(servers);
            ReloadFromDb();
        }
        return (hosts.Count, servers.Count);
    }

    public async Task EnsureStartupSyncAsync(string[]? startupArgs = null)
    {
        if (_startupSyncStarted) return;
        _startupSyncStarted = true;

        try
        {
            if (startupArgs is { Length: > 0 })
            {
                for (int i = 0; i < startupArgs.Length; i++)
                {
                    if (startupArgs[i] == "--connect-id" && i + 1 < startupArgs.Length)
                    {
                        var targetId = startupArgs[i + 1];
                        var targetSrv = _allServers.FirstOrDefault(s => s.Id == targetId);
                        if (targetSrv is not null)
                        {
                            SelectedServer = targetSrv;
                            await StartTunnelAsync(targetSrv);
                        }
                        break;
                    }
                    if (startupArgs[i] == "--apply-tunnel")
                    {
                        await ConnectBestAsync(CancellationToken.None);
                        break;
                    }
                }
            }

            if (!IsTunnelActive && AutoModeEnabled)
            {
                await RunAutoModeAsync(forceRescanIfEmpty: true, CancellationToken.None);
            }
        }
        catch
        {
            // Non-fatal startup flag handling
        }

        // Background hosts & community feeds refresh + silent GitHub release check
        _ = Task.Run(async () =>
        {
            if (AutoSyncFeedsOnStartup)
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
                    var (hosts, servers) = await _feedSync.SyncAsync(cts.Token);
                    _dispatchToUi(() =>
                    {
                        if (hosts.Count > 0)
                        {
                            var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse");
                            DynamicBypassRegistry.ClassifyAndAddDomains(hosts);
                            DynamicBypassRegistry.SaveOfflineCache(appData);
                            var allProtected = DynamicBypassRegistry.GetAllProtectedDomains().ToList();
                            _repo.SaveHostsCache(allProtected);
                            _tunnel.UpdateBypassDomains(allProtected);
                            CachedHostsCount = allProtected.Count;
                        }
                        if (servers.Count > 0)
                        {
                            _repo.UpsertCustomServers(servers);
                            ReloadFromDb();
                        }
                    });
                }
                catch
                {
                    // Keep offline built-in domains on network restriction
                }
            }

            if (AutoCheckUpdates)
            {
                try
                {
                    using var updCts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
                    var check = await _updater.CheckForUpdateAsync(updCts.Token, GitHubToken);
                    _dispatchToUi(() =>
                    {
                        if (check.UpdateAvailable && check.LatestRelease is { } rel)
                        {
                            _availableRelease = rel;
                            AvailableVersionText = rel.VersionText;
                            HasAvailableUpdate = true;
                            UpdateStatusText = $"Доступно обновление {rel.VersionText} (текущая v{check.CurrentVersion})";
                        }
                        else if (check.LatestRelease is not null)
                        {
                            UpdateStatusText = $"Установлена актуальная версия v{check.CurrentVersion}";
                        }
                    });
                }
                catch
                {
                    // Silent check never disturbs user on offline launch
                }
            }
        });
    }

    [RelayCommand]
    private void DismissUpdateBanner() => HasAvailableUpdate = false;

    [RelayCommand]
    public async Task CheckForUpdatesAsync(CancellationToken ct)
    {
        if (IsCheckingUpdates || IsUpdatingApp) return;
        IsCheckingUpdates = true;
        UpdateStatusText = "Проверка новых релизов на GitHub...";
        try
        {
            var res = await _updater.CheckForUpdateAsync(ct, GitHubToken);
            if (res.UpdateAvailable && res.LatestRelease is { } rel)
            {
                _availableRelease = rel;
                AvailableVersionText = rel.VersionText;
                HasAvailableUpdate = true;
                UpdateStatusText = $"Найдена новая версия {rel.VersionText} (сейчас v{res.CurrentVersion})";
                StatusMessage = UpdateStatusText;
            }
            else if (res.LatestRelease is not null)
            {
                _availableRelease = null;
                HasAvailableUpdate = false;
                UpdateStatusText = $"У вас актуальная версия v{res.CurrentVersion} (последний релиз {res.LatestRelease.VersionText})";
                StatusMessage = UpdateStatusText;
            }
            else
            {
                UpdateStatusText = res.ErrorMessage ?? "Не удалось получить информацию о релизе с GitHub";
                StatusMessage = UpdateStatusText;
            }
        }
        catch (Exception ex)
        {
            UpdateStatusText = $"Ошибка проверки обновлений: {ex.Message}";
            StatusMessage = UpdateStatusText;
        }
        finally
        {
            IsCheckingUpdates = false;
        }
    }

    [RelayCommand]
    public async Task InstallAppUpdateAsync(CancellationToken ct)
    {
        if (IsUpdatingApp) return;

        if (_availableRelease is null)
        {
            await CheckForUpdatesAsync(ct);
            if (_availableRelease is null) return;
        }

        var release = _availableRelease;
        IsUpdatingApp = true;
        IsBusy = true;
        UpdateProgressPercent = 2;

        try
        {
            var progress = new Progress<(double Percent, string Status)>(p =>
            {
                UpdateProgressPercent = p.Percent;
                UpdateStatusText = p.Status;
                StatusMessage = p.Status;
            });

            var (preparedPath, isInstaller) = await _updater.DownloadAndVerifyUpdateAsync(release, progress, ct, GitHubToken);

            // Cleanly stop active tunnel & restore Windows adapter DNS before exiting for self-update
            if (IsTunnelActive)
            {
                await StopTunnelAsync();
            }

            AppUpdateService.LaunchPreparedUpdateAndExit(preparedPath, isInstaller);
        }
        catch (OperationCanceledException)
        {
            UpdateStatusText = "Загрузка обновления отменена";
            StatusMessage = UpdateStatusText;
        }
        catch (Exception ex)
        {
            UpdateStatusText = $"Ошибка обновления: {ex.Message}";
            StatusMessage = UpdateStatusText;
        }
        finally
        {
            IsUpdatingApp = false;
            IsBusy = false;
        }
    }

    [RelayCommand]
    public void RestoreCatalogBuiltins()
    {
        int added = RestoreBuiltins();
        ConfigFeedback = $"Встроенная база проверена (добавлено: {added})";
        StatusMessage = ConfigFeedback;
    }

    public int RestoreBuiltins()
    {
        int added = _repo.SeedMissingBuiltins(CatalogSeeder.LoadFullCatalog());
        ReloadFromDb();
        return added;
    }

    [RelayCommand]
    private void ApplyImportTemplate(string? templateKind)
    {
        ImportEditorText = templateKind switch
        {
            "json" => "[\r\n  {\r\n    \"name\": \"Custom Bezmezhau Node\",\r\n    \"dohUrl\": \"https://dns.bezmezhau.com/dns-query\",\r\n    \"supportsBypass\": true\r\n  }\r\n]",
            "csv" => "name,endpoint,provider,supportsBypass\r\nBezmezhau Public,https://dns.bezmezhau.com/dns-query,Bezmezhau,true\r\nMagicDNS,https://dns.magicdns.ru/dns-query,MagicDNS,true",
            _ => "https://dns.bezmezhau.com/dns-query Bezmezhau Public\r\nhttps://gemini1.bezmezhau.com/dns-query Bezmezhau Gemini-1\r\nhttps://dns.magicdns.ru/dns-query MagicDNS\r\nhttps://us.geohide.ru/dns-query GeoHide US\r\nhttps://dns.malw.link/dns-query Malw.link\r\nhttps://dns.comss.one/dns-query Comss.one\r\n176.99.11.77 Xbox-DNS"
        };
    }

    public void RefreshTunnelCounters() => NotifyTunnelProperties();

    private void NotifyTunnelProperties()
    {
        OnPropertyChanged(nameof(IsTunnelActive));
        OnPropertyChanged(nameof(ActiveTunnelServer));
        OnPropertyChanged(nameof(ActiveTunnelServerId));
        OnPropertyChanged(nameof(TunnelQueries));
        OnPropertyChanged(nameof(TunnelCacheHits));
        OnPropertyChanged(nameof(TunnelSummaryTitle));
        OnPropertyChanged(nameof(TunnelSummarySubtitle));
    }
}
