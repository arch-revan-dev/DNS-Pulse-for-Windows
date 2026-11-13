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
    private readonly Action<Action> _dispatchToUi;

    private List<DnsServerEntry> _allServers = [];
    private List<DnsServerEntry> _filteredServers = [];
    private CancellationTokenSource? _liveCts;
    private CancellationTokenSource? _benchmarkCts;
    private CancellationTokenSource? _searchDebounceCts;
    private bool _startupSyncStarted;

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

    public bool IsElevated => WindowsNetworkAdapterService.IsElevated();
    public bool NeedsElevationForSystemDns => !IsElevated;
    public string BenchmarkProgressText => IsBenchmarkRunning && BenchmarkTotal > 0
        ? $"Проверка: {BenchmarkDone} / {BenchmarkTotal} · Рабочих: {BenchmarkWorkingCount}"
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
    public bool IsCustomPresetGroup => SelectedPresetGroup == "custom";
    public bool HasActiveFilters =>
        SelectedCategory != "Все" || BypassOnly || FavoritesOnly || EncryptedOnly || FreeOnly || !string.IsNullOrWhiteSpace(SearchQuery);

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

    public MainViewModel(DnsDatabaseRepository repo, Action<Action>? dispatchToUi = null)
    {
        _repo = repo;
        _dispatchToUi = dispatchToUi ?? (action => action());
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
        _tunnel.SplitTunnelBypassOnly = SplitTunnelEnabled;
        RefreshPresetGroupsAndItems();
        ReloadFromDb();
    }

    partial void OnActiveTabIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsTesterTab));
        OnPropertyChanged(nameof(IsCatalogTab));
        OnPropertyChanged(nameof(IsConfigsTab));
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

    partial void OnSplitTunnelEnabledChanged(bool value) => _tunnel.SplitTunnelBypassOnly = value;
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

    partial void OnIsDarkThemeChanged(bool value) => OnPropertyChanged(nameof(ThemeLabel));

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
    private async Task BenchmarkVisibleAsync(CancellationToken ct) => await BenchmarkTopAsync(18, ct);

    public async Task BenchmarkTopAsync(int count, CancellationToken ct)
    {
        _benchmarkCts?.Cancel();
        _benchmarkCts?.Dispose();
        _benchmarkCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _benchmarkCts.Token;

        var targets = VisibleServers.Take(count).ToList();
        if (targets.Count == 0)
        {
            StatusMessage = "Нет серверов для проверки под текущие фильтры";
            return;
        }

        IsBusy = true;
        IsBenchmarkRunning = true;
        BenchmarkTotal = targets.Count;
        BenchmarkDone = 0;
        BenchmarkWorkingCount = 0;
        StatusMessage = $"Проверка {targets.Count} узлов для {TargetDomain}...";

        try
        {
            using var gate = new SemaphoreSlim(6);
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
                        if (d % 3 == 0 || d == targets.Count)
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
                StatusMessage = $"Тест завершён: {targets.Count} узлов, рабочих: {Volatile.Read(ref working)}";
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

        DnsServerEntry? PickBestVerified() =>
            _allServers
                .Where(s => s.Verdict == BypassVerdict.VERIFIED_PROXY_OK && !s.IsSubscription)
                .OrderBy(s => s.LastLatencyMs ?? double.MaxValue)
                .FirstOrDefault();

        var best = PickBestVerified();
        if (best is null)
        {
            await BenchmarkTopAsync(18, ct);
            best = PickBestVerified();
        }

        if (best is null && !RequiresBypass)
        {
            best = _filteredServers.FirstOrDefault(s => !s.IsSubscription)
                   ?? _allServers.FirstOrDefault(s => !s.IsSubscription);
        }

        if (best is null)
        {
            StatusMessage = $"Не найдено рабочих Smart-DNS под {TargetDomain} в топ-18 — откройте «Сканер /24 и списки» или отключите «Обход 443»";
            return;
        }

        SelectedServer = best;
        await StartTunnelAsync(best);
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
        }
        catch
        {
            // Non-fatal startup flag handling
        }

        // Background hosts & community feeds refresh (same behavior as Android app startup)
        _ = Task.Run(async () =>
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
        });
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
