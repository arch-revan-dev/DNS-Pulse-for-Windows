using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;
using DnsPulse.App.Services;

namespace DnsPulse.App.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly DnsDatabaseRepository _repo;
    private readonly FourStageProber _prober = new();
    private readonly LocalDnsTunnelServer _tunnel = new();
    private readonly WindowsNetworkAdapterService _adapter;
    private readonly OnlineFeedSyncService _feedSync = new();
    private List<DnsServerEntry> _allServers = [];
    private CancellationTokenSource? _liveCts;

    public ObservableCollection<DnsServerEntry> VisibleServers { get; } = [];

    private string _targetDomain = "gemini.google.com";
    public string TargetDomain { get => _targetDomain; set { _targetDomain = value; OnPropertyChanged(); } }

    private bool _requiresBypass = true;
    public bool RequiresBypass { get => _requiresBypass; set { _requiresBypass = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private string _selectedCategory = "Все";
    public string SelectedCategory { get => _selectedCategory; set { _selectedCategory = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private SortMode _selectedSortMode = SortMode.BEST;
    public SortMode SelectedSortMode { get => _selectedSortMode; set { _selectedSortMode = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private bool _bypassOnly;
    public bool BypassOnly { get => _bypassOnly; set { _bypassOnly = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private bool _favoritesOnly;
    public bool FavoritesOnly { get => _favoritesOnly; set { _favoritesOnly = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private bool _encryptedOnly;
    public bool EncryptedOnly { get => _encryptedOnly; set { _encryptedOnly = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private bool _freeOnly;
    public bool FreeOnly { get => _freeOnly; set { _freeOnly = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private string _searchQuery = "";
    public string SearchQuery { get => _searchQuery; set { _searchQuery = value; OnPropertyChanged(); ApplyFilterAndSort(); } }

    private bool _isLiveRunning;
    public bool IsLiveRunning { get => _isLiveRunning; private set { _isLiveRunning = value; OnPropertyChanged(); } }

    public bool IsTunnelActive => _tunnel.IsRunning;
    public DnsServerEntry? ActiveTunnelServer => _tunnel.ActiveServer;
    public long TunnelQueries => _tunnel.QueriesHandled;
    public long TunnelCacheHits => _tunnel.CacheHits;
    public int TotalCatalogCount => _allServers.Count;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel(DnsDatabaseRepository repo)
    {
        _repo = repo;
        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DNS-Pulse");
        _adapter = new WindowsNetworkAdapterService(appData);
        _repo.SeedMissingBuiltins(CatalogSeeder.LoadFullCatalog());
        var cachedHosts = _repo.LoadHostsCache();
        if (cachedHosts.Count > 0) _tunnel.UpdateBypassDomains(cachedHosts);
        ReloadFromDb();
    }

    public void ReloadFromDb()
    {
        _allServers = _repo.GetAllServers();
        OnPropertyChanged(nameof(TotalCatalogCount));
        ApplyFilterAndSort();
    }

    public void ApplyFilterAndSort()
    {
        var items = ServerFilterSorter.FilterAndSort(
            _allServers, SelectedCategory, BypassOnly, FavoritesOnly, EncryptedOnly, FreeOnly,
            SearchQuery, SelectedSortMode, RequiresBypass);
        VisibleServers.Clear();
        foreach (var item in items.Take(120)) VisibleServers.Add(item);
        OnPropertyChanged(nameof(VisibleServers));
    }

    public async Task TestSingleAsync(DnsServerEntry server, CancellationToken ct)
    {
        var res = await _prober.ProbeFourStagesAsync(server, TargetDomain, RequiresBypass, ct);
        _repo.SaveProbeResult(res);
        ReloadFromDb();
    }

    public async Task BenchmarkTopAsync(int count, CancellationToken ct)
    {
        using var gate = new SemaphoreSlim(6);
        var targets = VisibleServers.Take(count).ToList();
        var tasks = targets.Select(async srv =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var res = await _prober.ProbeFourStagesAsync(srv, TargetDomain, RequiresBypass, ct);
                _repo.SaveProbeResult(res);
            }
            finally
            {
                gate.Release();
            }
        });
        await Task.WhenAll(tasks);
        ReloadFromDb();
    }

    public void ToggleLive()
    {
        if (IsLiveRunning)
        {
            _liveCts?.Cancel();
            IsLiveRunning = false;
            return;
        }

        _liveCts = new CancellationTokenSource();
        IsLiveRunning = true;
        var token = _liveCts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await BenchmarkTopAsync(6, token);
                    await Task.Delay(2800, token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }, token);
    }

    public async Task StartTunnelAsync(DnsServerEntry server, bool applySystemAdapter = true)
    {
        await _tunnel.StartAsync(server);
        if (applySystemAdapter && WindowsNetworkAdapterService.IsElevated())
        {
            await _adapter.ApplyLocalTunnelAsync("127.0.0.1", _repo.LoadHostsCache());
        }
        NotifyTunnelProperties();
    }

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
            NotifyTunnelProperties();
        }
    }

    public async Task StopTunnelAsync()
    {
        _tunnel.Stop();
        if (WindowsNetworkAdapterService.IsElevated())
            await _adapter.RestorePreviousDnsIfNeededAsync();
        NotifyTunnelProperties();
    }

    public void ToggleFavorite(DnsServerEntry server)
    {
        _repo.ToggleFavorite(server.Id);
        ReloadFromDb();
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

    public async Task<(int HostsCount, int ServersCount)> SyncOnlineFeedsAsync(CancellationToken ct)
    {
        var (hosts, servers) = await _feedSync.SyncAsync(ct);
        if (hosts.Count > 0)
        {
            _repo.SaveHostsCache(hosts);
            _tunnel.UpdateBypassDomains(hosts);
        }
        if (servers.Count > 0)
        {
            _repo.UpsertCustomServers(servers);
            ReloadFromDb();
        }
        return (hosts.Count, servers.Count);
    }

    public int RestoreBuiltins()
    {
        int added = _repo.SeedMissingBuiltins(CatalogSeeder.LoadFullCatalog());
        ReloadFromDb();
        return added;
    }

    private void NotifyTunnelProperties()
    {
        OnPropertyChanged(nameof(IsTunnelActive));
        OnPropertyChanged(nameof(ActiveTunnelServer));
        OnPropertyChanged(nameof(TunnelQueries));
        OnPropertyChanged(nameof(TunnelCacheHits));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
