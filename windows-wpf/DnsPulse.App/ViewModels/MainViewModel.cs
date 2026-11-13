using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using DnsPulse.App.Data;
using DnsPulse.App.Models;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly DnsDatabaseRepository _repo;
    private readonly FourStageProber _prober = new();
    private readonly LocalDnsTunnelServer _tunnel = new();
    private List<DnsServerEntry> _allServers = [];

    public ObservableCollection<DnsServerEntry> VisibleServers { get; } = [];

    public string TargetDomain { get; set; } = "gemini.google.com";
    public bool RequiresBypass { get; set; } = true;
    public string SelectedCategory { get; set; } = "Все";
    public SortMode SelectedSortMode { get; set; } = SortMode.BEST;
    public bool BypassOnly { get; set; }
    public bool FavoritesOnly { get; set; }
    public bool EncryptedOnly { get; set; }
    public bool FreeOnly { get; set; }
    public string SearchQuery { get; set; } = "";
    public bool IsLiveRunning { get; private set; }
    public bool IsTunnelActive => _tunnel.IsRunning;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainViewModel(DnsDatabaseRepository repo)
    {
        _repo = repo;
        _repo.SeedMissingBuiltins(CatalogSeeder.LoadFullCatalog());
        ReloadFromDb();
    }

    public void ReloadFromDb()
    {
        _allServers = _repo.GetAllServers();
        ApplyFilterAndSort();
    }

    public void ApplyFilterAndSort()
    {
        var items = ServerFilterSorter.FilterAndSort(
            _allServers, SelectedCategory, BypassOnly, FavoritesOnly, EncryptedOnly, FreeOnly,
            SearchQuery, SelectedSortMode, RequiresBypass);
        VisibleServers.Clear();
        foreach (var item in items) VisibleServers.Add(item);
        OnPropertyChanged(nameof(VisibleServers));
    }

    public async Task TestSingleAsync(DnsServerEntry server, CancellationToken ct)
    {
        var res = await _prober.ProbeFourStagesAsync(server, TargetDomain, RequiresBypass, ct);
        _repo.SaveProbeResult(res);
        ReloadFromDb();
    }

    public async Task StartTunnelAsync(DnsServerEntry server)
    {
        await _tunnel.StartAsync(server);
        OnPropertyChanged(nameof(IsTunnelActive));
    }

    public void StopTunnel()
    {
        _tunnel.Stop();
        OnPropertyChanged(nameof(IsTunnelActive));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
