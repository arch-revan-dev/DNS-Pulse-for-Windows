using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text.Json;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public sealed class WindowsNetworkAdapterService
{
    private readonly string _restorePath;

    public WindowsNetworkAdapterService(string appDataDir)
    {
        Directory.CreateDirectory(appDataDir);
        _restorePath = Path.Combine(appDataDir, "restore_network_state.json");
    }

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void RequestElevationAndRestart(string extraArgs = "--apply-tunnel")
    {
        var exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(exe)) return;
        Process.Start(new ProcessStartInfo(exe, extraArgs)
        {
            UseShellExecute = true,
            Verb = "runas"
        });
    }

    public async Task ApplyLocalTunnelAsync(string localDnsIp = "127.0.0.1", IEnumerable<string>? nrptDomains = null)
    {
        var state = CaptureCurrentAdapters();
        state.ActiveTunnel = true;
        await File.WriteAllTextAsync(_restorePath, JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));

        foreach (var adapter in state.Adapters)
        {
            await RunProcessAsync("netsh", $"interface ip set dns name=\"{adapter.InterfaceAlias}\" static {localDnsIp} primary");
        }

        if (nrptDomains is not null)
        {
            foreach (var d in nrptDomains.Take(40))
            {
                await RunProcessAsync("powershell", $"-NoProfile -Command \"Add-DnsClientNrptRule -Namespace '.{d}' -NameServers '{localDnsIp}' -ErrorAction SilentlyContinue\"");
            }
        }

        await FlushSystemDnsCacheAsync();
    }

    public async Task RestorePreviousDnsIfNeededAsync()
    {
        if (!File.Exists(_restorePath)) return;
        var json = await File.ReadAllTextAsync(_restorePath);
        var state = JsonSerializer.Deserialize<RestoreNetworkState>(json);
        if (state is null || !state.ActiveTunnel) return;

        foreach (var adapter in state.Adapters)
        {
            if (adapter.WasDhcp || adapter.PreviousDnsServers.Count == 0)
            {
                await RunProcessAsync("netsh", $"interface ip set dns name=\"{adapter.InterfaceAlias}\" dhcp");
            }
            else
            {
                await RunProcessAsync("netsh", $"interface ip set dns name=\"{adapter.InterfaceAlias}\" static {adapter.PreviousDnsServers[0]} primary");
                for (int i = 1; i < adapter.PreviousDnsServers.Count; i++)
                {
                    await RunProcessAsync("netsh", $"interface ip add dns name=\"{adapter.InterfaceAlias}\" {adapter.PreviousDnsServers[i]} index={i + 1}");
                }
            }
        }

        await RunProcessAsync("powershell", "-NoProfile -Command \"Get-DnsClientNrptRule | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\"");
        await FlushSystemDnsCacheAsync();

        state.ActiveTunnel = false;
        await File.WriteAllTextAsync(_restorePath, JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
    }

    public Task FlushSystemDnsCacheAsync() => RunProcessAsync("ipconfig", "/flushdns");

    public static void OpenWindowsNetworkSettings()
    {
        Process.Start(new ProcessStartInfo("ms-settings:network-status") { UseShellExecute = true });
    }

    private static RestoreNetworkState CaptureCurrentAdapters()
    {
        var state = new RestoreNetworkState { CapturedAt = DateTimeOffset.UtcNow };
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            var ipProps = nic.GetIPProperties();
            var dns = ipProps.DnsAddresses
                .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(a => a.ToString())
                .ToList();
            bool isDhcp = ipProps.GetIPv4Properties()?.IsDhcpEnabled ?? true;
            state.Adapters.Add(new AdapterDnsBackup
            {
                InterfaceAlias = nic.Name,
                WasDhcp = isDhcp && dns.Count == 0,
                PreviousDnsServers = dns
            });
        }
        return state;
    }

    private static async Task RunProcessAsync(string file, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo(file, args)
        {
            CreateNoWindow = true,
            UseShellExecute = false
        });
        if (proc is not null) await proc.WaitForExitAsync();
    }
}
