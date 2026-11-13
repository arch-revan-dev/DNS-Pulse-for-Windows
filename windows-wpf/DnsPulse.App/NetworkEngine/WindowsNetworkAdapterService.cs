using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using DnsPulse.App.Models;

namespace DnsPulse.App.NetworkEngine;

public sealed class WindowsNetworkAdapterService
{
    private readonly string _restoreFilePath;
    private readonly string _appDataDir;

    public WindowsNetworkAdapterService(string appDataDir)
    {
        _appDataDir = appDataDir;
        Directory.CreateDirectory(appDataDir);
        _restoreFilePath = Path.Combine(appDataDir, "restore_dns.json");
    }

    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(id);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool RequestElevationAndRestart(string extraArgs = "--apply-tunnel")
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe))
            return false;

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = extraArgs,
                UseShellExecute = true,
                Verb = "runas"
            });
            System.Windows.Application.Current?.Shutdown();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task ApplyLocalTunnelAsync(string localDnsIp = "127.0.0.1", IEnumerable<string>? nrptDomains = null)
    {
        if (!IsElevated())
            throw new UnauthorizedAccessException("Требуются права администратора для переключения DNS сетевых адаптеров Windows.");

        // 1. Capture active adapters & their current DNS settings before modifying
        var backups = new List<AdapterDnsBackup>();
        foreach (var nic in GetActivePhysicalAdapters())
        {
            var props = nic.GetIPProperties();
            var prevV4 = props.DnsAddresses
                .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                            !a.ToString().Equals(localDnsIp, StringComparison.Ordinal))
                .Select(a => a.ToString())
                .ToList();

            backups.Add(new AdapterDnsBackup
            {
                InterfaceAlias = nic.Name,
                WasDhcp = props.GetIPv4Properties()?.IsDhcpEnabled ?? true,
                PreviousDnsServers = prevV4
            });
        }

        if (backups.Count > 0 && !File.Exists(_restoreFilePath))
        {
            var state = new RestoreNetworkState
            {
                ActiveTunnel = true,
                Adapters = backups
            };
            await File.WriteAllTextAsync(_restoreFilePath, JsonSerializer.Serialize(state)).ConfigureAwait(false);
        }

        // 2. Point IPv4 DNS to 127.0.0.1 and clear IPv6 DNS servers so Chrome/Edge don't leak via ISP/router IPv6 DNS
        foreach (var backup in backups)
        {
            var escapedAlias = backup.InterfaceAlias.Replace("\"", "\\\"");
            await RunProcessAsync("netsh", $"interface ipv4 set dnsservers name=\"{escapedAlias}\" static {localDnsIp} validate=no").ConfigureAwait(false);
            await RunProcessAsync("netsh", $"interface ipv6 delete dnsservers name=\"{escapedAlias}\" all").ConfigureAwait(false);
        }

        // Clean up any legacy NRPT rules from older versions instead of spawning 40 slow powershell instances
        await RemoveLegacyNrptRulesAsync().ConfigureAwait(false);
        await FlushSystemDnsCacheAsync().ConfigureAwait(false);
    }

    public async Task RestorePreviousDnsIfNeededAsync()
    {
        if (!File.Exists(_restoreFilePath))
            return;

        if (!IsElevated())
            return;

        try
        {
            var json = await File.ReadAllTextAsync(_restoreFilePath).ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<RestoreNetworkState>(json);
            if (state?.Adapters is { Count: > 0 })
            {
                foreach (var a in state.Adapters)
                {
                    var escapedAlias = a.InterfaceAlias.Replace("\"", "\\\"");
                    await RunProcessAsync("netsh", $"interface ipv6 set dnsservers name=\"{escapedAlias}\" dhcp").ConfigureAwait(false);

                    if (a.WasDhcp || a.PreviousDnsServers.Count == 0)
                    {
                        await RunProcessAsync("netsh", $"interface ipv4 set dnsservers name=\"{escapedAlias}\" dhcp").ConfigureAwait(false);
                    }
                    else
                    {
                        await RunProcessAsync("netsh", $"interface ipv4 set dnsservers name=\"{escapedAlias}\" static {a.PreviousDnsServers[0]} validate=no").ConfigureAwait(false);
                        for (int i = 1; i < a.PreviousDnsServers.Count; i++)
                        {
                            await RunProcessAsync("netsh", $"interface ipv4 add dnsservers name=\"{escapedAlias}\" {a.PreviousDnsServers[i]} index={i + 1} validate=no").ConfigureAwait(false);
                        }
                    }
                }
            }

            await RemoveLegacyNrptRulesAsync().ConfigureAwait(false);
            await FlushSystemDnsCacheAsync().ConfigureAwait(false);
            File.Delete(_restoreFilePath);
        }
        catch
        {
            // Keep restore file for retry on next launch if restore failed
        }
    }

    public Task FlushSystemDnsCacheAsync() => RunProcessAsync("ipconfig", "/flushdns");

    public static void OpenWindowsNetworkSettings()
    {
        try
        {
            Process.Start(new ProcessStartInfo("ms-settings:network-status") { UseShellExecute = true });
        }
        catch
        {
            // Ignore on restricted shells
        }
    }

    private static Task RemoveLegacyNrptRulesAsync() =>
        RunPowerShellEncodedAsync(
            "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -like 'DnsPulse*' -or $_.DisplayName -like 'DnsPulse*' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue");

    private static IEnumerable<NetworkInterface> GetActivePhysicalAdapters()
    {
        return NetworkInterface.GetAllNetworkInterfaces().Where(n =>
            n.OperationalStatus == OperationalStatus.Up &&
            n.NetworkInterfaceType is not NetworkInterfaceType.Loopback and not NetworkInterfaceType.Tunnel &&
            !n.Description.Contains("Loopback", StringComparison.OrdinalIgnoreCase) &&
            !n.Name.Contains("Loopback", StringComparison.OrdinalIgnoreCase));
    }

    private static Task RunPowerShellEncodedAsync(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return RunProcessAsync("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}");
    }

    private static async Task RunProcessAsync(string fileName, string arguments)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            proc.Start();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await proc.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Non-fatal helper invocation
        }
    }
}
