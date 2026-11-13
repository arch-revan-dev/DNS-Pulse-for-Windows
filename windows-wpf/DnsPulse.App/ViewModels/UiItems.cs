using System.Text.Json.Serialization;
using DnsPulse.App.Models;

namespace DnsPulse.App.ViewModels;

public sealed record CategoryFilterItem(string Name, int Count, bool IsSelected);

public sealed record PresetGroupItem(string Id, string Label, bool IsSelected);

public sealed record DomainPresetItem(string Id, string GroupId, string Label, string Domain, bool RequiresBypass, bool IsSelected);

public static class DnsServerEntryDisplayExtensions
{
    public static string GetEndpointLabel(this DnsServerEntry s) =>
        s.Protocol switch
        {
            DnsProtocol.DoH when !string.IsNullOrWhiteSpace(s.DohUrl) => s.DohUrl!,
            DnsProtocol.DoT when !string.IsNullOrWhiteSpace(s.DotHost) => $"tls://{s.DotHost}:853",
            DnsProtocol.SNI443 => $"smartproxy://{s.SmartProxyIp ?? s.PrimaryIp}:443",
            _ => !string.IsNullOrWhiteSpace(s.PrimaryIp) ? s.PrimaryIp : (s.DotHost ?? s.DohUrl ?? "—")
        };

    public static string GetWin11PowerShellCommand(this DnsServerEntry s) =>
        !string.IsNullOrWhiteSpace(s.DohUrl)
            ? $"Add-DnsClientDohServerAddress -ServerAddress \"{(!string.IsNullOrWhiteSpace(s.PrimaryIp) ? s.PrimaryIp : "1.1.1.1")}\" -DohTemplate \"{s.DohUrl}\" -AllowFallbackToUdp $True -AutoUpgrade $True"
            : $"Set-DnsClientServerAddress -InterfaceAlias \"Wi-Fi\" -ServerAddresses \"{(!string.IsNullOrWhiteSpace(s.PrimaryIp) ? s.PrimaryIp : s.SmartProxyIp ?? "1.1.1.1")}\"";
}
