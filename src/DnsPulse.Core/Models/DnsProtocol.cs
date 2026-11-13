namespace DnsPulse.Core.Models;

/// <summary>
/// Supported DNS transport and proxy protocols.
/// </summary>
public enum DnsProtocol
{
    Udp = 0,
    Tcp = 1,
    DoT = 2,
    DoH = 3,
    DoH3 = 4,
    DoQ = 5,
    DnsCrypt = 6,
    AnonymizedDnsCrypt = 7,
    ODoH = 8,
    SniProxy = 9
}
