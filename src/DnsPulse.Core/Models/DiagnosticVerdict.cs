namespace DnsPulse.Core.Models;

/// <summary>
/// Structured diagnostic verdict explaining resolver health, censorship, or spoofing conditions.
/// </summary>
public enum DiagnosticVerdict
{
    Unknown = 0,
    Healthy = 1,
    LocalPort53Conflict = 2,
    DnsPoisoned = 3,
    EncryptedDnsDpiBlocked = 4,
    TlsSniDpiReset = 5,
    IpBlockedByIsp = 6,
    GeoBlockedByService = 7,
    TlsMitmRejected = 8,
    BrowserDohBypass = 9
}
