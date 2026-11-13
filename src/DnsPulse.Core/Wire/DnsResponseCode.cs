using System.Diagnostics.CodeAnalysis;

namespace DnsPulse.Core.Wire;

/// <summary>
/// DNS response codes (RFC 1035 and EDNS0 extended RCODEs).
/// </summary>
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute", Justification = "DNS RCODEs are discrete integer codes, not bit flags.")]
public enum DnsResponseCode
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    YxDomain = 6,
    YxRrSet = 7,
    NxRrSet = 8,
    NotAuth = 9,
    NotZone = 10,
    BadVers = 16
}
