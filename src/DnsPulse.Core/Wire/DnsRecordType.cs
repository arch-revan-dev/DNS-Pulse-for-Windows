using System.Diagnostics.CodeAnalysis;

namespace DnsPulse.Core.Wire;

/// <summary>
/// DNS resource record types supported by the PulseCore wire codec.
/// </summary>
public enum DnsRecordType
{
    None = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    [SuppressMessage("Naming", "CA1720:Identifier contains type name", Justification = "Standard DNS PTR record type mnemonic.")]
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    SVCB = 64,
    HTTPS = 65
}

/// <summary>
/// Standard DNS record classes.
/// </summary>
public enum DnsClass
{
    None = 0,
    In = 1,
    Cs = 2,
    Ch = 3,
    Hs = 4,
    Any = 255
}
