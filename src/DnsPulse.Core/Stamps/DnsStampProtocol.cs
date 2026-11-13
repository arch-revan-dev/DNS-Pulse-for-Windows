namespace DnsPulse.Core.Stamps;

/// <summary>
/// DNS stamp protocol identifiers defined by the DNSCrypt v2 stamp specification.
/// </summary>
public enum DnsStampProtocol
{
    /// <summary>Plain DNS (UDP/TCP, 0x00).</summary>
    Plain = 0x00,

    /// <summary>DNSCrypt v2 (0x01).</summary>
    DnsCrypt = 0x01,

    /// <summary>DNS-over-HTTPS (0x02).</summary>
    DoH = 0x02,

    /// <summary>DNS-over-TLS (0x03).</summary>
    DoT = 0x03,

    /// <summary>DNS-over-QUIC (0x04).</summary>
    DoQ = 0x04,

    /// <summary>Oblivious DoH Target (0x05).</summary>
    ObliviousDoHTarget = 0x05,

    /// <summary>Anonymized DNSCrypt Relay (0x81).</summary>
    AnonymizedDnsCryptRelay = 0x81,

    /// <summary>Oblivious DoH Relay (0x85).</summary>
    ObliviousDoHRelay = 0x85
}
