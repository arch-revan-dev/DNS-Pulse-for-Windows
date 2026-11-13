using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;

namespace DnsPulse.Engine.Cache;

/// <summary>
/// Canonical cache key partitioned by normalized domain name, record type, and routing zone.
/// </summary>
public readonly record struct DnsCacheKey : IEquatable<DnsCacheKey>
{
    public DnsCacheKey(string qName, DnsRecordType qType, RouteZone zone)
    {
        ArgumentNullException.ThrowIfNull(qName);

        QName = NormalizeName(qName);
        QType = qType;
        Zone = zone;
    }

    public string QName { get; }

    public DnsRecordType QType { get; }

    public RouteZone Zone { get; }

    public bool Equals(DnsCacheKey other)
    {
        return QType == other.QType
            && Zone == other.Zone
            && StringComparer.OrdinalIgnoreCase.Equals(QName, other.QName);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            StringComparer.OrdinalIgnoreCase.GetHashCode(QName),
            QType,
            Zone);
    }

    private static string NormalizeName(string name)
    {
        string trimmed = name.Trim();
        if (trimmed.Length == 0 || trimmed == ".")
        {
            return string.Empty;
        }

        return trimmed.TrimEnd('.');
    }
}
