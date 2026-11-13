using System.Net;
using System.Net.Sockets;

namespace DnsPulse.Core.Wire;

/// <summary>
/// Represents a parsed or constructed DNS resource record across Answer, Authority, and Additional sections.
/// </summary>
public sealed record DnsResourceRecord
{
    public string Name { get; init; } = string.Empty;

    public DnsRecordType RecordType { get; init; }

    public ushort RawRecordType { get; init; }

    public ushort RecordClass { get; init; } = (ushort)DnsClass.In;

    public uint TimeToLive { get; init; }

    public IPAddress? Address { get; init; }

    public string? TargetName { get; init; }

    public ushort Preference { get; init; }

    public ushort Priority { get; init; }

    public ushort Weight { get; init; }

    public ushort Port { get; init; }

    public IReadOnlyList<string> TxtStrings { get; init; } = [];

    public string? SoaMName { get; init; }

    public string? SoaRName { get; init; }

    public uint SoaSerial { get; init; }

    public uint SoaRefresh { get; init; }

    public uint SoaRetry { get; init; }

    public uint SoaExpire { get; init; }

    public uint SoaMinimum { get; init; }

    public ushort SvcPriority { get; init; }

    public IReadOnlyList<SvcParam> SvcParams { get; init; } = [];

    public ReadOnlyMemory<byte> RawData { get; init; }

    /// <summary>
    /// For <see cref="DnsRecordType.OPT"/> records, returns the advertised EDNS0 UDP payload size.
    /// </summary>
    public ushort EdnsUdpPayloadSize => RecordClass;

    /// <summary>
    /// For <see cref="DnsRecordType.OPT"/> records, returns the upper 8 bits of the extended RCODE.
    /// </summary>
    public byte ExtendedRcode => (byte)(TimeToLive >> 24);

    /// <summary>
    /// For <see cref="DnsRecordType.OPT"/> records, returns the EDNS version byte.
    /// </summary>
    public byte EdnsVersion => (byte)((TimeToLive >> 16) & 0xFF);

    /// <summary>
    /// For <see cref="DnsRecordType.OPT"/> records, indicates whether the DNSSEC OK (DO) bit is set.
    /// </summary>
    public bool IsDnssecOk => (TimeToLive & 0x8000u) != 0;

    public static DnsResourceRecord CreateA(string name, IPAddress address, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Address must be IPv4 for an A record.", nameof(address));
        }

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.A,
            RawRecordType = (ushort)DnsRecordType.A,
            TimeToLive = ttl,
            Address = address
        };
    }

    public static DnsResourceRecord CreateAaaa(string name, IPAddress address, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            throw new ArgumentException("Address must be IPv6 for an AAAA record.", nameof(address));
        }

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.AAAA,
            RawRecordType = (ushort)DnsRecordType.AAAA,
            TimeToLive = ttl,
            Address = address
        };
    }

    public static DnsResourceRecord CreateNs(string name, string nameServer, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(nameServer);

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.NS,
            RawRecordType = (ushort)DnsRecordType.NS,
            TimeToLive = ttl,
            TargetName = DnsQuestion.NormalizeName(nameServer)
        };
    }

    public static DnsResourceRecord CreateCname(string name, string canonicalName, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(canonicalName);

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.CNAME,
            RawRecordType = (ushort)DnsRecordType.CNAME,
            TimeToLive = ttl,
            TargetName = DnsQuestion.NormalizeName(canonicalName)
        };
    }

    public static DnsResourceRecord CreatePtr(string name, string targetName, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(targetName);

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.PTR,
            RawRecordType = (ushort)DnsRecordType.PTR,
            TimeToLive = ttl,
            TargetName = DnsQuestion.NormalizeName(targetName)
        };
    }

    public static DnsResourceRecord CreateMx(string name, ushort preference, string exchange, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(exchange);

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.MX,
            RawRecordType = (ushort)DnsRecordType.MX,
            TimeToLive = ttl,
            Preference = preference,
            TargetName = DnsQuestion.NormalizeName(exchange)
        };
    }

    public static DnsResourceRecord CreateTxt(string name, IEnumerable<string> strings, uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(strings);

        List<string> items = [.. strings];
        if (items.Count == 0)
        {
            items.Add(string.Empty);
        }

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.TXT,
            RawRecordType = (ushort)DnsRecordType.TXT,
            TimeToLive = ttl,
            TxtStrings = items
        };
    }

    public static DnsResourceRecord CreateSoa(
        string name,
        string mName,
        string rName,
        uint serial,
        uint refresh,
        uint retry,
        uint expire,
        uint minimum,
        uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(mName);
        ArgumentNullException.ThrowIfNull(rName);

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.SOA,
            RawRecordType = (ushort)DnsRecordType.SOA,
            TimeToLive = ttl,
            SoaMName = DnsQuestion.NormalizeName(mName),
            SoaRName = DnsQuestion.NormalizeName(rName),
            SoaSerial = serial,
            SoaRefresh = refresh,
            SoaRetry = retry,
            SoaExpire = expire,
            SoaMinimum = minimum
        };
    }

    public static DnsResourceRecord CreateSrv(
        string name,
        ushort priority,
        ushort weight,
        ushort port,
        string target,
        uint ttl = 300)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(target);

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = DnsRecordType.SRV,
            RawRecordType = (ushort)DnsRecordType.SRV,
            TimeToLive = ttl,
            Priority = priority,
            Weight = weight,
            Port = port,
            TargetName = DnsQuestion.NormalizeName(target)
        };
    }

    public static DnsResourceRecord CreateOpt(
        ushort udpPayloadSize = 1232,
        bool dnssecOk = false,
        byte extendedRcode = 0,
        byte ednsVersion = 0,
        ReadOnlyMemory<byte> options = default)
    {
        uint ttl = ((uint)extendedRcode << 24)
            | ((uint)ednsVersion << 16)
            | (dnssecOk ? 0x8000u : 0u);

        return new DnsResourceRecord
        {
            Name = string.Empty,
            RecordType = DnsRecordType.OPT,
            RawRecordType = (ushort)DnsRecordType.OPT,
            RecordClass = udpPayloadSize,
            TimeToLive = ttl,
            RawData = options.IsEmpty ? ReadOnlyMemory<byte>.Empty : options.ToArray()
        };
    }

    public static DnsResourceRecord CreateSvcb(
        string name,
        ushort svcPriority,
        string targetName,
        IEnumerable<SvcParam>? svcParams = null,
        uint ttl = 300)
    {
        return CreateServiceBinding(DnsRecordType.SVCB, name, svcPriority, targetName, svcParams, ttl);
    }

    public static DnsResourceRecord CreateHttps(
        string name,
        ushort svcPriority,
        string targetName,
        IEnumerable<SvcParam>? svcParams = null,
        uint ttl = 300)
    {
        return CreateServiceBinding(DnsRecordType.HTTPS, name, svcPriority, targetName, svcParams, ttl);
    }

    public static DnsResourceRecord CreateRaw(
        string name,
        ushort rawRecordType,
        ushort recordClass,
        uint ttl,
        ReadOnlyMemory<byte> rawData)
    {
        ArgumentNullException.ThrowIfNull(name);

        DnsRecordType knownType = Enum.IsDefined((DnsRecordType)rawRecordType)
            ? (DnsRecordType)rawRecordType
            : DnsRecordType.None;

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = knownType,
            RawRecordType = rawRecordType,
            RecordClass = recordClass,
            TimeToLive = ttl,
            RawData = rawData.ToArray()
        };
    }

    /// <summary>
    /// Returns a copy of this SVCB/HTTPS record with updated service parameters.
    /// </summary>
    public DnsResourceRecord WithSvcParams(IReadOnlyList<SvcParam> updatedParams)
    {
        ArgumentNullException.ThrowIfNull(updatedParams);

        return this with
        {
            SvcParams = [.. updatedParams],
            RawData = ReadOnlyMemory<byte>.Empty
        };
    }

    private static DnsResourceRecord CreateServiceBinding(
        DnsRecordType type,
        string name,
        ushort svcPriority,
        string targetName,
        IEnumerable<SvcParam>? svcParams,
        uint ttl)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(targetName);

        List<SvcParam> orderedParams = svcParams is not null ? [.. svcParams] : [];
        orderedParams.Sort((left, right) => left.Key.CompareTo(right.Key));

        return new DnsResourceRecord
        {
            Name = DnsQuestion.NormalizeName(name),
            RecordType = type,
            RawRecordType = (ushort)type,
            TimeToLive = ttl,
            SvcPriority = svcPriority,
            TargetName = DnsQuestion.NormalizeName(targetName),
            SvcParams = orderedParams
        };
    }
}
