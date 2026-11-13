namespace DnsPulse.Core.Wire;

/// <summary>
/// Represents a DNS question section entry.
/// </summary>
public sealed record DnsQuestion
{
    public string Name { get; init; } = string.Empty;

    public DnsRecordType RecordType { get; init; } = DnsRecordType.A;

    public ushort RawRecordType { get; init; } = (ushort)DnsRecordType.A;

    public ushort RecordClass { get; init; } = (ushort)DnsClass.In;

    /// <summary>
    /// Creates a standard IN-class DNS question.
    /// </summary>
    public static DnsQuestion Create(string name, DnsRecordType recordType, DnsClass recordClass = DnsClass.In)
    {
        ArgumentNullException.ThrowIfNull(name);

        return new DnsQuestion
        {
            Name = NormalizeName(name),
            RecordType = recordType,
            RawRecordType = (ushort)recordType,
            RecordClass = (ushort)recordClass
        };
    }

    internal static string NormalizeName(string name)
    {
        string trimmed = name.Trim();
        if (trimmed.Length == 0 || trimmed == ".")
        {
            return string.Empty;
        }

        return trimmed.TrimEnd('.');
    }
}
