namespace DnsPulse.Core.Wire;

/// <summary>
/// Represents a complete DNS wire protocol message with Header, Question, Answer, Authority, and Additional sections.
/// </summary>
public sealed record DnsMessage
{
    public DnsHeader Header { get; init; } = new();

    public IReadOnlyList<DnsQuestion> Questions { get; init; } = [];

    public IReadOnlyList<DnsResourceRecord> Answers { get; init; } = [];

    public IReadOnlyList<DnsResourceRecord> Authorities { get; init; } = [];

    public IReadOnlyList<DnsResourceRecord> Additionals { get; init; } = [];

    public bool IsTruncated => Header.Truncated;

    public bool IsAuthenticData => Header.AuthenticData;

    public bool HasEdns0 => FindOptRecord() is not null;

    public ushort? EdnsUdpPayloadSize => FindOptRecord()?.EdnsUdpPayloadSize;

    public bool IsDnssecOk => FindOptRecord()?.IsDnssecOk ?? false;

    public DnsResponseCode EffectiveResponseCode
    {
        get
        {
            DnsResourceRecord? opt = FindOptRecord();
            if (opt is null || opt.ExtendedRcode == 0)
            {
                return Header.ResponseCode;
            }

            int fullCode = (opt.ExtendedRcode << 4) | ((int)Header.ResponseCode & 0x0F);
            return (DnsResponseCode)fullCode;
        }
    }

    /// <summary>
    /// Creates a standard single-question DNS query message, optionally including an EDNS0 OPT record.
    /// </summary>
    public static DnsMessage CreateQuery(
        ushort id,
        string domain,
        DnsRecordType recordType,
        bool recursionDesired = true,
        bool enableEdns0 = true,
        ushort ednsUdpPayloadSize = 1232,
        bool dnssecOk = false,
        bool authenticData = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        DnsQuestion question = DnsQuestion.Create(domain, recordType);
        IReadOnlyList<DnsResourceRecord> additionals = enableEdns0
            ? [DnsResourceRecord.CreateOpt(ednsUdpPayloadSize, dnssecOk)]
            : [];

        return new DnsMessage
        {
            Header = new DnsHeader
            {
                Id = id,
                IsResponse = false,
                RecursionDesired = recursionDesired,
                AuthenticData = authenticData,
                QuestionCount = 1,
                AdditionalCount = (ushort)additionals.Count
            },
            Questions = [question],
            Additionals = additionals
        };
    }

    private DnsResourceRecord? FindOptRecord()
    {
        foreach (DnsResourceRecord record in Additionals)
        {
            if (record.RecordType == DnsRecordType.OPT)
            {
                return record;
            }
        }

        return null;
    }
}
