namespace DnsPulse.Core.Wire;

/// <summary>
/// Represents the 12-byte RFC 1035 DNS message header including RFC 4035 AD/CD bits.
/// </summary>
public sealed record DnsHeader
{
    public const int WireSize = 12;

    public ushort Id { get; init; }

    public bool IsResponse { get; init; }

    public byte OpCode { get; init; }

    public bool AuthoritativeAnswer { get; init; }

    public bool Truncated { get; init; }

    public bool RecursionDesired { get; init; }

    public bool RecursionAvailable { get; init; }

    public bool AuthenticData { get; init; }

    public bool CheckingDisabled { get; init; }

    public DnsResponseCode ResponseCode { get; init; }

    public ushort QuestionCount { get; init; }

    public ushort AnswerCount { get; init; }

    public ushort AuthorityCount { get; init; }

    public ushort AdditionalCount { get; init; }

    /// <summary>
    /// Encodes the 16-bit DNS header flags field in network order representation.
    /// </summary>
    public ushort EncodeFlags()
    {
        int flags = 0;
        if (IsResponse)
        {
            flags |= 0x8000;
        }

        flags |= (OpCode & 0x0F) << 11;

        if (AuthoritativeAnswer)
        {
            flags |= 0x0400;
        }

        if (Truncated)
        {
            flags |= 0x0200;
        }

        if (RecursionDesired)
        {
            flags |= 0x0100;
        }

        if (RecursionAvailable)
        {
            flags |= 0x0080;
        }

        if (AuthenticData)
        {
            flags |= 0x0020;
        }

        if (CheckingDisabled)
        {
            flags |= 0x0010;
        }

        flags |= (int)ResponseCode & 0x0F;
        return (ushort)flags;
    }

    /// <summary>
    /// Creates a <see cref="DnsHeader"/> from raw header fields.
    /// </summary>
    public static DnsHeader FromWireFields(
        ushort id,
        ushort flags,
        ushort questionCount,
        ushort answerCount,
        ushort authorityCount,
        ushort additionalCount)
    {
        return new DnsHeader
        {
            Id = id,
            IsResponse = (flags & 0x8000) != 0,
            OpCode = (byte)((flags >> 11) & 0x0F),
            AuthoritativeAnswer = (flags & 0x0400) != 0,
            Truncated = (flags & 0x0200) != 0,
            RecursionDesired = (flags & 0x0100) != 0,
            RecursionAvailable = (flags & 0x0080) != 0,
            AuthenticData = (flags & 0x0020) != 0,
            CheckingDisabled = (flags & 0x0010) != 0,
            ResponseCode = (DnsResponseCode)(flags & 0x0F),
            QuestionCount = questionCount,
            AnswerCount = answerCount,
            AuthorityCount = authorityCount,
            AdditionalCount = additionalCount
        };
    }
}
