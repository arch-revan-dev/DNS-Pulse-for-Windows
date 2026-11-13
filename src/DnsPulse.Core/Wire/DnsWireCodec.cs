using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DnsPulse.Core.Wire;

/// <summary>
/// High-performance, bounds-checked RFC 1035 / EDNS0 / RFC 9460 DNS wire format parser and serializer.
/// </summary>
public static class DnsWireCodec
{
    private const int MaxDomainNameWireLength = 255;
    private const int MaxLabelLength = 63;
    private const int MaxCompressionJumps = 128;
    private const int MaxCompressionOffset = 0x3FFF;
    private const int MaxPacketSize = 65535;

    /// <summary>
    /// Parses a DNS wire packet into a <see cref="DnsMessage"/>, throwing <see cref="FormatException"/> on malformed data.
    /// </summary>
    public static DnsMessage Parse(ReadOnlySpan<byte> packet)
    {
        if (!TryParseCore(packet, out DnsMessage? message, out string? error))
        {
            throw new FormatException(error ?? "Malformed DNS packet.");
        }

        return message!;
    }

    /// <summary>
    /// Attempts to parse a DNS wire packet safely without throwing on malformed, truncated, or cyclic packets.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> packet, [NotNullWhen(true)] out DnsMessage? message)
    {
        return TryParseCore(packet, out message, out _);
    }

    /// <summary>
    /// Serializes a <see cref="DnsMessage"/> directly into <paramref name="destination"/>, returning the byte count written.
    /// </summary>
    public static int Serialize(DnsMessage message, Span<byte> destination, bool enableCompression = true)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (!TrySerializeCore(message, destination, enableCompression, out int bytesWritten, out string? error, out bool bufferTooSmall))
        {
            if (bufferTooSmall)
            {
                throw new ArgumentException("Destination span is too small for the serialized DNS message.", nameof(destination));
            }

            throw new FormatException(error ?? "Invalid DNS message contents.");
        }

        return bytesWritten;
    }

    /// <summary>
    /// Attempts to serialize a <see cref="DnsMessage"/> into <paramref name="destination"/>.
    /// </summary>
    public static bool TrySerialize(
        DnsMessage message,
        Span<byte> destination,
        out int bytesWritten,
        bool enableCompression = true)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (TrySerializeCore(message, destination, enableCompression, out bytesWritten, out string? error, out bool bufferTooSmall))
        {
            return true;
        }

        if (!bufferTooSmall)
        {
            throw new FormatException(error ?? "Invalid DNS message contents.");
        }

        bytesWritten = 0;
        return false;
    }

    /// <summary>
    /// Serializes a <see cref="DnsMessage"/> into a newly allocated <see cref="byte"/> array using <see cref="ArrayPool{T}"/> internally.
    /// </summary>
    public static byte[] Serialize(DnsMessage message, bool enableCompression = true)
    {
        ArgumentNullException.ThrowIfNull(message);

        using PooledDnsPacket pooled = SerializePooled(message, enableCompression);
        return pooled.Span.ToArray();
    }

    /// <summary>
    /// Serializes a <see cref="DnsMessage"/> into a pooled buffer owned by the returned <see cref="PooledDnsPacket"/>.
    /// </summary>
    public static PooledDnsPacket SerializePooled(DnsMessage message, bool enableCompression = true)
    {
        ArgumentNullException.ThrowIfNull(message);

        int capacity = 4096;
        while (true)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(capacity);
            bool success = false;
            try
            {
                if (TrySerializeCore(message, rented, enableCompression, out int written, out string? error, out bool bufferTooSmall))
                {
                    success = true;
                    return new PooledDnsPacket(rented, written);
                }

                if (!bufferTooSmall)
                {
                    throw new FormatException(error ?? "Invalid DNS message contents.");
                }
            }
            finally
            {
                if (!success)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            if (capacity >= MaxPacketSize)
            {
                throw new FormatException("DNS message exceeds maximum 65535-byte wire length.");
            }

            capacity = Math.Min(MaxPacketSize, capacity * 2);
        }
    }

    private static bool TryParseCore(
        ReadOnlySpan<byte> packet,
        [NotNullWhen(true)] out DnsMessage? message,
        out string? error)
    {
        message = null;
        error = null;

        if (packet.Length < DnsHeader.WireSize)
        {
            error = "DNS packet is shorter than 12-byte header.";
            return false;
        }

        if (packet.Length > MaxPacketSize)
        {
            error = "DNS packet exceeds maximum 65535-byte wire length.";
            return false;
        }

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(0, 2));
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(4, 2));
        ushort anCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        ushort nsCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(8, 2));
        ushort arCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(10, 2));

        DnsHeader header = DnsHeader.FromWireFields(id, flags, qdCount, anCount, nsCount, arCount);
        int offset = DnsHeader.WireSize;

        int maxPossibleRecords = packet.Length - DnsHeader.WireSize;
        if (qdCount > maxPossibleRecords || anCount + nsCount + arCount > maxPossibleRecords)
        {
            error = "DNS header section counts exceed available packet bytes.";
            return false;
        }

        List<DnsQuestion> questions = new(qdCount);
        for (int index = 0; index < qdCount; index++)
        {
            if (!TryReadDomainName(packet, ref offset, packet.Length, out string qName, out error))
            {
                return false;
            }

            if (offset + 4 > packet.Length)
            {
                error = "Truncated DNS question section.";
                return false;
            }

            ushort rawType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, 2));
            ushort qClass = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2, 2));
            offset += 4;

            DnsRecordType knownType = Enum.IsDefined((DnsRecordType)rawType)
                ? (DnsRecordType)rawType
                : DnsRecordType.None;

            questions.Add(new DnsQuestion
            {
                Name = qName,
                RecordType = knownType,
                RawRecordType = rawType,
                RecordClass = qClass
            });
        }

        if (!TryReadResourceRecords(packet, ref offset, anCount, out List<DnsResourceRecord> answers, out error)
            || !TryReadResourceRecords(packet, ref offset, nsCount, out List<DnsResourceRecord> authorities, out error)
            || !TryReadResourceRecords(packet, ref offset, arCount, out List<DnsResourceRecord> additionals, out error))
        {
            return false;
        }

        message = new DnsMessage
        {
            Header = header,
            Questions = questions,
            Answers = answers,
            Authorities = authorities,
            Additionals = additionals
        };
        return true;
    }

    private static bool TryReadResourceRecords(
        ReadOnlySpan<byte> packet,
        ref int offset,
        ushort count,
        out List<DnsResourceRecord> records,
        out string? error)
    {
        records = new List<DnsResourceRecord>(count);
        error = null;

        for (int index = 0; index < count; index++)
        {
            if (!TryReadDomainName(packet, ref offset, packet.Length, out string name, out error))
            {
                return false;
            }

            if (offset + 10 > packet.Length)
            {
                error = "Truncated DNS resource record header.";
                return false;
            }

            ushort rawType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, 2));
            ushort rrClass = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2, 2));
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset + 4, 4));
            ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 8, 2));
            offset += 10;

            if (offset + rdLength > packet.Length)
            {
                error = "Truncated DNS resource record RDATA.";
                return false;
            }

            int rdStart = offset;
            int rdEnd = rdStart + rdLength;
            if (!TryParseResourceRecordData(packet, name, rawType, rrClass, ttl, rdStart, rdEnd, out DnsResourceRecord? record, out error))
            {
                return false;
            }

            records.Add(record!);
            offset = rdEnd;
        }

        return true;
    }

    private static bool TryParseResourceRecordData(
        ReadOnlySpan<byte> packet,
        string name,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        error = null;
        int rdLength = rdEnd - rdStart;
        DnsRecordType knownType = Enum.IsDefined((DnsRecordType)rawType)
            ? (DnsRecordType)rawType
            : DnsRecordType.None;
        ReadOnlyMemory<byte> rawCopy = rdLength > 0 ? packet.Slice(rdStart, rdLength).ToArray() : ReadOnlyMemory<byte>.Empty;

        switch (knownType)
        {
            case DnsRecordType.A:
                if (rdLength != 4)
                {
                    error = "A record RDATA must be exactly 4 bytes.";
                    return false;
                }

                record = new DnsResourceRecord
                {
                    Name = name,
                    RecordType = DnsRecordType.A,
                    RawRecordType = rawType,
                    RecordClass = rrClass,
                    TimeToLive = ttl,
                    Address = new IPAddress(packet.Slice(rdStart, 4)),
                    RawData = rawCopy
                };
                return true;

            case DnsRecordType.AAAA:
                if (rdLength != 16)
                {
                    error = "AAAA record RDATA must be exactly 16 bytes.";
                    return false;
                }

                record = new DnsResourceRecord
                {
                    Name = name,
                    RecordType = DnsRecordType.AAAA,
                    RawRecordType = rawType,
                    RecordClass = rrClass,
                    TimeToLive = ttl,
                    Address = new IPAddress(packet.Slice(rdStart, 16)),
                    RawData = rawCopy
                };
                return true;

            case DnsRecordType.NS:
            case DnsRecordType.CNAME:
            case DnsRecordType.PTR:
                return TryParseSingleNameRecord(packet, name, knownType, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            case DnsRecordType.MX:
                return TryParseMxRecord(packet, name, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            case DnsRecordType.SOA:
                return TryParseSoaRecord(packet, name, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            case DnsRecordType.TXT:
                return TryParseTxtRecord(packet, name, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            case DnsRecordType.SRV:
                return TryParseSrvRecord(packet, name, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            case DnsRecordType.OPT:
                return TryParseOptRecord(packet, name, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            case DnsRecordType.SVCB:
            case DnsRecordType.HTTPS:
                return TryParseServiceBindingRecord(packet, name, knownType, rawType, rrClass, ttl, rdStart, rdEnd, rawCopy, out record, out error);

            default:
                record = new DnsResourceRecord
                {
                    Name = name,
                    RecordType = DnsRecordType.None,
                    RawRecordType = rawType,
                    RecordClass = rrClass,
                    TimeToLive = ttl,
                    RawData = rawCopy
                };
                return true;
        }
    }

    private static bool TryParseSingleNameRecord(
        ReadOnlySpan<byte> packet,
        string name,
        DnsRecordType knownType,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        int cursor = rdStart;
        if (!TryReadDomainName(packet, ref cursor, rdEnd, out string target, out error))
        {
            return false;
        }

        if (cursor != rdEnd)
        {
            error = "Domain-name RDATA contains unexpected trailing bytes.";
            return false;
        }

        record = new DnsResourceRecord
        {
            Name = name,
            RecordType = knownType,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            TargetName = target,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryParseMxRecord(
        ReadOnlySpan<byte> packet,
        string name,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        if (rdEnd - rdStart < 3)
        {
            error = "MX record RDATA is too short.";
            return false;
        }

        ushort preference = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(rdStart, 2));
        int cursor = rdStart + 2;
        if (!TryReadDomainName(packet, ref cursor, rdEnd, out string exchange, out error))
        {
            return false;
        }

        if (cursor != rdEnd)
        {
            error = "MX record RDATA contains unexpected trailing bytes.";
            return false;
        }

        record = new DnsResourceRecord
        {
            Name = name,
            RecordType = DnsRecordType.MX,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            Preference = preference,
            TargetName = exchange,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryParseSoaRecord(
        ReadOnlySpan<byte> packet,
        string name,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        int cursor = rdStart;
        if (!TryReadDomainName(packet, ref cursor, rdEnd, out string mName, out error)
            || !TryReadDomainName(packet, ref cursor, rdEnd, out string rName, out error))
        {
            return false;
        }

        if (cursor + 20 != rdEnd)
        {
            error = "SOA record RDATA length mismatch.";
            return false;
        }

        uint serial = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(cursor, 4));
        uint refresh = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(cursor + 4, 4));
        uint retry = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(cursor + 8, 4));
        uint expire = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(cursor + 12, 4));
        uint minimum = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(cursor + 16, 4));

        record = new DnsResourceRecord
        {
            Name = name,
            RecordType = DnsRecordType.SOA,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            SoaMName = mName,
            SoaRName = rName,
            SoaSerial = serial,
            SoaRefresh = refresh,
            SoaRetry = retry,
            SoaExpire = expire,
            SoaMinimum = minimum,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryParseTxtRecord(
        ReadOnlySpan<byte> packet,
        string name,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        error = null;
        if (rdEnd == rdStart)
        {
            error = "TXT record RDATA cannot be empty.";
            return false;
        }

        List<string> strings = [];
        int cursor = rdStart;
        while (cursor < rdEnd)
        {
            byte strLen = packet[cursor++];
            if (cursor + strLen > rdEnd)
            {
                error = "Truncated TXT character-string.";
                return false;
            }

            strings.Add(Encoding.UTF8.GetString(packet.Slice(cursor, strLen)));
            cursor += strLen;
        }

        record = new DnsResourceRecord
        {
            Name = name,
            RecordType = DnsRecordType.TXT,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            TxtStrings = strings,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryParseSrvRecord(
        ReadOnlySpan<byte> packet,
        string name,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        if (rdEnd - rdStart < 7)
        {
            error = "SRV record RDATA is too short.";
            return false;
        }

        ushort priority = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(rdStart, 2));
        ushort weight = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(rdStart + 2, 2));
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(rdStart + 4, 2));
        int cursor = rdStart + 6;
        if (!TryReadDomainName(packet, ref cursor, rdEnd, out string target, out error))
        {
            return false;
        }

        if (cursor != rdEnd)
        {
            error = "SRV record RDATA contains unexpected trailing bytes.";
            return false;
        }

        record = new DnsResourceRecord
        {
            Name = name,
            RecordType = DnsRecordType.SRV,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            Priority = priority,
            Weight = weight,
            Port = port,
            TargetName = target,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryParseOptRecord(
        ReadOnlySpan<byte> packet,
        string name,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        error = null;
        if (name.Length != 0)
        {
            error = "OPT record owner name must be the root domain.";
            return false;
        }

        int cursor = rdStart;
        while (cursor < rdEnd)
        {
            if (cursor + 4 > rdEnd)
            {
                error = "Truncated EDNS0 option header inside OPT record.";
                return false;
            }

            ushort optLen = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(cursor + 2, 2));
            cursor += 4;
            if (cursor + optLen > rdEnd)
            {
                error = "Truncated EDNS0 option data inside OPT record.";
                return false;
            }

            cursor += optLen;
        }

        record = new DnsResourceRecord
        {
            Name = string.Empty,
            RecordType = DnsRecordType.OPT,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryParseServiceBindingRecord(
        ReadOnlySpan<byte> packet,
        string name,
        DnsRecordType knownType,
        ushort rawType,
        ushort rrClass,
        uint ttl,
        int rdStart,
        int rdEnd,
        ReadOnlyMemory<byte> rawCopy,
        [NotNullWhen(true)] out DnsResourceRecord? record,
        out string? error)
    {
        record = null;
        if (rdEnd - rdStart < 3)
        {
            error = "SVCB/HTTPS record RDATA is too short.";
            return false;
        }

        ushort svcPriority = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(rdStart, 2));
        int cursor = rdStart + 2;
        if (!TryReadDomainName(packet, ref cursor, rdEnd, out string targetName, out error))
        {
            return false;
        }

        if (!SvcParam.TryParseList(packet[cursor..rdEnd], out List<SvcParam> svcParams, out error))
        {
            return false;
        }

        record = new DnsResourceRecord
        {
            Name = name,
            RecordType = knownType,
            RawRecordType = rawType,
            RecordClass = rrClass,
            TimeToLive = ttl,
            SvcPriority = svcPriority,
            TargetName = targetName,
            SvcParams = svcParams,
            RawData = rawCopy
        };
        return true;
    }

    private static bool TryReadDomainName(
        ReadOnlySpan<byte> packet,
        ref int offset,
        int inlineLimit,
        out string domainName,
        out string? error)
    {
        domainName = string.Empty;
        error = null;

        int pos = offset;
        int endAfterInline = -1;
        int totalWireOctets = 0;
        Span<ushort> visitedPointers = stackalloc ushort[MaxCompressionJumps];
        int jumpCount = 0;
        StringBuilder builder = new();

        while (true)
        {
            int currentLimit = endAfterInline < 0 ? inlineLimit : packet.Length;
            if (pos >= currentLimit)
            {
                error = "Truncated DNS domain name.";
                return false;
            }

            byte len = packet[pos];
            byte labelType = (byte)(len & 0xC0);

            if (labelType == 0xC0)
            {
                if (pos + 1 >= currentLimit)
                {
                    error = "Truncated DNS compression pointer.";
                    return false;
                }

                ushort pointer = (ushort)(((len & 0x3F) << 8) | packet[pos + 1]);
                if (endAfterInline < 0)
                {
                    endAfterInline = pos + 2;
                }

                if (pointer < DnsHeader.WireSize)
                {
                    error = "DNS compression pointer targets the message header.";
                    return false;
                }

                if (pointer >= packet.Length)
                {
                    error = "DNS compression pointer targets out-of-bounds offset.";
                    return false;
                }

                if (pointer == pos)
                {
                    error = "Self-referential DNS compression pointer detected.";
                    return false;
                }

                for (int i = 0; i < jumpCount; i++)
                {
                    if (visitedPointers[i] == pointer)
                    {
                        error = "Cyclic DNS compression pointer chain detected.";
                        return false;
                    }
                }

                if (jumpCount >= MaxCompressionJumps)
                {
                    error = "Exceeded maximum DNS compression pointer jumps.";
                    return false;
                }

                visitedPointers[jumpCount++] = pointer;
                pos = pointer;
                continue;
            }

            if (labelType != 0)
            {
                error = "Unsupported DNS label type bits.";
                return false;
            }

            if (len == 0)
            {
                totalWireOctets += 1;
                if (totalWireOctets > MaxDomainNameWireLength)
                {
                    error = "DNS domain name exceeds 255 wire octets.";
                    return false;
                }

                if (endAfterInline < 0)
                {
                    endAfterInline = pos + 1;
                }

                break;
            }

            totalWireOctets += 1 + len;
            if (totalWireOctets > MaxDomainNameWireLength)
            {
                error = "DNS domain name exceeds 255 wire octets.";
                return false;
            }

            if (pos + 1 + len >= currentLimit)
            {
                error = "Truncated DNS domain label.";
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.UTF8.GetString(packet.Slice(pos + 1, len)));
            pos += 1 + len;
        }

        offset = endAfterInline;
        domainName = builder.ToString();
        return true;
    }

    private static bool TrySerializeCore(
        DnsMessage message,
        Span<byte> destination,
        bool enableCompression,
        out int bytesWritten,
        out string? error,
        out bool bufferTooSmall)
    {
        bytesWritten = 0;
        error = null;
        bufferTooSmall = false;

        if (destination.Length < DnsHeader.WireSize)
        {
            bufferTooSmall = true;
            return false;
        }

        if (message.Questions.Count > ushort.MaxValue
            || message.Answers.Count > ushort.MaxValue
            || message.Authorities.Count > ushort.MaxValue
            || message.Additionals.Count > ushort.MaxValue)
        {
            error = "DNS section record count exceeds 16-bit limit.";
            return false;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(0, 2), message.Header.Id);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2, 2), message.Header.EncodeFlags());
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(4, 2), (ushort)message.Questions.Count);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(6, 2), (ushort)message.Answers.Count);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(8, 2), (ushort)message.Authorities.Count);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(10, 2), (ushort)message.Additionals.Count);

        int offset = DnsHeader.WireSize;
        Dictionary<string, int>? compressionMap = enableCompression
            ? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            : null;

        foreach (DnsQuestion question in message.Questions)
        {
            if (!TryWriteDomainName(question.Name, destination, ref offset, compressionMap, out error, out bufferTooSmall))
            {
                return false;
            }

            if (offset + 4 > destination.Length)
            {
                bufferTooSmall = true;
                return false;
            }

            ushort rawType = question.RawRecordType != 0 ? question.RawRecordType : (ushort)question.RecordType;
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), rawType);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset + 2, 2), question.RecordClass);
            offset += 4;
        }

        if (!TryWriteResourceRecords(message.Answers, destination, ref offset, compressionMap, out error, out bufferTooSmall)
            || !TryWriteResourceRecords(message.Authorities, destination, ref offset, compressionMap, out error, out bufferTooSmall)
            || !TryWriteResourceRecords(message.Additionals, destination, ref offset, compressionMap, out error, out bufferTooSmall))
        {
            return false;
        }

        bytesWritten = offset;
        return true;
    }

    private static bool TryWriteResourceRecords(
        IReadOnlyList<DnsResourceRecord> records,
        Span<byte> destination,
        ref int offset,
        Dictionary<string, int>? compressionMap,
        out string? error,
        out bool bufferTooSmall)
    {
        error = null;
        bufferTooSmall = false;

        foreach (DnsResourceRecord record in records)
        {
            if (!TryWriteDomainName(record.Name, destination, ref offset, compressionMap, out error, out bufferTooSmall))
            {
                return false;
            }

            if (offset + 10 > destination.Length)
            {
                bufferTooSmall = true;
                return false;
            }

            ushort rawType = record.RawRecordType != 0 ? record.RawRecordType : (ushort)record.RecordType;
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), rawType);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset + 2, 2), record.RecordClass);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset + 4, 4), record.TimeToLive);

            int rdLengthOffset = offset + 8;
            offset += 10;
            int rdataStart = offset;

            if (!TryWriteResourceRecordData(record, destination, ref offset, compressionMap, out error, out bufferTooSmall))
            {
                return false;
            }

            int rdLength = offset - rdataStart;
            if (rdLength > ushort.MaxValue)
            {
                error = "DNS resource record RDATA exceeds 65535 bytes.";
                return false;
            }

            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(rdLengthOffset, 2), (ushort)rdLength);
        }

        return true;
    }

    private static bool TryWriteResourceRecordData(
        DnsResourceRecord record,
        Span<byte> destination,
        ref int offset,
        Dictionary<string, int>? compressionMap,
        out string? error,
        out bool bufferTooSmall)
    {
        error = null;
        bufferTooSmall = false;

        switch (record.RecordType)
        {
            case DnsRecordType.A:
                if (record.Address is null || record.Address.AddressFamily != AddressFamily.InterNetwork)
                {
                    error = "A record requires a valid IPv4 address.";
                    return false;
                }

                if (offset + 4 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                if (!record.Address.TryWriteBytes(destination.Slice(offset, 4), out _))
                {
                    error = "Failed to serialize IPv4 address.";
                    return false;
                }

                offset += 4;
                return true;

            case DnsRecordType.AAAA:
                if (record.Address is null || record.Address.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    error = "AAAA record requires a valid IPv6 address.";
                    return false;
                }

                if (offset + 16 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                if (!record.Address.TryWriteBytes(destination.Slice(offset, 16), out _))
                {
                    error = "Failed to serialize IPv6 address.";
                    return false;
                }

                offset += 16;
                return true;

            case DnsRecordType.NS:
            case DnsRecordType.CNAME:
            case DnsRecordType.PTR:
                return TryWriteDomainName(record.TargetName ?? string.Empty, destination, ref offset, compressionMap, out error, out bufferTooSmall);

            case DnsRecordType.MX:
                if (offset + 2 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), record.Preference);
                offset += 2;
                return TryWriteDomainName(record.TargetName ?? string.Empty, destination, ref offset, compressionMap, out error, out bufferTooSmall);

            case DnsRecordType.SOA:
                if (!TryWriteDomainName(record.SoaMName ?? string.Empty, destination, ref offset, compressionMap, out error, out bufferTooSmall)
                    || !TryWriteDomainName(record.SoaRName ?? string.Empty, destination, ref offset, compressionMap, out error, out bufferTooSmall))
                {
                    return false;
                }

                if (offset + 20 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset, 4), record.SoaSerial);
                BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset + 4, 4), record.SoaRefresh);
                BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset + 8, 4), record.SoaRetry);
                BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset + 12, 4), record.SoaExpire);
                BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset + 16, 4), record.SoaMinimum);
                offset += 20;
                return true;

            case DnsRecordType.TXT:
                IReadOnlyList<string> txtItems = record.TxtStrings;
                if (txtItems.Count == 0)
                {
                    if (offset + 1 > destination.Length)
                    {
                        bufferTooSmall = true;
                        return false;
                    }

                    destination[offset++] = 0;
                    return true;
                }

                foreach (string text in txtItems)
                {
                    int byteCount = Encoding.UTF8.GetByteCount(text);
                    if (byteCount > 255)
                    {
                        error = "TXT character-string exceeds 255 bytes.";
                        return false;
                    }

                    if (offset + 1 + byteCount > destination.Length)
                    {
                        bufferTooSmall = true;
                        return false;
                    }

                    destination[offset++] = (byte)byteCount;
                    Encoding.UTF8.GetBytes(text, destination.Slice(offset, byteCount));
                    offset += byteCount;
                }

                return true;

            case DnsRecordType.SRV:
                if (offset + 6 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), record.Priority);
                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset + 2, 2), record.Weight);
                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset + 4, 2), record.Port);
                offset += 6;
                // RFC 2782 specifies SRV Target MUST NOT be compressed.
                return TryWriteDomainName(record.TargetName ?? string.Empty, destination, ref offset, null, out error, out bufferTooSmall);

            case DnsRecordType.OPT:
                if (!record.RawData.IsEmpty)
                {
                    if (offset + record.RawData.Length > destination.Length)
                    {
                        bufferTooSmall = true;
                        return false;
                    }

                    record.RawData.Span.CopyTo(destination.Slice(offset, record.RawData.Length));
                    offset += record.RawData.Length;
                }

                return true;

            case DnsRecordType.SVCB:
            case DnsRecordType.HTTPS:
                if (offset + 2 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), record.SvcPriority);
                offset += 2;
                // RFC 9460 Section 2.2 specifies TargetName MUST NOT be compressed.
                if (!TryWriteDomainName(record.TargetName ?? string.Empty, destination, ref offset, null, out error, out bufferTooSmall))
                {
                    return false;
                }

                if (!SvcParam.TryWriteList(record.SvcParams, destination[offset..], out int svcWritten))
                {
                    bufferTooSmall = true;
                    return false;
                }

                offset += svcWritten;
                return true;

            default:
                if (!record.RawData.IsEmpty)
                {
                    if (offset + record.RawData.Length > destination.Length)
                    {
                        bufferTooSmall = true;
                        return false;
                    }

                    record.RawData.Span.CopyTo(destination.Slice(offset, record.RawData.Length));
                    offset += record.RawData.Length;
                }

                return true;
        }
    }

    private static bool TryWriteDomainName(
        string name,
        Span<byte> destination,
        ref int offset,
        Dictionary<string, int>? compressionMap,
        out string? error,
        out bool bufferTooSmall)
    {
        error = null;
        bufferTooSmall = false;

        string normalized = DnsQuestion.NormalizeName(name);
        if (normalized.Length == 0)
        {
            if (offset + 1 > destination.Length)
            {
                bufferTooSmall = true;
                return false;
            }

            destination[offset++] = 0;
            return true;
        }

        string[] labels = normalized.Split('.');
        int totalWireLength = 1;
        foreach (string label in labels)
        {
            if (label.Length == 0)
            {
                error = string.Create(CultureInfo.InvariantCulture, $"Domain name '{name}' contains an empty label.");
                return false;
            }

            int utf8Len = Encoding.UTF8.GetByteCount(label);
            if (utf8Len > MaxLabelLength)
            {
                error = string.Create(CultureInfo.InvariantCulture, $"DNS label '{label}' exceeds 63 bytes.");
                return false;
            }

            totalWireLength += 1 + utf8Len;
        }

        if (totalWireLength > MaxDomainNameWireLength)
        {
            error = string.Create(CultureInfo.InvariantCulture, $"Domain name '{name}' exceeds 255 wire octets.");
            return false;
        }

        int cursor = 0;
        for (int index = 0; index < labels.Length; index++)
        {
            string suffix = normalized[cursor..];
            if (compressionMap is not null && compressionMap.TryGetValue(suffix, out int targetOffset))
            {
                if (offset + 2 > destination.Length)
                {
                    bufferTooSmall = true;
                    return false;
                }

                ushort pointer = (ushort)(0xC000 | targetOffset);
                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), pointer);
                offset += 2;
                return true;
            }

            if (compressionMap is not null && offset <= MaxCompressionOffset)
            {
                compressionMap[suffix] = offset;
            }

            string label = labels[index];
            int labelByteCount = Encoding.UTF8.GetByteCount(label);
            if (offset + 1 + labelByteCount > destination.Length)
            {
                bufferTooSmall = true;
                return false;
            }

            destination[offset++] = (byte)labelByteCount;
            Encoding.UTF8.GetBytes(label, destination.Slice(offset, labelByteCount));
            offset += labelByteCount;
            cursor += label.Length + 1;
        }

        if (offset + 1 > destination.Length)
        {
            bufferTooSmall = true;
            return false;
        }

        destination[offset++] = 0;
        return true;
    }
}
