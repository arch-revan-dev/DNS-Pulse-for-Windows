using System.Buffers.Binary;
using System.Text;

namespace DnsPulse.App.NetworkEngine;

public sealed record DnsParsedAnswer(string Name, ushort Type, uint Ttl, string Data);

public sealed record DnsDecodedResponse(ushort TransactionId, int Rcode, List<DnsParsedAnswer> Answers, List<string> Ips);

public static class DnsPacketCodec
{
    public static byte[] EncodeQuery(string domain, ushort qtype = 1, ushort? transactionId = null)
    {
        var clean = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(clean))
            throw new ArgumentException("Domain cannot be empty", nameof(domain));

        var labels = clean.Split('.');
        using var ms = new MemoryStream(64);

        ushort txId = transactionId ?? (ushort)Random.Shared.Next(1, 65535);
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], txId);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x0100); // RD=1
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1); // QDCOUNT=1
        ms.Write(header);

        foreach (var label in labels)
        {
            var bytes = Encoding.UTF8.GetBytes(label);
            if (bytes.Length is 0 or > 63)
                throw new ArgumentException($"Invalid DNS label: {label}", nameof(domain));
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes);
        }
        ms.WriteByte(0);

        Span<byte> tail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(tail[0..2], qtype);
        BinaryPrimitives.WriteUInt16BigEndian(tail[2..4], 1); // IN
        ms.Write(tail);

        return ms.ToArray();
    }

    public static DnsDecodedResponse DecodeResponse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 12)
            throw new InvalidDataException("DNS response packet shorter than 12 bytes");

        ushort txId = BinaryPrimitives.ReadUInt16BigEndian(packet[0..2]);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        int rcode = flags & 0x0F;
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        ushort anCount = BinaryPrimitives.ReadUInt16BigEndian(packet[6..8]);

        int offset = 12;
        for (int i = 0; i < qdCount && offset < packet.Length; i++)
        {
            (_, offset) = ReadName(packet, offset);
            offset += 4;
        }

        var answers = new List<DnsParsedAnswer>();
        var ips = new List<string>();

        for (int i = 0; i < anCount && offset + 10 <= packet.Length; i++)
        {
            (string rrName, int nextOffset) = ReadName(packet, offset);
            offset = nextOffset;
            if (offset + 10 > packet.Length) break;

            ushort rtype = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, 2));
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset + 4, 4));
            ushort rdLen = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 8, 2));
            offset += 10;

            if (offset + rdLen > packet.Length) break;
            var rdata = packet.Slice(offset, rdLen);
            offset += rdLen;

            string data = "";
            if (rtype == 1 && rdLen == 4)
            {
                data = $"{rdata[0]}.{rdata[1]}.{rdata[2]}.{rdata[3]}";
                ips.Add(data);
            }
            else if (rtype == 28 && rdLen == 16)
            {
                var parts = new string[8];
                for (int j = 0; j < 8; j++)
                    parts[j] = BinaryPrimitives.ReadUInt16BigEndian(rdata.Slice(j * 2, 2)).ToString("x");
                data = string.Join(":", parts);
                ips.Add(data);
            }
            else if (rtype == 5)
            {
                (data, _) = ReadName(packet, offset - rdLen);
            }

            answers.Add(new DnsParsedAnswer(rrName, rtype, ttl, data));
        }

        return new DnsDecodedResponse(txId, rcode, answers, ips);
    }

    public static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static (string Name, int NextOffset) ReadName(ReadOnlySpan<byte> buf, int start)
    {
        var labels = new List<string>();
        int offset = start;
        int nextOffset = start;
        bool jumped = false;
        int guard = 0;

        while (offset < buf.Length && guard++ < 128)
        {
            byte len = buf[offset];
            if (len == 0)
            {
                if (!jumped) nextOffset = offset + 1;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (offset + 1 >= buf.Length) break;
                int ptr = ((len & 0x3F) << 8) | buf[offset + 1];
                if (!jumped) nextOffset = offset + 2;
                offset = ptr;
                jumped = true;
                continue;
            }
            offset++;
            if (offset + len > buf.Length) break;
            labels.Add(Encoding.UTF8.GetString(buf.Slice(offset, len)));
            offset += len;
            if (!jumped) nextOffset = offset;
        }

        return (string.Join('.', labels), nextOffset);
    }
}
