using System.Buffers.Binary;
using System.Text;

namespace DnsPulse.Engine.Sidecar;

/// <summary>
/// Result of inspecting a buffer for a TLS handshake <c>ClientHello</c> and its SNI extension range.
/// </summary>
/// <param name="IsTlsClientHello"><c>true</c> if the buffer starts with a TLS handshake record containing a <c>ClientHello</c>.</param>
/// <param name="RecordLength">Declared TLS record payload length in bytes (0 if not a TLS record).</param>
/// <param name="HandshakeLength">Declared <c>ClientHello</c> handshake message body length in bytes.</param>
/// <param name="SniExtensionOffset">Zero-based byte offset of the SNI (<c>0x0000</c>) extension header (type + length + data), or -1 if absent.</param>
/// <param name="SniExtensionLength">Total byte length of the SNI extension (including 4-byte extension header), or 0 if absent.</param>
/// <param name="ServerNameOffset">Zero-based byte offset of the UTF-8/ASCII host name inside the SNI extension, or -1 if absent.</param>
/// <param name="ServerNameLength">Byte length of the SNI host name, or 0 if absent.</param>
/// <param name="ServerName">Extracted SNI host name if present and fully within the inspected buffer; otherwise <c>null</c>.</param>
/// <param name="IsTruncated"><c>true</c> when the buffer ends before the declared TLS record or <c>ClientHello</c> structure finishes.</param>
/// <param name="HasEchExtension"><c>true</c> when an Encrypted Client Hello (<c>0xFE0D</c>) extension was observed.</param>
public readonly record struct TlsClientHelloInspection(
    bool IsTlsClientHello,
    int RecordLength,
    int HandshakeLength,
    int SniExtensionOffset,
    int SniExtensionLength,
    int ServerNameOffset,
    int ServerNameLength,
    string? ServerName,
    bool IsTruncated,
    bool HasEchExtension)
{
    /// <summary>
    /// Gets a value indicating whether an SNI (<c>0x0000</c>) extension was located in the buffer.
    /// </summary>
    public bool HasSni => this.SniExtensionOffset >= 0 && this.SniExtensionLength > 0;

    /// <summary>
    /// Empty inspection result representing non-TLS or non-<c>ClientHello</c> data.
    /// </summary>
    public static TlsClientHelloInspection NotClientHello { get; } = new(
        IsTlsClientHello: false,
        RecordLength: 0,
        HandshakeLength: 0,
        SniExtensionOffset: -1,
        SniExtensionLength: 0,
        ServerNameOffset: -1,
        ServerNameLength: 0,
        ServerName: null,
        IsTruncated: false,
        HasEchExtension: false);
}

/// <summary>
/// Allocation-free <see cref="ReadOnlySpan{T}"/> inspector for TLS <c>ClientHello</c> records,
/// locating the exact SNI (<c>0x0000</c>) extension and hostname byte ranges for TCP fragmentation.
/// </summary>
public static class TlsClientHelloInspector
{
    private const byte TlsContentTypeHandshake = 0x16;
    private const byte TlsHandshakeTypeClientHello = 0x01;
    private const byte TlsRecordMajorVersion = 0x03;
    private const int TlsRecordHeaderSize = 5;
    private const int HandshakeHeaderSize = 4;
    private const int ClientHelloRandomSize = 32;
    private const int MaxSessionIdLength = 32;
    private const ushort ExtensionServerName = 0x0000;
    private const ushort ExtensionEncryptedClientHello = 0xFE0D;
    private const byte SniHostNameType = 0x00;

    /// <summary>
    /// Inspects <paramref name="buffer"/> and returns a <see cref="TlsClientHelloInspection"/> without throwing on truncated or non-TLS input.
    /// </summary>
    public static TlsClientHelloInspection Inspect(ReadOnlySpan<byte> buffer)
    {
        TryInspect(buffer, out TlsClientHelloInspection result);
        return result;
    }

    /// <summary>
    /// Attempts to inspect <paramref name="buffer"/> as a TLS handshake <c>ClientHello</c> record.
    /// </summary>
    /// <returns><c>true</c> if <paramref name="buffer"/> begins with a valid TLS handshake <c>ClientHello</c> header; otherwise <c>false</c>.</returns>
    public static bool TryInspect(ReadOnlySpan<byte> buffer, out TlsClientHelloInspection result)
    {
        result = TlsClientHelloInspection.NotClientHello;

        // Minimum: 5-byte TLS record header + 1-byte handshake type
        if (buffer.Length < TlsRecordHeaderSize + 1)
        {
            return false;
        }

        if (buffer[0] != TlsContentTypeHandshake || buffer[1] != TlsRecordMajorVersion || buffer[2] > 0x04)
        {
            return false;
        }

        int recordLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(3, 2));
        if (recordLength < HandshakeHeaderSize)
        {
            return false;
        }

        if (buffer[TlsRecordHeaderSize] != TlsHandshakeTypeClientHello)
        {
            return false;
        }

        bool isTruncated = buffer.Length < TlsRecordHeaderSize + recordLength;
        int recordLimit = Math.Min(buffer.Length, TlsRecordHeaderSize + recordLength);

        if (recordLimit < TlsRecordHeaderSize + HandshakeHeaderSize)
        {
            result = new TlsClientHelloInspection(
                IsTlsClientHello: true,
                RecordLength: recordLength,
                HandshakeLength: 0,
                SniExtensionOffset: -1,
                SniExtensionLength: 0,
                ServerNameOffset: -1,
                ServerNameLength: 0,
                ServerName: null,
                IsTruncated: true,
                HasEchExtension: false);
            return true;
        }

        int handshakeLength = (buffer[6] << 16) | (buffer[7] << 8) | buffer[8];
        int handshakeBodyStart = TlsRecordHeaderSize + HandshakeHeaderSize;
        int handshakeEnd = Math.Min(recordLimit, handshakeBodyStart + handshakeLength);
        if (buffer.Length < handshakeBodyStart + handshakeLength)
        {
            isTruncated = true;
        }

        // ClientHello body begins with 2-byte client_version + 32-byte random + 1-byte session_id_length
        int pos = handshakeBodyStart;
        if (pos + 2 + ClientHelloRandomSize + 1 > handshakeEnd)
        {
            result = CreatePartialResult(recordLength, handshakeLength, isTruncated: true);
            return true;
        }

        // Validate legacy client version major byte is 0x03 (SSL 3.0 / TLS 1.x)
        if (buffer[pos] != TlsRecordMajorVersion)
        {
            return false;
        }

        pos += 2 + ClientHelloRandomSize;

        int sessionIdLength = buffer[pos++];
        if (sessionIdLength > MaxSessionIdLength)
        {
            return false;
        }

        if (pos + sessionIdLength + 2 > handshakeEnd)
        {
            result = CreatePartialResult(recordLength, handshakeLength, isTruncated: true);
            return true;
        }

        pos += sessionIdLength;

        int cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(pos, 2));
        pos += 2;
        if (cipherSuitesLength < 2 || (cipherSuitesLength & 1) != 0)
        {
            return false;
        }

        if (pos + cipherSuitesLength + 1 > handshakeEnd)
        {
            result = CreatePartialResult(recordLength, handshakeLength, isTruncated: true);
            return true;
        }

        pos += cipherSuitesLength;

        int compressionMethodsLength = buffer[pos++];
        if (compressionMethodsLength < 1)
        {
            return false;
        }

        if (pos + compressionMethodsLength > handshakeEnd)
        {
            result = CreatePartialResult(recordLength, handshakeLength, isTruncated: true);
            return true;
        }

        pos += compressionMethodsLength;

        // No extensions present
        if (pos == handshakeEnd)
        {
            result = CreatePartialResult(recordLength, handshakeLength, isTruncated);
            return true;
        }

        if (pos + 2 > handshakeEnd)
        {
            result = CreatePartialResult(recordLength, handshakeLength, isTruncated: true);
            return true;
        }

        int extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(pos, 2));
        pos += 2;
        int extensionsEnd = Math.Min(handshakeEnd, pos + extensionsLength);
        if (handshakeEnd < pos + extensionsLength)
        {
            isTruncated = true;
        }

        int sniExtensionOffset = -1;
        int sniExtensionLength = 0;
        int serverNameOffset = -1;
        int serverNameLength = 0;
        string? serverName = null;
        bool hasEchExtension = false;

        while (pos + 4 <= extensionsEnd)
        {
            ushort extType = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(pos, 2));
            int extDataLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(pos + 2, 2));
            int extDataStart = pos + 4;

            if (extDataStart + extDataLength > extensionsEnd)
            {
                isTruncated = true;
                break;
            }

            if (extType == ExtensionEncryptedClientHello)
            {
                hasEchExtension = true;
            }
            else if (extType == ExtensionServerName && sniExtensionOffset < 0)
            {
                sniExtensionOffset = pos;
                sniExtensionLength = 4 + extDataLength;
                ParseSniExtensionPayload(
                    buffer,
                    extDataStart,
                    extDataLength,
                    out serverNameOffset,
                    out serverNameLength,
                    out serverName);
            }

            pos = extDataStart + extDataLength;
        }

        if (pos < extensionsEnd)
        {
            isTruncated = true;
        }

        result = new TlsClientHelloInspection(
            IsTlsClientHello: true,
            RecordLength: recordLength,
            HandshakeLength: handshakeLength,
            SniExtensionOffset: sniExtensionOffset,
            SniExtensionLength: sniExtensionLength,
            ServerNameOffset: serverNameOffset,
            ServerNameLength: serverNameLength,
            ServerName: serverName,
            IsTruncated: isTruncated,
            HasEchExtension: hasEchExtension);
        return true;
    }

    private static TlsClientHelloInspection CreatePartialResult(int recordLength, int handshakeLength, bool isTruncated)
    {
        return new TlsClientHelloInspection(
            IsTlsClientHello: true,
            RecordLength: recordLength,
            HandshakeLength: handshakeLength,
            SniExtensionOffset: -1,
            SniExtensionLength: 0,
            ServerNameOffset: -1,
            ServerNameLength: 0,
            ServerName: null,
            IsTruncated: isTruncated,
            HasEchExtension: false);
    }

    private static void ParseSniExtensionPayload(
        ReadOnlySpan<byte> buffer,
        int extDataStart,
        int extDataLength,
        out int serverNameOffset,
        out int serverNameLength,
        out string? serverName)
    {
        serverNameOffset = -1;
        serverNameLength = 0;
        serverName = null;

        if (extDataLength < 2)
        {
            return;
        }

        int listLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(extDataStart, 2));
        int listStart = extDataStart + 2;
        int listEnd = Math.Min(extDataStart + extDataLength, listStart + listLength);

        int entryPos = listStart;
        while (entryPos + 3 <= listEnd)
        {
            byte nameType = buffer[entryPos];
            int nameLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(entryPos + 1, 2));
            int nameStart = entryPos + 3;

            if (nameStart + nameLength > listEnd)
            {
                break;
            }

            if (nameType == SniHostNameType && nameLength > 0)
            {
                serverNameOffset = nameStart;
                serverNameLength = nameLength;
                serverName = Encoding.UTF8.GetString(buffer.Slice(nameStart, nameLength));
                return;
            }

            entryPos = nameStart + nameLength;
        }
    }
}
