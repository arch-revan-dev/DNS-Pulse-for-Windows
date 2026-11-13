using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Unicode;

namespace DnsPulse.Core.Stamps;

/// <summary>
/// Encodes and decodes DNSCrypt v2 <c>sdns://</c> DNS stamps across all eight protocol variants.
/// </summary>
public static class DnsStampCodec
{
    /// <summary>The canonical DNS stamp URI scheme prefix.</summary>
    public const string SchemePrefix = "sdns://";

    private const int HashSizeBytes = 32;
    private const int PublicKeySizeBytes = 32;
    private const int MaxLengthPrefixedBytes = 255;
    private const int MaxVlpItemBytes = 127;

    /// <summary>
    /// Parses a DNSCrypt v2 <c>sdns://</c> stamp string.
    /// </summary>
    /// <param name="stamp">The <c>sdns://</c> stamp string.</param>
    /// <returns>The decoded <see cref="DnsStamp"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stamp"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="stamp"/> is malformed or unsupported.</exception>
    public static DnsStamp Parse(string stamp)
    {
        ArgumentNullException.ThrowIfNull(stamp);

        if (!TryDecodeInternal(stamp, out DnsStamp? result, out string? error))
        {
            throw new FormatException(error);
        }

        return result;
    }

    /// <summary>
    /// Attempts to parse a DNSCrypt v2 <c>sdns://</c> stamp string without throwing on malformed input.
    /// </summary>
    /// <param name="stamp">The <c>sdns://</c> stamp string.</param>
    /// <param name="result">When this method returns <see langword="true"/>, contains the decoded stamp.</param>
    /// <returns><see langword="true"/> if parsing succeeded; otherwise, <see langword="false"/>.</returns>
    public static bool TryParse(string? stamp, [NotNullWhen(true)] out DnsStamp? result)
    {
        if (stamp is null)
        {
            result = null;
            return false;
        }

        return TryDecodeInternal(stamp, out result, out _);
    }

    /// <summary>
    /// Encodes a <see cref="DnsStamp"/> into a canonical unpadded base64url <c>sdns://</c> string.
    /// </summary>
    /// <param name="stamp">The stamp to encode.</param>
    /// <returns>The encoded <c>sdns://</c> stamp string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="stamp"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">Thrown when the stamp contains invalid protocol fields or oversized values.</exception>
    public static string Encode(DnsStamp stamp)
    {
        ArgumentNullException.ThrowIfNull(stamp);

        List<byte> buffer = new(128)
        {
            (byte)stamp.Protocol
        };

        if (stamp.Protocol != DnsStampProtocol.AnonymizedDnsCryptRelay)
        {
            Span<byte> propsBytes = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(propsBytes, stamp.EffectiveRawProperties());
            AppendSpan(buffer, propsBytes);
        }

        switch (stamp.Protocol)
        {
            case DnsStampProtocol.Plain:
                WriteLengthPrefixedString(buffer, stamp.ServerAddress, nameof(stamp.ServerAddress));
                break;

            case DnsStampProtocol.DnsCrypt:
                WriteLengthPrefixedString(buffer, stamp.ServerAddress, nameof(stamp.ServerAddress));
                if (stamp.PublicKey.IsDefault || stamp.PublicKey.Length != PublicKeySizeBytes)
                {
                    throw new FormatException("DNSCrypt stamps require an exact 32-byte public key.");
                }

                WriteLengthPrefixedBytes(buffer, stamp.PublicKey.AsSpan(), nameof(stamp.PublicKey));
                WriteLengthPrefixedString(buffer, stamp.ProviderName, nameof(stamp.ProviderName));
                break;

            case DnsStampProtocol.DoH:
            case DnsStampProtocol.ObliviousDoHRelay:
                WriteLengthPrefixedString(buffer, stamp.ServerAddress, nameof(stamp.ServerAddress));
                WriteVlpHashes(buffer, stamp.Hashes);
                WriteLengthPrefixedString(buffer, stamp.HostName, nameof(stamp.HostName));
                WriteLengthPrefixedString(buffer, stamp.Path, nameof(stamp.Path));
                WriteOptionalVlpBootstrapIps(buffer, stamp.BootstrapIps);
                break;

            case DnsStampProtocol.DoT:
            case DnsStampProtocol.DoQ:
                WriteLengthPrefixedString(buffer, stamp.ServerAddress, nameof(stamp.ServerAddress));
                WriteVlpHashes(buffer, stamp.Hashes);
                WriteLengthPrefixedString(buffer, stamp.HostName, nameof(stamp.HostName));
                WriteOptionalVlpBootstrapIps(buffer, stamp.BootstrapIps);
                break;

            case DnsStampProtocol.ObliviousDoHTarget:
                WriteLengthPrefixedString(buffer, stamp.HostName, nameof(stamp.HostName));
                WriteLengthPrefixedString(buffer, stamp.Path, nameof(stamp.Path));
                break;

            case DnsStampProtocol.AnonymizedDnsCryptRelay:
                WriteLengthPrefixedString(buffer, stamp.ServerAddress, nameof(stamp.ServerAddress));
                break;

            default:
                throw new FormatException($"Unsupported DNS stamp protocol: {stamp.Protocol}.");
        }

        return string.Concat(SchemePrefix, EncodeBase64Url(buffer.ToArray()));
    }

    private static bool TryDecodeInternal(
        string stamp,
        [NotNullWhen(true)] out DnsStamp? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;

        if (!stamp.StartsWith(SchemePrefix, StringComparison.OrdinalIgnoreCase))
        {
            error = "DNS stamp must start with 'sdns://'.";
            return false;
        }

        ReadOnlySpan<char> payload = stamp.AsSpan(SchemePrefix.Length);
        if (!TryDecodeBase64Url(payload, out byte[]? data, out error))
        {
            return false;
        }

        if (data.Length < 1)
        {
            error = "DNS stamp payload is empty.";
            return false;
        }

        byte protocolByte = data[0];
        if (!TryMapProtocol(protocolByte, out DnsStampProtocol protocol))
        {
            error = string.Create(CultureInfo.InvariantCulture, $"Unknown DNS stamp protocol byte: 0x{protocolByte:X2}.");
            return false;
        }

        int offset = 1;
        ulong rawProps = 0;
        DnsStampFlags flags = DnsStampFlags.None;

        if (protocol != DnsStampProtocol.AnonymizedDnsCryptRelay)
        {
            if (data.Length - offset < 8)
            {
                error = "DNS stamp truncated before 8-byte properties header.";
                return false;
            }

            rawProps = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
            flags = (DnsStampFlags)(rawProps & 0x7UL);
            offset += 8;
        }

        string serverAddress = string.Empty;
        ImmutableArray<ImmutableArray<byte>> hashes = [];
        ImmutableArray<byte> publicKey = [];
        string providerName = string.Empty;
        string hostName = string.Empty;
        string path = string.Empty;
        ImmutableArray<string> bootstrapIps = [];

        switch (protocol)
        {
            case DnsStampProtocol.Plain:
            case DnsStampProtocol.AnonymizedDnsCryptRelay:
                if (!TryReadLengthPrefixedString(data, ref offset, out serverAddress, out error))
                {
                    return false;
                }

                break;

            case DnsStampProtocol.DnsCrypt:
                if (!TryReadLengthPrefixedString(data, ref offset, out serverAddress, out error)
                    || !TryReadLengthPrefixedBytes(data, ref offset, out byte[] pkBytes, out error)
                    || !TryReadLengthPrefixedString(data, ref offset, out providerName, out error))
                {
                    return false;
                }

                if (pkBytes.Length != PublicKeySizeBytes)
                {
                    error = string.Create(
                        CultureInfo.InvariantCulture,
                        $"DNSCrypt public key must be {PublicKeySizeBytes} bytes, found {pkBytes.Length}.");
                    return false;
                }

                publicKey = ImmutableArray.Create(pkBytes);
                break;

            case DnsStampProtocol.DoH:
            case DnsStampProtocol.ObliviousDoHRelay:
                if (!TryReadLengthPrefixedString(data, ref offset, out serverAddress, out error)
                    || !TryReadVlpHashes(data, ref offset, out hashes, out error)
                    || !TryReadLengthPrefixedString(data, ref offset, out hostName, out error)
                    || !TryReadLengthPrefixedString(data, ref offset, out path, out error))
                {
                    return false;
                }

                if (offset < data.Length && !TryReadVlpBootstrapIps(data, ref offset, out bootstrapIps, out error))
                {
                    return false;
                }

                break;

            case DnsStampProtocol.DoT:
            case DnsStampProtocol.DoQ:
                if (!TryReadLengthPrefixedString(data, ref offset, out serverAddress, out error)
                    || !TryReadVlpHashes(data, ref offset, out hashes, out error)
                    || !TryReadLengthPrefixedString(data, ref offset, out hostName, out error))
                {
                    return false;
                }

                if (offset < data.Length && !TryReadVlpBootstrapIps(data, ref offset, out bootstrapIps, out error))
                {
                    return false;
                }

                break;

            case DnsStampProtocol.ObliviousDoHTarget:
                if (!TryReadLengthPrefixedString(data, ref offset, out hostName, out error)
                    || !TryReadLengthPrefixedString(data, ref offset, out path, out error))
                {
                    return false;
                }

                break;
        }

        if (offset != data.Length)
        {
            error = string.Create(
                CultureInfo.InvariantCulture,
                $"DNS stamp contains {data.Length - offset} unexpected trailing byte(s).");
            return false;
        }

        result = new DnsStamp
        {
            Protocol = protocol,
            Properties = flags,
            RawProperties = rawProps,
            ServerAddress = serverAddress,
            Hashes = hashes,
            PublicKey = publicKey,
            ProviderName = providerName,
            HostName = hostName,
            Path = path,
            BootstrapIps = bootstrapIps
        };
        error = null;
        return true;
    }

    private static bool TryMapProtocol(byte protocolByte, out DnsStampProtocol protocol)
    {
        switch (protocolByte)
        {
            case 0x00:
                protocol = DnsStampProtocol.Plain;
                return true;
            case 0x01:
                protocol = DnsStampProtocol.DnsCrypt;
                return true;
            case 0x02:
                protocol = DnsStampProtocol.DoH;
                return true;
            case 0x03:
                protocol = DnsStampProtocol.DoT;
                return true;
            case 0x04:
                protocol = DnsStampProtocol.DoQ;
                return true;
            case 0x05:
                protocol = DnsStampProtocol.ObliviousDoHTarget;
                return true;
            case 0x81:
                protocol = DnsStampProtocol.AnonymizedDnsCryptRelay;
                return true;
            case 0x85:
                protocol = DnsStampProtocol.ObliviousDoHRelay;
                return true;
            default:
                protocol = default;
                return false;
        }
    }

    private static bool TryReadLengthPrefixedBytes(
        byte[] data,
        ref int offset,
        out byte[] value,
        [NotNullWhen(false)] out string? error)
    {
        if (offset >= data.Length)
        {
            value = [];
            error = "DNS stamp truncated while reading length prefix.";
            return false;
        }

        int len = data[offset++];
        if (data.Length - offset < len)
        {
            value = [];
            error = string.Create(
                CultureInfo.InvariantCulture,
                $"DNS stamp truncated: expected {len} byte(s), remaining {data.Length - offset}.");
            return false;
        }

        value = data.AsSpan(offset, len).ToArray();
        offset += len;
        error = null;
        return true;
    }

    private static bool TryReadLengthPrefixedString(
        byte[] data,
        ref int offset,
        out string value,
        [NotNullWhen(false)] out string? error)
    {
        if (!TryReadLengthPrefixedBytes(data, ref offset, out byte[] bytes, out error))
        {
            value = string.Empty;
            return false;
        }

        if (!Utf8.IsValid(bytes))
        {
            value = string.Empty;
            error = "DNS stamp contains invalid UTF-8 string bytes.";
            return false;
        }

        value = Encoding.UTF8.GetString(bytes);
        error = null;
        return true;
    }

    private static bool TryReadVlpHashes(
        byte[] data,
        ref int offset,
        out ImmutableArray<ImmutableArray<byte>> hashes,
        [NotNullWhen(false)] out string? error)
    {
        ImmutableArray<ImmutableArray<byte>>.Builder builder = ImmutableArray.CreateBuilder<ImmutableArray<byte>>();
        bool isFirst = true;

        while (true)
        {
            if (offset >= data.Length)
            {
                hashes = [];
                error = "DNS stamp truncated while reading VLP hash array.";
                return false;
            }

            byte lenByte = data[offset++];
            bool hasMore = (lenByte & 0x80) != 0;
            int len = lenByte & 0x7F;

            if (len == 0)
            {
                if (isFirst && !hasMore)
                {
                    hashes = [];
                    error = null;
                    return true;
                }

                hashes = [];
                error = "Invalid zero-length hash entry in VLP hash array.";
                return false;
            }

            if (len != HashSizeBytes)
            {
                hashes = [];
                error = string.Create(
                    CultureInfo.InvariantCulture,
                    $"Certificate hash entry must be {HashSizeBytes} bytes, found {len}.");
                return false;
            }

            if (data.Length - offset < len)
            {
                hashes = [];
                error = "DNS stamp truncated inside VLP hash entry.";
                return false;
            }

            builder.Add(ImmutableArray.Create(data, offset, len));
            offset += len;
            isFirst = false;

            if (!hasMore)
            {
                break;
            }
        }

        hashes = builder.ToImmutable();
        error = null;
        return true;
    }

    private static bool TryReadVlpBootstrapIps(
        byte[] data,
        ref int offset,
        out ImmutableArray<string> bootstrapIps,
        [NotNullWhen(false)] out string? error)
    {
        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        bool isFirst = true;

        while (true)
        {
            if (offset >= data.Length)
            {
                bootstrapIps = [];
                error = "DNS stamp truncated while reading VLP bootstrap IP array.";
                return false;
            }

            byte lenByte = data[offset++];
            bool hasMore = (lenByte & 0x80) != 0;
            int len = lenByte & 0x7F;

            if (len == 0)
            {
                if (isFirst && !hasMore)
                {
                    bootstrapIps = [];
                    error = null;
                    return true;
                }

                bootstrapIps = [];
                error = "Invalid empty bootstrap IP entry in VLP array.";
                return false;
            }

            if (data.Length - offset < len)
            {
                bootstrapIps = [];
                error = "DNS stamp truncated inside VLP bootstrap IP entry.";
                return false;
            }

            ReadOnlySpan<byte> slice = data.AsSpan(offset, len);
            if (!Utf8.IsValid(slice))
            {
                bootstrapIps = [];
                error = "Bootstrap IP entry contains invalid UTF-8 bytes.";
                return false;
            }

            string ipText = Encoding.UTF8.GetString(slice);
            if (!IsValidBootstrapIp(ipText))
            {
                bootstrapIps = [];
                error = $"Invalid bootstrap IP address '{ipText}'.";
                return false;
            }

            builder.Add(ipText);
            offset += len;
            isFirst = false;

            if (!hasMore)
            {
                break;
            }
        }

        bootstrapIps = builder.ToImmutable();
        error = null;
        return true;
    }

    private static bool IsValidBootstrapIp(string ipText)
    {
        string trimmed = ipText;
        if (trimmed.Length >= 2 && trimmed[0] == '[' && trimmed[^1] == ']')
        {
            trimmed = trimmed[1..^1];
            return IPAddress.TryParse(trimmed, out IPAddress? v6)
                && v6.AddressFamily == AddressFamily.InterNetworkV6;
        }

        if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
        {
            return false;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            return trimmed.AsSpan().Count('.') == 3;
        }

        return parsed.AddressFamily == AddressFamily.InterNetworkV6;
    }

    private static void WriteLengthPrefixedString(List<byte> buffer, string? value, string fieldName)
    {
        string text = value ?? string.Empty;
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        WriteLengthPrefixedBytes(buffer, bytes, fieldName);
    }

    private static void WriteLengthPrefixedBytes(List<byte> buffer, ReadOnlySpan<byte> bytes, string fieldName)
    {
        if (bytes.Length > MaxLengthPrefixedBytes)
        {
            throw new FormatException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Field '{fieldName}' exceeds maximum length of {MaxLengthPrefixedBytes} bytes."));
        }

        buffer.Add((byte)bytes.Length);
        AppendSpan(buffer, bytes);
    }

    private static void WriteVlpHashes(List<byte> buffer, ImmutableArray<ImmutableArray<byte>> hashes)
    {
        if (hashes.IsDefaultOrEmpty)
        {
            buffer.Add(0x00);
            return;
        }

        for (int i = 0; i < hashes.Length; i++)
        {
            ImmutableArray<byte> hash = hashes[i];
            if (hash.IsDefault || hash.Length != HashSizeBytes)
            {
                throw new FormatException(
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Certificate hash at index {i} must be exactly {HashSizeBytes} bytes."));
            }

            byte prefix = (byte)(hash.Length | (i < hashes.Length - 1 ? 0x80 : 0));
            buffer.Add(prefix);
            AppendSpan(buffer, hash.AsSpan());
        }
    }

    private static void WriteOptionalVlpBootstrapIps(List<byte> buffer, ImmutableArray<string> bootstrapIps)
    {
        if (bootstrapIps.IsDefaultOrEmpty)
        {
            return;
        }

        for (int i = 0; i < bootstrapIps.Length; i++)
        {
            string ip = bootstrapIps[i];
            if (string.IsNullOrWhiteSpace(ip) || !IsValidBootstrapIp(ip))
            {
                throw new FormatException(
                    string.Create(CultureInfo.InvariantCulture, $"Bootstrap IP at index {i} is invalid."));
            }

            byte[] bytes = Encoding.UTF8.GetBytes(ip);
            if (bytes.Length > MaxVlpItemBytes)
            {
                throw new FormatException(
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Bootstrap IP at index {i} exceeds {MaxVlpItemBytes} bytes."));
            }

            byte prefix = (byte)(bytes.Length | (i < bootstrapIps.Length - 1 ? 0x80 : 0));
            buffer.Add(prefix);
            AppendSpan(buffer, bytes);
        }
    }

    private static void AppendSpan(List<byte> buffer, ReadOnlySpan<byte> bytes)
    {
        for (int i = 0; i < bytes.Length; i++)
        {
            buffer.Add(bytes[i]);
        }
    }

    private static bool TryDecodeBase64Url(
        ReadOnlySpan<char> input,
        [NotNullWhen(true)] out byte[]? bytes,
        [NotNullWhen(false)] out string? error)
    {
        bytes = null;

        if (input.IsEmpty)
        {
            error = "DNS stamp base64url payload is empty.";
            return false;
        }

        int remainder = input.Length & 3;
        if (remainder == 1)
        {
            error = "DNS stamp base64url payload has invalid length.";
            return false;
        }

        int outputLen = (input.Length >> 2) * 3;
        if (remainder == 2)
        {
            outputLen += 1;
        }
        else if (remainder == 3)
        {
            outputLen += 2;
        }

        byte[] result = new byte[outputLen];
        int inIndex = 0;
        int outIndex = 0;

        while (inIndex + 4 <= input.Length)
        {
            if (!TryDecodeBase64UrlChar(input[inIndex], out int c0)
                || !TryDecodeBase64UrlChar(input[inIndex + 1], out int c1)
                || !TryDecodeBase64UrlChar(input[inIndex + 2], out int c2)
                || !TryDecodeBase64UrlChar(input[inIndex + 3], out int c3))
            {
                error = "DNS stamp contains invalid unpadded base64url character.";
                return false;
            }

            int combined = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
            result[outIndex++] = (byte)(combined >> 16);
            result[outIndex++] = (byte)(combined >> 8);
            result[outIndex++] = (byte)combined;
            inIndex += 4;
        }

        if (remainder == 2)
        {
            if (!TryDecodeBase64UrlChar(input[inIndex], out int c0)
                || !TryDecodeBase64UrlChar(input[inIndex + 1], out int c1))
            {
                error = "DNS stamp contains invalid unpadded base64url character.";
                return false;
            }

            result[outIndex] = (byte)((c0 << 2) | (c1 >> 4));
        }
        else if (remainder == 3)
        {
            if (!TryDecodeBase64UrlChar(input[inIndex], out int c0)
                || !TryDecodeBase64UrlChar(input[inIndex + 1], out int c1)
                || !TryDecodeBase64UrlChar(input[inIndex + 2], out int c2))
            {
                error = "DNS stamp contains invalid unpadded base64url character.";
                return false;
            }

            result[outIndex++] = (byte)((c0 << 2) | (c1 >> 4));
            result[outIndex] = (byte)(((c1 & 0x0F) << 4) | (c2 >> 2));
        }

        bytes = result;
        error = null;
        return true;
    }

    private static bool TryDecodeBase64UrlChar(char ch, out int value)
    {
        if (ch is >= 'A' and <= 'Z')
        {
            value = ch - 'A';
            return true;
        }

        if (ch is >= 'a' and <= 'z')
        {
            value = ch - 'a' + 26;
            return true;
        }

        if (ch is >= '0' and <= '9')
        {
            value = ch - '0' + 52;
            return true;
        }

        if (ch == '-')
        {
            value = 62;
            return true;
        }

        if (ch == '_')
        {
            value = 63;
            return true;
        }

        value = -1;
        return false;
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        int fullGroups = bytes.Length / 3;
        int rem = bytes.Length % 3;
        int charLen = fullGroups * 4 + (rem == 0 ? 0 : rem + 1);
        char[] chars = new char[charLen];

        int inIdx = 0;
        int outIdx = 0;

        for (int i = 0; i < fullGroups; i++)
        {
            int combined = (bytes[inIdx] << 16) | (bytes[inIdx + 1] << 8) | bytes[inIdx + 2];
            chars[outIdx++] = alphabet[(combined >> 18) & 0x3F];
            chars[outIdx++] = alphabet[(combined >> 12) & 0x3F];
            chars[outIdx++] = alphabet[(combined >> 6) & 0x3F];
            chars[outIdx++] = alphabet[combined & 0x3F];
            inIdx += 3;
        }

        if (rem == 1)
        {
            int b0 = bytes[inIdx];
            chars[outIdx++] = alphabet[(b0 >> 2) & 0x3F];
            chars[outIdx] = alphabet[(b0 & 0x03) << 4];
        }
        else if (rem == 2)
        {
            int b0 = bytes[inIdx];
            int b1 = bytes[inIdx + 1];
            chars[outIdx++] = alphabet[(b0 >> 2) & 0x3F];
            chars[outIdx++] = alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
            chars[outIdx] = alphabet[(b1 & 0x0F) << 2];
        }

        return new string(chars);
    }
}
