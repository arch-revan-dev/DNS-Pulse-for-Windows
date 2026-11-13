using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DnsPulse.Core.Wire;

/// <summary>
/// Well-known RFC 9460 SVCB/HTTPS service parameter keys.
/// </summary>
public enum SvcParamKey
{
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    Ipv4Hint = 4,
    Ech = 5,
    Ipv6Hint = 6
}

/// <summary>
/// Represents an RFC 9460 SVCB/HTTPS <c>SvcParam</c> entry with typed helpers for
/// <c>mandatory</c>, <c>alpn</c>, <c>no-default-alpn</c>, <c>port</c>, <c>ipv4hint</c>, <c>ech</c>, and <c>ipv6hint</c>.
/// </summary>
public sealed record SvcParam
{
    public ushort Key { get; init; }

    public ReadOnlyMemory<byte> Value { get; init; }

    public SvcParamKey KnownKey => (SvcParamKey)Key;

    public static SvcParam CreateMandatory(IEnumerable<ushort> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        List<ushort> distinct = [.. keys.Distinct()];
        if (distinct.Count == 0)
        {
            throw new ArgumentException("Mandatory SvcParam requires at least one key.", nameof(keys));
        }

        distinct.Sort();
        byte[] buffer = new byte[distinct.Count * 2];
        for (int index = 0; index < distinct.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(index * 2, 2), distinct[index]);
        }

        return new SvcParam
        {
            Key = (ushort)SvcParamKey.Mandatory,
            Value = buffer
        };
    }

    public static SvcParam CreateAlpn(IEnumerable<string> alpnIds)
    {
        ArgumentNullException.ThrowIfNull(alpnIds);

        List<byte[]> encoded = [];
        int totalLength = 0;
        foreach (string id in alpnIds)
        {
            if (string.IsNullOrEmpty(id))
            {
                throw new ArgumentException("ALPN identifier cannot be null or empty.", nameof(alpnIds));
            }

            byte[] utf8 = Encoding.UTF8.GetBytes(id);
            if (utf8.Length is < 1 or > 255)
            {
                throw new ArgumentException("ALPN identifier wire length must be between 1 and 255 bytes.", nameof(alpnIds));
            }

            encoded.Add(utf8);
            totalLength += 1 + utf8.Length;
        }

        if (encoded.Count == 0)
        {
            throw new ArgumentException("ALPN SvcParam requires at least one protocol identifier.", nameof(alpnIds));
        }

        byte[] buffer = new byte[totalLength];
        int offset = 0;
        foreach (byte[] item in encoded)
        {
            buffer[offset++] = (byte)item.Length;
            item.CopyTo(buffer, offset);
            offset += item.Length;
        }

        return new SvcParam
        {
            Key = (ushort)SvcParamKey.Alpn,
            Value = buffer
        };
    }

    public static SvcParam CreateNoDefaultAlpn()
    {
        return new SvcParam
        {
            Key = (ushort)SvcParamKey.NoDefaultAlpn,
            Value = ReadOnlyMemory<byte>.Empty
        };
    }

    public static SvcParam CreatePort(ushort port)
    {
        byte[] buffer = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, port);
        return new SvcParam
        {
            Key = (ushort)SvcParamKey.Port,
            Value = buffer
        };
    }

    public static SvcParam CreateIpv4Hint(IEnumerable<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        List<IPAddress> list = [.. addresses];
        if (list.Count == 0)
        {
            throw new ArgumentException("ipv4hint requires at least one IPv4 address.", nameof(addresses));
        }

        byte[] buffer = new byte[list.Count * 4];
        for (int index = 0; index < list.Count; index++)
        {
            IPAddress address = list[index];
            if (address.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("All addresses in ipv4hint must be IPv4.", nameof(addresses));
            }

            if (!address.TryWriteBytes(buffer.AsSpan(index * 4, 4), out _))
            {
                throw new FormatException("Failed to serialize IPv4 hint address.");
            }
        }

        return new SvcParam
        {
            Key = (ushort)SvcParamKey.Ipv4Hint,
            Value = buffer
        };
    }

    public static SvcParam CreateEch(ReadOnlyMemory<byte> echConfigList)
    {
        if (echConfigList.IsEmpty)
        {
            throw new ArgumentException("ECH config list cannot be empty.", nameof(echConfigList));
        }

        return new SvcParam
        {
            Key = (ushort)SvcParamKey.Ech,
            Value = echConfigList.ToArray()
        };
    }

    public static SvcParam CreateIpv6Hint(IEnumerable<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        List<IPAddress> list = [.. addresses];
        if (list.Count == 0)
        {
            throw new ArgumentException("ipv6hint requires at least one IPv6 address.", nameof(addresses));
        }

        byte[] buffer = new byte[list.Count * 16];
        for (int index = 0; index < list.Count; index++)
        {
            IPAddress address = list[index];
            if (address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException("All addresses in ipv6hint must be IPv6.", nameof(addresses));
            }

            if (!address.TryWriteBytes(buffer.AsSpan(index * 16, 16), out _))
            {
                throw new FormatException("Failed to serialize IPv6 hint address.");
            }
        }

        return new SvcParam
        {
            Key = (ushort)SvcParamKey.Ipv6Hint,
            Value = buffer
        };
    }

    public static SvcParam CreateRaw(ushort key, ReadOnlyMemory<byte> value)
    {
        return new SvcParam
        {
            Key = key,
            Value = value.ToArray()
        };
    }

    public IReadOnlyList<ushort> ParseMandatoryKeys()
    {
        ReadOnlySpan<byte> span = Value.Span;
        if (Key != (ushort)SvcParamKey.Mandatory || span.Length < 2 || (span.Length % 2) != 0)
        {
            throw new FormatException("Invalid mandatory SvcParam value.");
        }

        ushort[] result = new ushort[span.Length / 2];
        for (int index = 0; index < result.Length; index++)
        {
            result[index] = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(index * 2, 2));
        }

        return result;
    }

    public IReadOnlyList<string> ParseAlpnIds()
    {
        if (Key != (ushort)SvcParamKey.Alpn)
        {
            throw new FormatException("SvcParam is not an ALPN parameter.");
        }

        ReadOnlySpan<byte> span = Value.Span;
        if (span.Length == 0)
        {
            throw new FormatException("ALPN SvcParam value cannot be empty.");
        }

        List<string> ids = [];
        int offset = 0;
        while (offset < span.Length)
        {
            byte len = span[offset++];
            if (len == 0 || offset + len > span.Length)
            {
                throw new FormatException("Malformed ALPN length-prefixed entry.");
            }

            ids.Add(Encoding.UTF8.GetString(span.Slice(offset, len)));
            offset += len;
        }

        return ids;
    }

    public ushort ParsePort()
    {
        ReadOnlySpan<byte> span = Value.Span;
        if (Key != (ushort)SvcParamKey.Port || span.Length != 2)
        {
            throw new FormatException("Invalid port SvcParam value.");
        }

        return BinaryPrimitives.ReadUInt16BigEndian(span);
    }

    public IReadOnlyList<IPAddress> ParseIpv4Hints()
    {
        ReadOnlySpan<byte> span = Value.Span;
        if (Key != (ushort)SvcParamKey.Ipv4Hint || span.Length < 4 || (span.Length % 4) != 0)
        {
            throw new FormatException("Invalid ipv4hint SvcParam value.");
        }

        IPAddress[] addresses = new IPAddress[span.Length / 4];
        for (int index = 0; index < addresses.Length; index++)
        {
            addresses[index] = new IPAddress(span.Slice(index * 4, 4));
        }

        return addresses;
    }

    public IReadOnlyList<IPAddress> ParseIpv6Hints()
    {
        ReadOnlySpan<byte> span = Value.Span;
        if (Key != (ushort)SvcParamKey.Ipv6Hint || span.Length < 16 || (span.Length % 16) != 0)
        {
            throw new FormatException("Invalid ipv6hint SvcParam value.");
        }

        IPAddress[] addresses = new IPAddress[span.Length / 16];
        for (int index = 0; index < addresses.Length; index++)
        {
            addresses[index] = new IPAddress(span.Slice(index * 16, 16));
        }

        return addresses;
    }

    internal static bool TryParseList(ReadOnlySpan<byte> data, out List<SvcParam> parameters, out string? error)
    {
        parameters = [];
        error = null;

        int offset = 0;
        int previousKey = -1;
        while (offset < data.Length)
        {
            if (offset + 4 > data.Length)
            {
                error = "Truncated SvcParam header.";
                return false;
            }

            ushort key = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
            ushort len = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset + 2, 2));
            offset += 4;

            if (key <= previousKey)
            {
                error = string.Create(CultureInfo.InvariantCulture, $"SvcParam keys must be strictly increasing (encountered key {key}).");
                return false;
            }

            if (offset + len > data.Length)
            {
                error = "Truncated SvcParam value.";
                return false;
            }

            ReadOnlySpan<byte> valSpan = data.Slice(offset, len);
            if (!ValidateKnownSvcParam(key, valSpan, out error))
            {
                return false;
            }

            parameters.Add(new SvcParam
            {
                Key = key,
                Value = valSpan.ToArray()
            });

            previousKey = key;
            offset += len;
        }

        return true;
    }

    internal static bool TryWriteList(IReadOnlyList<SvcParam> parameters, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (parameters.Count == 0)
        {
            return true;
        }

        List<SvcParam> sorted = [.. parameters];
        sorted.Sort((left, right) => left.Key.CompareTo(right.Key));

        int offset = 0;
        int previousKey = -1;
        foreach (SvcParam param in sorted)
        {
            if (param.Key == previousKey)
            {
                throw new FormatException(string.Create(CultureInfo.InvariantCulture, $"Duplicate SvcParam key {param.Key} is invalid per RFC 9460."));
            }

            int required = 4 + param.Value.Length;
            if (offset + required > destination.Length)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), param.Key);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset + 2, 2), (ushort)param.Value.Length);
            param.Value.Span.CopyTo(destination.Slice(offset + 4, param.Value.Length));
            offset += required;
            previousKey = param.Key;
        }

        bytesWritten = offset;
        return true;
    }

    internal static void WriteList(IReadOnlyList<SvcParam> parameters, IBufferWriter<byte> writer)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(writer);

        if (parameters.Count == 0)
        {
            return;
        }

        int totalSize = 0;
        foreach (SvcParam param in parameters)
        {
            totalSize += 4 + param.Value.Length;
        }

        Span<byte> span = writer.GetSpan(totalSize);
        if (!TryWriteList(parameters, span, out int written))
        {
            throw new InvalidOperationException("Failed to serialize SvcParam list into buffer writer.");
        }

        writer.Advance(written);
    }

    private static bool ValidateKnownSvcParam(ushort key, ReadOnlySpan<byte> valSpan, out string? error)
    {
        error = null;
        switch ((SvcParamKey)key)
        {
            case SvcParamKey.Mandatory:
                if (valSpan.Length < 2 || (valSpan.Length % 2) != 0)
                {
                    error = "Invalid mandatory SvcParam length.";
                    return false;
                }
                break;

            case SvcParamKey.Alpn:
                if (valSpan.Length == 0)
                {
                    error = "ALPN SvcParam cannot be empty.";
                    return false;
                }

                int offset = 0;
                while (offset < valSpan.Length)
                {
                    byte len = valSpan[offset++];
                    if (len == 0 || offset + len > valSpan.Length)
                    {
                        error = "Truncated ALPN identifier inside SvcParam.";
                        return false;
                    }

                    offset += len;
                }
                break;

            case SvcParamKey.NoDefaultAlpn:
                if (valSpan.Length != 0)
                {
                    error = "no-default-alpn SvcParam must have zero-length value.";
                    return false;
                }
                break;

            case SvcParamKey.Port:
                if (valSpan.Length != 2)
                {
                    error = "port SvcParam must be 2 bytes.";
                    return false;
                }
                break;

            case SvcParamKey.Ipv4Hint:
                if (valSpan.Length < 4 || (valSpan.Length % 4) != 0)
                {
                    error = "ipv4hint SvcParam length must be a non-zero multiple of 4.";
                    return false;
                }
                break;

            case SvcParamKey.Ech:
                if (valSpan.Length == 0)
                {
                    error = "ech SvcParam cannot be empty.";
                    return false;
                }
                break;

            case SvcParamKey.Ipv6Hint:
                if (valSpan.Length < 16 || (valSpan.Length % 16) != 0)
                {
                    error = "ipv6hint SvcParam length must be a non-zero multiple of 16.";
                    return false;
                }
                break;

            default:
                break;
        }

        return true;
    }
}
