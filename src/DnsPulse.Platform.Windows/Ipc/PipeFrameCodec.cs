using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;

namespace DnsPulse.Platform.Windows.Ipc;

/// <summary>
/// Shared 4-byte little-endian length-prefixed UTF-8 JSON framing codec for Named Pipe IPC.
/// </summary>
internal static class PipeFrameCodec
{
    public const int MaxMessageBytes = 1024 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public static byte[] Serialize<T>(T value)
    {
        return JsonSerializer.SerializeToUtf8Bytes(value, SerializerOptions);
    }

    public static T? Deserialize<T>(ReadOnlySpan<byte> utf8Json)
    {
        return JsonSerializer.Deserialize<T>(utf8Json, SerializerOptions);
    }

    public static async Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        int maxMessageBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (payload.IsEmpty || payload.Length > maxMessageBytes)
        {
            throw new InvalidDataException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"IPC frame length {payload.Length} bytes is outside valid range [1, {maxMessageBytes}]."));
        }

        int totalBytes = 4 + payload.Length;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(totalBytes);
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(0, 4), payload.Length);
            payload.Span.CopyTo(buffer.AsSpan(4));
            await stream.WriteAsync(buffer.AsMemory(0, totalBytes), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task<byte[]?> ReadFrameAsync(
        Stream stream,
        int maxMessageBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] header = new byte[4];
        int headerRead = 0;
        while (headerRead < header.Length)
        {
            int bytesRead = await stream.ReadAsync(header.AsMemory(headerRead), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                if (headerRead == 0)
                {
                    return null;
                }

                throw new EndOfStreamException("Unexpected end of stream while reading IPC frame length header.");
            }

            headerRead += bytesRead;
        }

        int payloadLength = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (payloadLength <= 0 || payloadLength > maxMessageBytes)
        {
            throw new InvalidDataException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"IPC frame length {payloadLength} bytes exceeds allowed range [1, {maxMessageBytes}]."));
        }

        byte[] payload = new byte[payloadLength];
        int bodyRead = 0;
        while (bodyRead < payloadLength)
        {
            int bytesRead = await stream.ReadAsync(payload.AsMemory(bodyRead), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while reading IPC frame payload.");
            }

            bodyRead += bytesRead;
        }

        return payload;
    }
}
