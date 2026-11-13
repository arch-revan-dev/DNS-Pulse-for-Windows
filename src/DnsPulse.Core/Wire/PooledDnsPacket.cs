using System.Buffers;

namespace DnsPulse.Core.Wire;

/// <summary>
/// Owns a rented <see cref="ArrayPool{T}"/> buffer containing a serialized DNS packet.
/// </summary>
public sealed class PooledDnsPacket : IDisposable
{
    private byte[]? _buffer;
    private readonly int _length;

    internal PooledDnsPacket(byte[] buffer, int length)
    {
        _buffer = buffer;
        _length = length;
    }

    public ReadOnlyMemory<byte> Memory
    {
        get
        {
            ObjectDisposedException.ThrowIf(_buffer is null, this);
            return _buffer.AsMemory(0, _length);
        }
    }

    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_buffer is null, this);
            return _buffer.AsSpan(0, _length);
        }
    }

    public int Length => _length;

    public void Dispose()
    {
        byte[]? rented = Interlocked.Exchange(ref _buffer, null);
        if (rented is not null)
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
