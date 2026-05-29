using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Hoddmir.Memory;

/// <summary>
/// Holds a fixed-size byte buffer in a GC-pinned managed array so it is never
/// moved or copied by the runtime, and is zeroed on disposal.
/// Prefer this over stackalloc for buffers that must outlive a single method frame
/// or be held by a long-lived object (e.g. DEK, nonce prefix).
/// </summary>
public sealed class SensitiveBytes : IDisposable
{
    // GC.AllocateArray with pinned:true allocates in the Pinned Object Heap (POH).
    // The array stays at a fixed address for its entire lifetime — no Marshal, no unsafe.
    private byte[]? _buffer;
    private bool _disposed;

    public int Length { get; }

    public SensitiveBytes(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        Length  = length;
        _buffer = GC.AllocateArray<byte>(length, pinned: true);
    }

    /// <summary>Returns a span over the pinned buffer. Valid only while this instance is alive.</summary>
    public Span<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _buffer.AsSpan();
    }

    /// <summary>Copies the buffer contents to a new heap array. The copy is NOT zeroed on GC — caller is responsible.</summary>
    public byte[] ToManagedCopy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var copy = new byte[Length];
        _buffer.AsSpan().CopyTo(copy);
        return copy;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_buffer is not null)
        {
            CryptographicOperations.ZeroMemory(_buffer.AsSpan());
            _buffer = null;
        }
    }
}
