namespace Hoddmir.Storage.Providers;

/// <summary>
/// In-memory append-only store. Thread-safe via <see cref="SemaphoreSlim"/>.
/// Primarily intended for testing and in-process vaults.
/// </summary>
public sealed class MemoryAppendOnlyStoreProvider : IAppendOnlyStoreProvider, IAtomicReplace
{
    private byte[] _buf = Array.Empty<byte>();
    private long   _len;
    private readonly SemaphoreSlim _sem = new(1, 1);

    public async Task<long> GetLengthAsync(CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try   { return _len; }
        finally { _sem.Release(); }
    }

    public async Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int toRead = (int)Math.Min(buffer.Length, Math.Max(0L, _len - offset));
            if (toRead <= 0) return 0;
            new ReadOnlySpan<byte>(_buf, (int)offset, toRead).CopyTo(buffer.Span);
            return toRead;
        }
        finally { _sem.Release(); }
    }

    /// <inheritdoc />
    public async Task AppendAsync(ReadOnlyMemory<byte> data, long expectedOffset, CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            long offset = this._len;
            if (offset != expectedOffset)
                throw new IOException("The backend length changed before append.");
            int need = checked((int)(offset + data.Length));
            if (this._buf.Length < need)
                Array.Resize(ref this._buf, Math.Max(need, this._buf.Length == 0 ? 1024 : this._buf.Length * 2));
            data.Span.CopyTo(this._buf.AsSpan((int)offset, data.Length));
            this._len = need;
        }
        finally { _sem.Release(); }
    }

    public Task FlushAsync(bool hard = false, CancellationToken ct = default) => Task.CompletedTask;

    public async Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
    {
        using var ms = new MemoryStream(capacity: (int)_len);
        await buildNew(ms).ConfigureAwait(false);
        var newBytes = ms.ToArray();

        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _buf = newBytes;
            _len = newBytes.LongLength;
        }
        finally { _sem.Release(); }
    }
}
