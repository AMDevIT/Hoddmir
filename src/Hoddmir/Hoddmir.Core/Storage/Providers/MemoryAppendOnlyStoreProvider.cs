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

    public async Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int need = (int)(_len + data.Length);
            if (_buf.Length < need)
                Array.Resize(ref _buf, Math.Max(need, _buf.Length == 0 ? 1024 : _buf.Length * 2));
            data.Span.CopyTo(new Span<byte>(_buf, (int)_len, data.Length));
            _len += data.Length;
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
