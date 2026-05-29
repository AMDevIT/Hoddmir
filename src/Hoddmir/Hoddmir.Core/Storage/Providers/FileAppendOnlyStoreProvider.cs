namespace Hoddmir.Storage.Providers;

/// <summary>
/// File-backed append-only store. Supports atomic compaction via <see cref="ReplaceWithAsync"/>.
/// All operations are serialised through a <see cref="SemaphoreSlim"/> so that
/// async mutual exclusion is correct (unlike a synchronous <c>lock</c>, which would
/// release before the async I/O completes).
/// </summary>
public sealed class FileAppendOnlyStoreProvider
    : IAppendOnlyStoreProvider, IAtomicReplace, IAsyncDisposable
{
    private readonly string _path;
    // Not readonly: swapped after ReplaceWithAsync.
    private FileStream _fs;
    // SemaphoreSlim(1,1) gives async-safe mutual exclusion.
    private readonly SemaphoreSlim _sem = new(1, 1);

    public FileAppendOnlyStoreProvider(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _fs = OpenStream(path, FileMode.OpenOrCreate);
        _fs.Position = _fs.Length; // start in append position
    }

    public async Task<long> GetLengthAsync(CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try   { return _fs.Length; }
        finally { _sem.Release(); }
    }

    public async Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _fs.Position = offset;
            return await _fs.ReadAsync(buffer, ct).ConfigureAwait(false);
        }
        finally { _sem.Release(); }
    }

    public async Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try   { await _fs.WriteAsync(data, ct).ConfigureAwait(false); }
        finally { _sem.Release(); }
    }

    public async Task FlushAsync(bool hard = false, CancellationToken ct = default)
    {
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try   { await _fs.FlushAsync(ct).ConfigureAwait(false); }
        finally { _sem.Release(); }
    }

    public async Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
    {
        string temp = _path + ".tmp";

        await using (var outFs = new FileStream(temp, FileMode.Create, FileAccess.ReadWrite,
                         FileShare.None, 4096,
                         FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.SequentialScan))
        {
            await buildNew(outFs).ConfigureAwait(false);
            await outFs.FlushAsync(ct).ConfigureAwait(false);
        }

        await _sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _fs.FlushAsync(ct).ConfigureAwait(false);
            await _fs.DisposeAsync().ConfigureAwait(false);

            // Atomic rename on NTFS and POSIX
            File.Replace(temp, _path, _path + ".bak", ignoreMetadataErrors: true);
            TryDelete(_path + ".bak");

            _fs = OpenStream(_path, FileMode.Open);
            _fs.Position = _fs.Length;
        }
        finally { _sem.Release(); }
    }

    private static FileStream OpenStream(string path, FileMode mode) =>
        new(path, mode, FileAccess.ReadWrite, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.RandomAccess);

    private static void TryDelete(string p) { try { File.Delete(p); } catch { /* best effort */ } }

    public async ValueTask DisposeAsync()
    {
        await _sem.WaitAsync().ConfigureAwait(false);
        try   { await _fs.DisposeAsync().ConfigureAwait(false); }
        finally { _sem.Release(); _sem.Dispose(); }
    }
}
