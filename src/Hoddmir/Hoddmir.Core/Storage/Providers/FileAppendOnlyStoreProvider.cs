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
    #region Fields

    private readonly string path;
    // Not readonly: swapped after ReplaceWithAsync.
    private FileStream fs;
    // SemaphoreSlim(1,1) gives async-safe mutual exclusion.
    private readonly SemaphoreSlim semaphore = new(1, 1);

    #endregion

    #region .ctor

    public FileAppendOnlyStoreProvider(string path)
    {
        this.path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        fs = OpenStream(path, FileMode.OpenOrCreate);
        fs.Position = fs.Length; // start in append position
    }

    #endregion

    #region Methods

    public async Task<long> GetLengthAsync(CancellationToken ct = default)
    {
        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try   
        { 
            return fs.Length; 
        }
        finally 
        { 
            semaphore.Release(); 
        }
    }

    public async Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default)
    {
        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            fs.Position = offset;
            return await fs.ReadAsync(buffer, ct).ConfigureAwait(false);
        }
        finally { semaphore.Release(); }
    }

    public async Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try   { await fs.WriteAsync(data, ct).ConfigureAwait(false); }
        finally { semaphore.Release(); }
    }

    public async Task FlushAsync(bool hard = false, CancellationToken ct = default)
    {
        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try   { await fs.FlushAsync(ct).ConfigureAwait(false); }
        finally { semaphore.Release(); }
    }

    public async Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
    {
        string temp = path + ".tmp";

        await using (FileStream outFs = new (temp, 
                                             FileMode.Create, 
                                             FileAccess.ReadWrite,
                                             FileShare.None, 
                                             4096,
                                             FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.SequentialScan))
        {
            await buildNew(outFs).ConfigureAwait(false);
            await outFs.FlushAsync(ct).ConfigureAwait(false);
        }

        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await fs.FlushAsync(ct).ConfigureAwait(false);
            await fs.DisposeAsync().ConfigureAwait(false);

            // Atomic rename on NTFS and POSIX
            File.Replace(temp, path, path + ".bak", ignoreMetadataErrors: true);
            TryDelete(path + ".bak");

            fs = OpenStream(path, FileMode.Open);
            fs.Position = fs.Length;
        }
        finally { semaphore.Release(); }
    }

    private static FileStream OpenStream(string path, FileMode mode) =>
        new(path, mode, FileAccess.ReadWrite, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.RandomAccess);

    private static void TryDelete(string p) 
    { 
        try 
        { 
            File.Delete(p); 
        } 
        catch
        { 
            /* best effort */ 
        } 
    }

    public async ValueTask DisposeAsync()
    {
        await semaphore.WaitAsync().ConfigureAwait(false);

        try   
        { 
            await fs.DisposeAsync().ConfigureAwait(false); 
        }
        finally 
        { 
            semaphore.Release(); 
            semaphore.Dispose(); 
        }
    }

    #endregion
}
