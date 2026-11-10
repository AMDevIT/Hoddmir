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
    private readonly FileStream writerLock;
    // Not readonly: swapped after ReplaceWithAsync.
    private FileStream fs;
    // SemaphoreSlim(1,1) gives async-safe mutual exclusion.
    private readonly SemaphoreSlim semaphore = new(1, 1);

    #endregion

    #region .ctor

    /// <summary>Opens an existing vault file or creates an empty file with <see cref="FileMode.CreateNew"/>.</summary>
    public FileAppendOnlyStoreProvider(string path, FileMode mode = FileMode.Open)
    {
        if (mode is not (FileMode.Open or FileMode.CreateNew))
            throw new ArgumentOutOfRangeException(nameof(mode));

        this.path = Path.GetFullPath(path);
        if (mode == FileMode.CreateNew)
            Directory.CreateDirectory(Path.GetDirectoryName(this.path)!);
        // The lock file must keep the same identity across vault replacements and reopenings.
        this.writerLock = new(this.path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            this.fs = OpenStream(this.path, mode);
        }
        catch
        {
            this.writerLock.Dispose();
            throw;
        }
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

    /// <inheritdoc />
    public async Task AppendAsync(ReadOnlyMemory<byte> data, long expectedOffset, CancellationToken ct = default)
    {
        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            long offset = this.fs.Length;
            if (offset != expectedOffset)
                throw new IOException("The backend length changed before append.");
            this.fs.Position = offset;
            await this.fs.WriteAsync(data, ct).ConfigureAwait(false);
        }
        finally { semaphore.Release(); }
    }

    public async Task FlushAsync(bool hard = false, CancellationToken ct = default)
    {
        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (hard)
                this.fs.Flush(flushToDisk: true);
            else
                await this.fs.FlushAsync(ct).ConfigureAwait(false);
        }
        finally { semaphore.Release(); }
    }

    public async Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
    {
        string temp = this.path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            FileStreamOptions options = new()
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = File.GetUnixFileMode(this.path);

            await using (FileStream output = new(temp, options))
            {
                await buildNew(output).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                output.Flush(flushToDisk: true);
            }

            await this.semaphore.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await this.fs.DisposeAsync().ConfigureAwait(false);
                try
                {
                    File.Replace(temp, this.path, null, ignoreMetadataErrors: false);
                }
                finally
                {
                    this.fs = OpenStream(this.path, FileMode.Open);
                }
            }
            finally { this.semaphore.Release(); }
        }
        finally { TryDelete(temp); }
    }

    private static FileStream OpenStream(string path, FileMode mode) =>
        new(path, mode, FileAccess.ReadWrite, FileShare.None, 1,
            FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.RandomAccess);

    private static void TryDelete(string p) 
    { 
        try 
        { 
            File.Delete(p); 
        } 
        catch (IOException)
        { 
            // Cleanup must not hide the original rewrite failure.
        }
        catch (UnauthorizedAccessException)
        {
            // Cleanup must not hide the original rewrite failure.
        } 
    }

    public async ValueTask DisposeAsync()
    {
        await this.semaphore.WaitAsync().ConfigureAwait(false);

        using (this.semaphore)
        {
            try
            {
                // Keep the writer lock until the vault stream has been closed, even on failure.
                await using (this.writerLock.ConfigureAwait(false))
                {
                    await this.fs.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                this.semaphore.Release();
            }
        }
    }

    #endregion
}
