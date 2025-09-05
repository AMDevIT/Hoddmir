namespace Hoddmir.Storage.Providers
{
    public class FileAppendOnlyStoreProvider 
        : IAppendOnlyStoreProvider, IAtomicReplace, IAsyncDisposable
    {
        private readonly string _path;
        private readonly FileStream _fs;
        private readonly object _lock = new();

        public FileAppendOnlyStoreProvider(string path)
        {
            _path = path;
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            _fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.RandomAccess);
            _fs.Position = _fs.Length; // append
        }

        public Task<long> GetLengthAsync(CancellationToken ct = default)
            => Task.FromResult(_fs.Length);

        public Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default)
        {
            lock (_lock)
            {
                _fs.Position = offset;
                return _fs.ReadAsync(buffer, ct).AsTask();
            }
        }

        public Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            lock (_lock)
            {
                return _fs.WriteAsync(data, ct).AsTask();
            }
        }

        public Task FlushAsync(bool hard, CancellationToken ct = default)
            => _fs.FlushAsync(ct);

        public async Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
        {
            var temp = _path + ".tmp";
            await using (var outFs = new FileStream(temp, FileMode.Create, FileAccess.ReadWrite, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.SequentialScan))
            {
                await buildNew(outFs).ConfigureAwait(false);
                await outFs.FlushAsync(ct).ConfigureAwait(false);
            }

            await _fs.FlushAsync(ct);
            await _fs.DisposeAsync();

            // sostituzione atomica su NTFS
            File.Replace(temp, _path, _path + ".bak", ignoreMetadataErrors: true);
            TryDelete(_path + ".bak");

            // riapri per proseguire
            var reopened = new FileStream(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough | FileOptions.RandomAccess);
            typeof(FileAppendOnlyStoreProvider)
                .GetField("_fs", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                .SetValue(this, reopened);
            reopened.Position = reopened.Length;
        }

        static void TryDelete(string p) { try { File.Delete(p); } catch { } }

        public ValueTask DisposeAsync() => _fs.DisposeAsync();
    }
}
