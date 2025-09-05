namespace Hoddmir.Storage.Providers
{
    public sealed class MemoryAppendOnlyStoreProvider 
        : IAppendOnlyStoreProvider, IAtomicReplace
    {
        private byte[] _buf = Array.Empty<byte>();
        private readonly object _lock = new();

        public Task<long> GetLengthAsync(CancellationToken ct = default)
        { 
            lock (_lock) 
                return Task.FromResult((long)_buf.Length); 
        }

        public Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default)
        {
            lock (_lock)
            {
                if (offset >= _buf.Length) return Task.FromResult(0);
                int toCopy = (int)Math.Min(buffer.Length, _buf.Length - offset);
                _buf.AsSpan((int)offset, toCopy).CopyTo(buffer.Span);
                return Task.FromResult(toCopy);
            }
        }

        public Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            lock (_lock)
            {
                var oldLen = _buf.Length;
                Array.Resize(ref _buf, oldLen + data.Length);
                data.Span.CopyTo(_buf.AsSpan(oldLen));
                return Task.CompletedTask;
            }
        }

        public Task FlushAsync(bool hard = false, CancellationToken ct = default) => Task.CompletedTask;

        public Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
        {
            using var ms = new MemoryStream();
            buildNew(ms);
            _buf = ms.ToArray();
            return Task.CompletedTask;
        }
    }
}
