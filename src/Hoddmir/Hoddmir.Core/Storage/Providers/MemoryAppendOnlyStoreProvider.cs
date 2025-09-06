namespace Hoddmir.Storage.Providers
{
    public sealed class MemoryAppendOnlyStoreProvider 
        : IAppendOnlyStoreProvider, IAtomicReplace
    {
        private byte[] _buf = Array.Empty<byte>();
        private long _len;

        public Task<long> GetLengthAsync(CancellationToken ct = default)
            => Task.FromResult(_len);

        public Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default)
        {
            int toRead = (int)Math.Min(buffer.Length, Math.Max(0, _len - offset));
            if (toRead <= 0) return Task.FromResult(0);
            new ReadOnlySpan<byte>(_buf, (int)offset, toRead).CopyTo(buffer.Span);
            return Task.FromResult(toRead);
        }

        public Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            var need = (int)(_len + data.Length);
            if (_buf.Length < need)
                Array.Resize(ref _buf, Math.Max(need, _buf.Length == 0 ? 1024 : _buf.Length * 2));

            data.Span.CopyTo(new Span<byte>(_buf, (int)_len, data.Length));
            _len += data.Length;
            return Task.CompletedTask;
        }

        public Task FlushAsync(bool hard = false, CancellationToken ct = default)
            => Task.CompletedTask;

        // *** punto critico ***
        public async Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default)
        {
            // Costruisci il nuovo contenuto in un MemoryStream temporaneo
            using var ms = new MemoryStream(capacity: _buf.Length);
            await buildNew(ms).ConfigureAwait(false);
            var newBytes = ms.ToArray();

            // SOSTITUISCI atomico: rimpiazza buffer e lunghezza
            _buf = newBytes;
            _len = newBytes.LongLength;
        }
    }
}
