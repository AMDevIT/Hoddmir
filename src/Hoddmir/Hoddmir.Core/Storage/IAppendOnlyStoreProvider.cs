namespace Hoddmir.Core.Storage
{
    public interface IAppendOnlyStoreProvider
    {
        Task<long> GetLengthAsync(CancellationToken ct = default);
        Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default);
        Task AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
        Task FlushAsync(bool hard = false, CancellationToken ct = default);
    }
}
