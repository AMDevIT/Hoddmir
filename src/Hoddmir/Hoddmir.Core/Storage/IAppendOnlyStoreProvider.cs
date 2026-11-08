namespace Hoddmir.Storage;

/// <summary>
/// Abstraction over an append-only byte store with random-read support.
/// Implementations must be thread-safe and grant the attached store exclusive write access
/// to the underlying data for its lifetime, including during replacement.
/// </summary>
public interface IAppendOnlyStoreProvider
{
    Task<long> GetLengthAsync(CancellationToken ct = default);
    Task<int>  ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default);
    /// <summary>Appends the data and returns its starting offset.</summary>
    Task<long> AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
    Task       FlushAsync(bool hard = false, CancellationToken ct = default);
}
