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
    /// <summary>Appends only if the current length matches the expected offset.</summary>
    /// <exception cref="IOException">The expected offset differs from the current length. No bytes were appended.</exception>
    Task AppendAsync(ReadOnlyMemory<byte> data, long expectedOffset, CancellationToken ct = default);
    Task       FlushAsync(bool hard = false, CancellationToken ct = default);
}
