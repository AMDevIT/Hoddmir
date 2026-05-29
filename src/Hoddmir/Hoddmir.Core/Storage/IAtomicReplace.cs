namespace Hoddmir.Storage;

/// <summary>
/// Replaces the entire store content atomically (used by <c>CompactAsync</c>).
/// The delegate receives a fresh writable stream; after it completes the stream is
/// flushed and the store's backing storage is swapped with the new content.
/// </summary>
public interface IAtomicReplace
{
    Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default);
}
