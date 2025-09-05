namespace Hoddmir.Core.Storage
{
    public interface IAtomicReplace
    {
        Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default);
    }
}
