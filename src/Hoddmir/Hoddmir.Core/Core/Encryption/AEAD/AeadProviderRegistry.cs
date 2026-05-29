namespace Hoddmir.Encryption;

/// <summary>
/// Global registry of fallback <see cref="IAEADProvider"/> factory delegates, keyed by
/// <see cref="AeadAlgorithmId"/>.
/// <para>
/// This is the extension point that lets optional packages (e.g. Hoddmir.BouncyCastle)
/// register alternative backends at module-init time. When a built-in provider cannot run
/// on the current runtime (e.g. <see cref="AeadAlgorithmId.AesGcm"/> on .NET 8), the
/// registry is consulted before throwing <see cref="PlatformNotSupportedException"/>.
/// </para>
/// <para>
/// Registration is intentionally write-once per key: a second registration for the same
/// <see cref="AeadAlgorithmId"/> is silently ignored so that app code cannot accidentally
/// shadow a library registration.
/// </para>
/// </summary>
public static class AeadProviderRegistry
{
    private static readonly Dictionary<AeadAlgorithmId, Func<IAEADProvider>> _factories = new();
    private static readonly object _lock = new();

    /// <summary>
    /// Registers a fallback factory for <paramref name="id"/>.
    /// Ignored if a factory for that id is already registered.
    /// </summary>
    public static void Register(AeadAlgorithmId id, Func<IAEADProvider> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        lock (_lock)
        {
            _factories.TryAdd(id, factory);
        }
    }

    /// <summary>
    /// Returns a fallback provider for <paramref name="id"/>, or <c>null</c> if none was registered.
    /// </summary>
    public static IAEADProvider? TryCreate(AeadAlgorithmId id)
    {
        lock (_lock)
        {
            return _factories.TryGetValue(id, out var factory) ? factory() : null;
        }
    }

    /// <summary>Returns whether a fallback factory is registered for <paramref name="id"/>.</summary>
    public static bool IsRegistered(AeadAlgorithmId id)
    {
        lock (_lock) { return _factories.ContainsKey(id); }
    }
}
