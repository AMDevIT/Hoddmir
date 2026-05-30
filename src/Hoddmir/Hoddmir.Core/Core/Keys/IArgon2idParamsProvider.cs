namespace Hoddmir.Core.Keys;

/// <summary>
/// Provides Argon2id parameters, either fixed or calibrated to a target duration.
/// </summary>
public interface IArgon2idParamsProvider
{
    /// <summary>
    /// Returns the last computed parameters, or <c>null</c> if
    /// <see cref="GetParametersAsync"/> has not been called yet.
    /// </summary>
    Argon2idParams? CachedParameters { get; }

    /// <summary>Computes (or returns cached) Argon2id parameters.</summary>
    Task<Argon2idParams> GetParametersAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Synchronous convenience wrapper — blocks the calling thread.
    /// Prefer <see cref="GetParametersAsync"/> in async contexts.
    /// </summary>
    Argon2idParams GetParameters() => GetParametersAsync().GetAwaiter().GetResult();
}
