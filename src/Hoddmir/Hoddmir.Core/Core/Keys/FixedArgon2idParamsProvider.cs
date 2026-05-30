namespace Hoddmir.Core.Keys;

/// <summary>
/// <see cref="IArgon2idParamsProvider"/> that always returns a pre-configured
/// <see cref="Argon2idParams"/>. Useful for tests and environments where calibration
/// is not desired.
/// </summary>
public sealed class FixedArgon2idParamsProvider(Argon2idParams parameters) : IArgon2idParamsProvider
{
    public Argon2idParams? CachedParameters => parameters;

    public Task<Argon2idParams> GetParametersAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(parameters);

    public override string ToString() => $"FixedArgon2idParamsProvider({parameters})";
}
