using Konscious.Security.Cryptography;

namespace Hoddmir.Keys;

/// <summary>Default <see cref="IArgonKeyProvider"/> implementation using Konscious.Argon2.</summary>
public sealed class ArgonKeyProvider : IArgonKeyProvider
{
    public byte[] DeriveKey(ReadOnlySpan<byte> password,
                            ReadOnlySpan<byte> salt,
                            in Argon2idParams parameters,
                            int keyLength = IArgonKeyProvider.DefaultKeyLength)
    {
        using Argon2id argon = new(password.ToArray())
        {
            Salt                = salt.ToArray(),
            MemorySize          = parameters.MemoryKiB,
            Iterations          = parameters.Iterations,
            DegreeOfParallelism = Math.Max(1, parameters.Parallelism),
        };
        return argon.GetBytes(keyLength);
    }
}
