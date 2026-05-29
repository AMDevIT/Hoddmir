namespace Hoddmir.Keys;

/// <summary>Derives a key-encryption key (KEK) from a password using Argon2id.</summary>
public interface IArgonKeyProvider
{
    /// <summary>Default output key length in bytes.</summary>
    const int DefaultKeyLength = 32;

    /// <summary>
    /// Derives a KEK from <paramref name="password"/> and <paramref name="salt"/>
    /// using the supplied <paramref name="parameters"/>.
    /// </summary>
    byte[] DeriveKey(ReadOnlySpan<byte> password,
                     ReadOnlySpan<byte> salt,
                     in Argon2idParams parameters,
                     int keyLength = DefaultKeyLength);
}
