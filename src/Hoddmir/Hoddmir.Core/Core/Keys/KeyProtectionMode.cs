namespace Hoddmir.Keys;

/// <summary>
/// Determines how the Data Encryption Key (DEK) is protected in the store header.
/// </summary>
/// <remarks>
/// Only Argon2id is supported in the current format (v0x04).
/// Platform-specific modes (Windows Hello TPM, Apple Secure Enclave) will be
/// added as optional extension libraries in future releases.
/// </remarks>
public enum KeyProtectionMode : byte
{
    /// <summary>Argon2id key derivation. The only supported mode in v0x04.</summary>
    PasswordArgon2id = 0,
}