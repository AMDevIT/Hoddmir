namespace Hoddmir.Core.Encryption.AEAD;

/// <summary>
/// Stable numeric identifier for each AEAD algorithm persisted in the store header.
/// Do NOT reorder or reuse values — they are written to disk.
/// </summary>
public enum AeadAlgorithmId : byte
{
    AesGcm            = 1,
    ChaCha20Poly1305  = 2,
    AesCtrHmacSha256  = 3,
}
