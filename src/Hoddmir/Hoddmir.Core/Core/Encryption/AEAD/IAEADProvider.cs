namespace Hoddmir.Encryption;

/// <summary>
/// Low-level AEAD provider. All spans are caller-allocated; sizes must match the
/// properties declared below. Use <see cref="AeadExtensions"/> for higher-level helpers.
/// </summary>
public interface IAEADProvider
{
    /// <summary>Human-readable algorithm name, e.g. "AES-GCM".</summary>
    string Name { get; }

    /// <summary>Required key size in bytes (e.g. 32 for 256-bit).</summary>
    int KeySizeBytes { get; }

    /// <summary>Required nonce size in bytes (e.g. 12).</summary>
    int NonceSizeBytes { get; }

    /// <summary>Authentication tag size in bytes (e.g. 16).</summary>
    int TagSizeBytes { get; }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> and writes the
    /// authentication tag into <paramref name="tag"/>.
    /// <paramref name="ciphertext"/> must be exactly <c>plaintext.Length</c> bytes.
    /// </summary>
    void Encrypt(ReadOnlySpan<byte> key,
                 ReadOnlySpan<byte> nonce,
                 ReadOnlySpan<byte> aad,
                 ReadOnlySpan<byte> plaintext,
                 Span<byte> ciphertext,
                 Span<byte> tag);

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> into <paramref name="plaintext"/>, verifying
    /// the authentication tag first.
    /// Returns <c>false</c> if the tag is invalid (tamper, wrong key, wrong nonce, wrong AAD).
    /// <paramref name="plaintext"/> must be exactly <c>ciphertext.Length</c> bytes.
    /// </summary>
    bool Decrypt(ReadOnlySpan<byte> key,
                 ReadOnlySpan<byte> nonce,
                 ReadOnlySpan<byte> aad,
                 ReadOnlySpan<byte> ciphertext,
                 ReadOnlySpan<byte> tag,
                 Span<byte> plaintext);
}
