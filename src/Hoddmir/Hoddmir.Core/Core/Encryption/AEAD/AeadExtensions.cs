using System.Security.Cryptography;

namespace Hoddmir.Encryption;

/// <summary>
/// High-level helpers built on top of <see cref="IAEADProvider"/>.
/// These methods handle allocation so callers don't have to manage buffer sizes.
/// </summary>
public static class AeadExtensions
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and returns a single buffer:
    /// <c>ciphertext (plaintext.Length bytes) || tag (TagSizeBytes)</c>.
    /// A fresh random nonce is generated internally and returned via <paramref name="nonceOut"/>.
    /// </summary>
    public static byte[] Encrypt(this IAEADProvider provider,
                                 ReadOnlySpan<byte> key,
                                 ReadOnlySpan<byte> aad,
                                 ReadOnlySpan<byte> plaintext,
                                 out byte[] nonceOut)
    {
        nonceOut = new byte[provider.NonceSizeBytes];
        RandomNumberGenerator.Fill(nonceOut);

        var output = new byte[plaintext.Length + provider.TagSizeBytes];
        var ct  = output.AsSpan(0, plaintext.Length);
        var tag = output.AsSpan(plaintext.Length, provider.TagSizeBytes);

        provider.Encrypt(key, nonceOut, aad, plaintext, ct, tag);
        return output;
    }

    /// <summary>
    /// Decrypts a combined <c>ciphertext || tag</c> buffer (as produced by <see cref="Encrypt"/>).
    /// Returns the plaintext, or <c>null</c> if authentication fails.
    /// </summary>
    public static byte[]? TryDecrypt(this IAEADProvider provider,
                                     ReadOnlySpan<byte> key,
                                     ReadOnlySpan<byte> nonce,
                                     ReadOnlySpan<byte> aad,
                                     ReadOnlySpan<byte> combined)
    {
        if (combined.Length < provider.TagSizeBytes)
            return null;

        int ctLen = combined.Length - provider.TagSizeBytes;
        var ct  = combined[..ctLen];
        var tag = combined[ctLen..];

        var plaintext = new byte[ctLen];
        return provider.Decrypt(key, nonce, aad, ct, tag, plaintext) ? plaintext : null;
    }
}
