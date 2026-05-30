using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace Hoddmir.Core.Encryption.AEAD;

/// <summary>
/// AES-256-GCM AEAD provider backed by the .NET 9+ managed implementation.
/// </summary>
public sealed class AesGcmProvider
    : IAEADProvider
{
    #region Consts

    private const string ProviderName = "AES-GCM";
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    #endregion

    #region Fields

    public static readonly AeadAlgorithmId AlgorithmId = AeadAlgorithmId.AesGcm;
    private readonly ILogger? logger;

    #endregion

    #region Properties

    public string Name => ProviderName;
    public int KeySizeBytes => KeySize;
    public int NonceSizeBytes => NonceSize;
    public int TagSizeBytes
    {
        get;
    }

    #endregion

    #region .ctor

    public AesGcmProvider(int tagSizeBytes = TagSize, ILogger? logger = null)
    {
        if (tagSizeBytes is not (12 or 13 or 14 or 15 or 16))
            throw new ArgumentOutOfRangeException(nameof(tagSizeBytes),
                                                  "AES-GCM tag must be between 12 and 16 bytes.");

        this.TagSizeBytes = tagSizeBytes;
        this.logger = logger;
    }

    #endregion

    #region Methods

    public void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {

        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException("Nonce must be 12 bytes.", nameof(nonce));

        if (tag.Length != TagSizeBytes)
            throw new ArgumentException($"Tag must be {TagSizeBytes} bytes.", nameof(tag));

        if (key.Length != KeySizeBytes)
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));

        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("Ciphertext span must equal plaintext length.", nameof(ciphertext));

        using AesGcm gcm = new(key, TagSizeBytes);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
    }

    public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {

        if (nonce.Length != NonceSizeBytes || tag.Length != TagSizeBytes || key.Length != KeySizeBytes)
            return false;

        if (plaintext.Length != ciphertext.Length)
            return false;

        try
        {
            using AesGcm gcm = new(key, TagSizeBytes);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            return true;
        }
        catch (CryptographicException)
        {
            logger?.LogDebug("AES-GCM decryption failed: bad tag or corrupted data.");
            return false;
        }
    }

    public override string ToString()
    { 
        return $"Provider: {Name}, Key: {KeySizeBytes * 8} bits, " +
               $"Nonce: {NonceSizeBytes} B, Tag: {TagSizeBytes} B";
    }

    #endregion
}
