using Microsoft.Extensions.Logging;
using System.Runtime.Versioning;

#if NET9_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace Hoddmir.Encryption;

/// <summary>
/// AES-256-GCM AEAD provider backed by the .NET 9+ managed implementation.
/// <para>
/// On runtimes older than .NET 9, this provider requires a fallback to be registered in
/// <see cref="AeadProviderRegistry"/> for <see cref="AeadAlgorithmId.AesGcm"/>
/// (e.g. the <c>Hoddmir.BouncyCastle</c> package does this automatically).
/// If no fallback is registered, constructing this provider throws
/// <see cref="PlatformNotSupportedException"/>.
/// </para>
/// </summary>
[UnsupportedOSPlatform("net8.0")]   // Informs the Roslyn analyzer; actual check is at runtime.
public sealed class AesGcmProvider : IAEADProvider
{
    public static readonly AeadAlgorithmId AlgorithmId = AeadAlgorithmId.AesGcm;

    private const string ProviderName = "AES-GCM";
    private const int KeySize   = 32;
    private const int NonceSize = 12;
    private const int TagSize   = 16;

    // On .NET 8, construction delegates to a fallback registered in AeadProviderRegistry.
    // _fallback is null on .NET 9+ (native path is used).
    private readonly IAEADProvider? _fallback;
    private readonly ILogger?       _logger;

    public string Name         => ProviderName;
    public int KeySizeBytes    => KeySize;
    public int NonceSizeBytes  => NonceSize;
    public int TagSizeBytes    { get; }

    public AesGcmProvider(int tagSizeBytes = TagSize, ILogger? logger = null)
    {
        if (tagSizeBytes is not (12 or 13 or 14 or 15 or 16))
            throw new ArgumentOutOfRangeException(nameof(tagSizeBytes),
                "AES-GCM tag must be between 12 and 16 bytes.");

        TagSizeBytes = tagSizeBytes;
        _logger      = logger;

#if !NET9_0_OR_GREATER
        // Try to get a registered fallback (e.g. BouncyCastle).
        _fallback = AeadProviderRegistry.TryCreate(AeadAlgorithmId.AesGcm);
        if (_fallback is null)
            throw new PlatformNotSupportedException(
                $"{ProviderName} requires .NET 9 or later on this platform " +
                $"({System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}). " +
                $"Reference the Hoddmir.BouncyCastle package, or use " +
                $"{nameof(AesCtrHmacSha256Provider)} / {nameof(ChaCha20Poly1305Provider)} instead.");
#endif
    }

    public void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        if (_fallback is not null) { _fallback.Encrypt(key, nonce, aad, plaintext, ciphertext, tag); return; }

#if NET9_0_OR_GREATER
        if (nonce.Length != NonceSizeBytes)  throw new ArgumentException("Nonce must be 12 bytes.", nameof(nonce));
        if (tag.Length   != TagSizeBytes)    throw new ArgumentException($"Tag must be {TagSizeBytes} bytes.", nameof(tag));
        if (key.Length   != KeySizeBytes)    throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        if (ciphertext.Length != plaintext.Length) throw new ArgumentException("Ciphertext span must equal plaintext length.", nameof(ciphertext));

        using AesGcm gcm = new(key, TagSizeBytes);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
#endif
    }

    public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        if (_fallback is not null) return _fallback.Decrypt(key, nonce, aad, ciphertext, tag, plaintext);

#if NET9_0_OR_GREATER
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
            _logger?.LogDebug("AES-GCM decryption failed: bad tag or corrupted data.");
            return false;
        }
#else
        return false; // unreachable: constructor throws on .NET 8 with no fallback
#endif
    }

    public override string ToString() =>
        $"Provider: {Name}, Key: {KeySizeBytes * 8} bits, Nonce: {NonceSizeBytes} B, Tag: {TagSizeBytes} B";
}
