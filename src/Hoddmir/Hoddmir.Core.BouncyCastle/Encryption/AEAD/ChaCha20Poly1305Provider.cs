using Hoddmir.Encryption;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.CompilerServices;
using CryptographicOperations = System.Security.Cryptography.CryptographicOperations;

namespace Hoddmir.BouncyCastle.Encryption;

/// <summary>
/// ChaCha20-Poly1305 AEAD provider backed by BouncyCastle.
/// Available on all .NET target frameworks including net8.0, iOS, and Android.
/// </summary>
public sealed class ChaCha20Poly1305Provider : IAEADProvider
{
    public static readonly AeadAlgorithmId AlgorithmId = AeadAlgorithmId.ChaCha20Poly1305;

    private const string ProviderName = "ChaCha20-Poly1305";
    private const int KeySize   = 32;
    private const int NonceSize = 12;
    private const int TagSize   = 16;

    private readonly ILogger? _logger;

    public string Name         => ProviderName;
    public int KeySizeBytes    => KeySize;
    public int NonceSizeBytes  => NonceSize;
    public int TagSizeBytes    => TagSize;

    public ChaCha20Poly1305Provider(ILogger? logger = null) => _logger = logger;

    public void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize || tag.Length != TagSize)
        {
            _logger?.LogDebug("ChaCha20-Poly1305 Encrypt: bad sizes key={K} nonce={N} tag={T}",
                              key.Length, nonce.Length, tag.Length);
            throw new ArgumentException("Invalid key, nonce, or tag length.");
        }
        if (ciphertext.Length != plaintext.Length)
        {
            _logger?.LogDebug("ChaCha20-Poly1305 Encrypt: ciphertext length {CT} != plaintext length {PT}",
                              ciphertext.Length, plaintext.Length);
            throw new ArgumentException("Ciphertext span must equal plaintext length.");
        }

        var aead = new ChaCha20Poly1305();
        aead.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));

        if (!aad.IsEmpty)
            aead.ProcessAadBytes(aad.ToArray(), 0, aad.Length);

        var outBuf = new byte[plaintext.Length + TagSize];
        int outLen = aead.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, outBuf, 0);
        outLen += aead.DoFinal(outBuf, outLen);

        outBuf.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        outBuf.AsSpan(plaintext.Length, TagSize).CopyTo(tag);

        CryptographicOperations.ZeroMemory(outBuf);
    }

    public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize || tag.Length != TagSize)
        {
            _logger?.LogDebug("ChaCha20-Poly1305 Decrypt: bad sizes key={K} nonce={N} tag={T}",
                              key.Length, nonce.Length, tag.Length);
            return false;
        }
        if (plaintext.Length != ciphertext.Length)
        {
            _logger?.LogDebug("ChaCha20-Poly1305 Decrypt: plaintext length {PT} != ciphertext length {CT}",
                              plaintext.Length, ciphertext.Length);
            return false;
        }

        var aead = new ChaCha20Poly1305();
        aead.Init(false, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));

        if (!aad.IsEmpty)
            aead.ProcessAadBytes(aad.ToArray(), 0, aad.Length);

        var ptTmp = new byte[plaintext.Length];
        try
        {
            int outLen = aead.ProcessBytes(ciphertext.ToArray(), 0, ciphertext.Length, ptTmp, 0);
            outLen += aead.ProcessBytes(tag.ToArray(), 0, tag.Length, ptTmp, outLen);
            outLen += aead.DoFinal(ptTmp, outLen);

            ptTmp.AsSpan(0, plaintext.Length).CopyTo(plaintext);
            return true;
        }
        catch (InvalidCipherTextException)
        {
            _logger?.LogDebug("ChaCha20-Poly1305 Decrypt: authentication failed.");
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ptTmp);
        }
    }

    public override string ToString() =>
        $"Provider: {Name}, Key: {KeySizeBytes * 8} bits, Nonce: {NonceSizeBytes} B, Tag: {TagSizeBytes} B";
}

/// <summary>
/// Registers BouncyCastle-backed providers into <see cref="AeadProviderRegistry"/>
/// at module load time, so that e.g. <see cref="AesGcmProvider"/> can fall back to
/// BouncyCastle on .NET 8 automatically.
/// </summary>
internal static class BouncyCastleModuleInit
{
    [ModuleInitializer]
    internal static void Register()
    {
        // AES-GCM via BouncyCastle — available on all target frameworks.
        AeadProviderRegistry.Register(AeadAlgorithmId.AesGcm,
            () => new Hoddmir.BouncyCastle.Encryption.AesGcmBouncyCastleProvider());

        // ChaCha20-Poly1305 via BouncyCastle — not strictly needed on .NET 9+
        // where the managed impl exists, but registered for completeness.
        AeadProviderRegistry.Register(AeadAlgorithmId.ChaCha20Poly1305,
            () => new ChaCha20Poly1305Provider());
    }
}
