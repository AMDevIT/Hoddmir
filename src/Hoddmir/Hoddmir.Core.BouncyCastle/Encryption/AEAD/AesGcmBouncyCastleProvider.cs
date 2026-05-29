using Hoddmir.Encryption;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using CryptographicOperations = System.Security.Cryptography.CryptographicOperations;

namespace Hoddmir.BouncyCastle.Encryption;

/// <summary>
/// AES-256-GCM AEAD provider backed by BouncyCastle.
/// Used automatically as a fallback for <see cref="AesGcmProvider"/> on runtimes
/// that do not support .NET's native AesGcm (i.e. &lt; .NET 9).
/// Can also be used directly when explicit BouncyCastle behaviour is desired.
/// </summary>
public sealed class AesGcmBouncyCastleProvider : IAEADProvider
{
    private const string ProviderName = "AES-GCM (BouncyCastle)";
    private const int KeySize   = 32;
    private const int NonceSize = 12;
    private const int TagSize   = 16;

    private readonly ILogger? _logger;

    public string Name         => ProviderName;
    public int KeySizeBytes    => KeySize;
    public int NonceSizeBytes  => NonceSize;
    public int TagSizeBytes    => TagSize;

    public AesGcmBouncyCastleProvider(ILogger? logger = null) => _logger = logger;

    public void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize || tag.Length != TagSize)
            throw new ArgumentException("Invalid key, nonce, or tag length.");
        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("Ciphertext span must equal plaintext length.");

        var gcm = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key.ToArray()), TagSize * 8, nonce.ToArray(),
                                            aad.IsEmpty ? null : aad.ToArray());
        gcm.Init(true, parameters);

        var outBuf = new byte[gcm.GetOutputSize(plaintext.Length)];
        int outLen = gcm.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, outBuf, 0);
        outLen += gcm.DoFinal(outBuf, outLen);

        // BouncyCastle appends tag after ciphertext
        outBuf.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        outBuf.AsSpan(plaintext.Length, TagSize).CopyTo(tag);
        CryptographicOperations.ZeroMemory(outBuf);
    }

    public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize || tag.Length != TagSize)
            return false;
        if (plaintext.Length != ciphertext.Length)
            return false;

        var gcm = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key.ToArray()), TagSize * 8, nonce.ToArray(),
                                            aad.IsEmpty ? null : aad.ToArray());
        gcm.Init(false, parameters);

        // BouncyCastle expects ciphertext || tag as a single buffer for decryption
        var inputBuf = new byte[ciphertext.Length + TagSize];
        ciphertext.CopyTo(inputBuf.AsSpan(0, ciphertext.Length));
        tag.CopyTo(inputBuf.AsSpan(ciphertext.Length, TagSize));

        var ptTmp = new byte[gcm.GetOutputSize(inputBuf.Length)];
        try
        {
            int outLen = gcm.ProcessBytes(inputBuf, 0, inputBuf.Length, ptTmp, 0);
            outLen += gcm.DoFinal(ptTmp, outLen);
            ptTmp.AsSpan(0, plaintext.Length).CopyTo(plaintext);
            return true;
        }
        catch (InvalidCipherTextException)
        {
            _logger?.LogDebug("AES-GCM (BouncyCastle) Decrypt: authentication failed.");
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ptTmp);
            CryptographicOperations.ZeroMemory(inputBuf);
        }
    }

    public override string ToString() =>
        $"Provider: {Name}, Key: {KeySizeBytes * 8} bits, Nonce: {NonceSizeBytes} B, Tag: {TagSizeBytes} B";
}
