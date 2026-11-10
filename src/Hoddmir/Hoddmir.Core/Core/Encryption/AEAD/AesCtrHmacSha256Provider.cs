using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hoddmir.Core.Encryption.AEAD;

/// <summary>
/// AES-256-CTR + HMAC-SHA-256 (Encrypt-then-MAC) AEAD provider.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Key requirements:</strong> Supply a 32-byte cryptographic key.
/// Derive password-based keys with a password KDF such as Argon2id before passing
/// them to this provider. An optional public HKDF salt leaves the cost of guessing
/// a weak key essentially unchanged.
/// </para>
/// <para>
/// <strong>Nonce construction:</strong>
/// The 12-byte caller-supplied nonce is used directly as the AES-CTR IV
/// (bytes 0–11); the 4-byte big-endian block counter starts at 1 internally.
/// </para>
/// <para>
/// <strong>MAC:</strong>
/// Trunc-16(HMAC-SHA-256(Kmac, LE64(AAD length) ‖ LE64(ciphertext length) ‖ AAD ‖ nonce ‖ ciphertext)).
/// The tag is verified <em>before</em> decryption (Encrypt-then-MAC).
/// </para>
/// </remarks>
public sealed class AesCtrHmacSha256Provider 
    : IAEADProvider
{
    #region Fields

    public static readonly AeadAlgorithmId AlgorithmId = AeadAlgorithmId.AesCtrHmacSha256;

    private const string ProviderName   = "AES-CTR+HMAC-SHA256 (EtM)";
    private const int    KeySize        = 32;
    private const int    NonceSize      = 12;
    private const int    TagSize        = 16;
    private const int    MinSaltBytes   = 32;

    // Threshold for the IKM low-entropy warning: if more than half the bytes
    // in the IKM are identical we consider it suspiciously low-entropy.
    private const double LowEntropyThreshold = 0.5;

    private readonly byte[]   hkdfSalt; // all-zeros when not supplied by caller
    private readonly ILogger? logger;

    #endregion

    #region Properties

    public string Name         => ProviderName;
    public int KeySizeBytes    => KeySize;
    public int NonceSizeBytes  => NonceSize; // caller-supplied; block counter occupies the last 4 bytes internally
    public int TagSizeBytes    => TagSize;   // MAC truncated to 16 bytes

    #endregion

    #region .ctor

    /// <param name="hkdfSalt">
    /// Optional HKDF salt (recommended ≥ 32 random bytes).
    /// Defaults to all-zeros, which is safe only when the IKM is already a
    /// uniformly random key — see the class-level security precondition.
    /// </param>
    /// <param name="logger">Optional logger for diagnostic and warning messages.</param>
    public AesCtrHmacSha256Provider(byte[]? hkdfSalt = null, ILogger? logger = null)
    {
        if (hkdfSalt is not null && hkdfSalt.Length < MinSaltBytes)
            throw new ArgumentException($"HKDF salt must be at least {MinSaltBytes} bytes when provided. " +
                                        $"Received {hkdfSalt.Length} bytes.", 
                                        nameof(hkdfSalt));

        this.hkdfSalt = hkdfSalt?.ToArray() ?? new byte[32];
        this.logger   = logger;
    }

    #endregion

    #region Methods

    public void Encrypt(ReadOnlySpan<byte> key,
                        ReadOnlySpan<byte> nonce,
                        ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> plaintext,
                        Span<byte> ciphertext,
                        Span<byte> tag)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize || tag.Length != TagSize)
            throw new ArgumentException("Invalid key, nonce, or tag length.");

        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("Ciphertext span must equal plaintext length.");

        WarnIfLowEntropyIkm(key);

        Span<byte> kenc = stackalloc byte[32];
        Span<byte> kmac = stackalloc byte[32];
        try
        {
            this.DeriveSubkeys(key, kenc, kmac);
            AesCtrXor(kenc, nonce, plaintext, ciphertext);
            ComputeMac(kmac, aad, nonce, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kenc);
            CryptographicOperations.ZeroMemory(kmac);
        }
    }

    public bool Decrypt(ReadOnlySpan<byte> key,
                        ReadOnlySpan<byte> nonce,
                        ReadOnlySpan<byte> aad,
                        ReadOnlySpan<byte> ciphertext,
                        ReadOnlySpan<byte> tag,
                        Span<byte> plaintext)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize || tag.Length != TagSize)
            return false;

        if (plaintext.Length != ciphertext.Length)
            return false;

        WarnIfLowEntropyIkm(key);

        Span<byte> kenc = stackalloc byte[32];
        Span<byte> kmac = stackalloc byte[32];
        Span<byte> expectedTag = stackalloc byte[TagSize];
        try
        {
            this.DeriveSubkeys(key, kenc, kmac);
            ComputeMac(kmac, aad, nonce, ciphertext, expectedTag);
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, tag))
            {
                this.logger?.LogDebug("AES-CTR+HMAC decryption failed: MAC mismatch.");
                return false;
            }

            AesCtrXor(kenc, nonce, ciphertext, plaintext);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kenc);
            CryptographicOperations.ZeroMemory(kmac);
            CryptographicOperations.ZeroMemory(expectedTag);
        }
    }

    // HKDF-SHA-256 (RFC 5869): Extract(salt, ikm) → PRK → Expand(PRK, info, 64) → Kenc ‖ Kmac.
    private void DeriveSubkeys(ReadOnlySpan<byte> ikm, Span<byte> kenc, Span<byte> kmac)
    {
        Span<byte> okm = stackalloc byte[64];
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, okm, this.hkdfSalt, "AES-CTR-HKDF"u8);
            okm[..32].CopyTo(kenc);
            okm[32..].CopyTo(kmac);
        }
        finally { CryptographicOperations.ZeroMemory(okm); }
    }

    /// <summary>Warns when a key has a conspicuously repetitive byte pattern.</summary>
    private void WarnIfLowEntropyIkm(ReadOnlySpan<byte> ikm)
    {
        if (this.logger is null)
            return;

        Span<int> frequency = stackalloc int[256];
        frequency.Clear();
        foreach (byte value in ikm)
            frequency[value]++;

        foreach (int count in frequency)
        {
            if (count <= ikm.Length * LowEntropyThreshold)
                continue;

            this.logger.LogWarning("[{Provider}] The key appears to have low entropy. " +
                                   "Derive password-based keys with a password KDF before encryption.", this.Name);
            break;
        }
        frequency.Clear();
    }
    /// <summary>Authenticates the lengths and bytes of the variable-length fields and the fixed-length nonce.</summary>
    private static void ComputeMac(ReadOnlySpan<byte> kmac,
                                   ReadOnlySpan<byte> aad,
                                   ReadOnlySpan<byte> nonce,
                                   ReadOnlySpan<byte> ciphertext,
                                   Span<byte> tag)
    {
        Span<byte> lengths = stackalloc byte[2 * sizeof(ulong)];
        Span<byte> hash = stackalloc byte[32];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[sizeof(ulong)..], (ulong)ciphertext.Length);

        using IncrementalHash hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, kmac);
        hmac.AppendData(lengths);
        hmac.AppendData(aad);
        hmac.AppendData(nonce);
        hmac.AppendData(ciphertext);
        hmac.GetHashAndReset(hash);
        hash[..TagSize].CopyTo(tag);
        CryptographicOperations.ZeroMemory(hash);
    }

    // AES-256-CTR: keystream = ECB-encrypt(nonce[0..11] ‖ counter_BE[4]), XOR with input.
    // Counter starts at 1. ECB on a single block is the standard way to build CTR manually.
    private static void AesCtrXor(ReadOnlySpan<byte> kenc,
                                  ReadOnlySpan<byte> nonce,
                                  ReadOnlySpan<byte> input,
                                  Span<byte> output)
    {
        using Aes aes = Aes.Create();

#pragma warning disable CA5358 // ECB encrypts unique counter blocks only — standard CTR construction
        aes.Mode = CipherMode.ECB;
#pragma warning restore CA5358

        aes.Padding = PaddingMode.None;
        byte[] key = kenc.ToArray();
        try { aes.Key = key; }
        finally { CryptographicOperations.ZeroMemory(key); }

        using ICryptoTransform enc = aes.CreateEncryptor();

        byte[] counterBlock = new byte[16];
        nonce.CopyTo(counterBlock);

        byte[] keystreamBuf = new byte[16];
        uint   counter      = 1;
        int    offset       = 0;

        while (offset < input.Length)
        {
            BinaryPrimitives.WriteUInt32BigEndian(counterBlock.AsSpan(12), counter);
            enc.TransformBlock(counterBlock, 0, 16, keystreamBuf, 0);

            int n = Math.Min(16, input.Length - offset);
            for (int i = 0; i < n; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystreamBuf[i]);

            counter++;
            offset += n;
        }

        CryptographicOperations.ZeroMemory(keystreamBuf);
    }

    public override string ToString()
    {
        return $"Provider: {Name}, Key: {KeySizeBytes * 8} bits, Nonce: {NonceSizeBytes} B, " +
               $"Tag: {TagSizeBytes} B";
    }

    #endregion
}
