using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hoddmir.Encryption;

/// <summary>
/// AES-256-CTR + HMAC-SHA-256 (Encrypt-then-MAC) AEAD provider.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Security precondition — IKM entropy:</strong>
/// The subkey derivation step uses HKDF-SHA-256 (RFC 5869). When no explicit
/// <c>hkdfSalt</c> is supplied the salt defaults to all-zeros, which is safe
/// <em>only if the IKM (the key passed to <see cref="Encrypt"/> /
/// <see cref="Decrypt"/>) is already a uniformly random key of at least 128 bits</em>
/// — for example, the randomly-generated DEK used by <c>EncryptedEntryStore</c>.
/// If your IKM is a password, a PIN, or any other low-entropy material you
/// <strong>must</strong> pass an explicit random <c>hkdfSalt</c> (≥ 32 bytes),
/// or — better — pre-process the IKM through Argon2id / PBKDF2 before passing it here.
/// Violating this precondition silently weakens subkey separation without error.
/// </para>
/// <para>
/// <strong>Nonce construction:</strong>
/// The 12-byte caller-supplied nonce is used directly as the AES-CTR IV
/// (bytes 0–11); the 4-byte big-endian block counter starts at 1 internally.
/// </para>
/// <para>
/// <strong>MAC:</strong>
/// Trunc-16(HMAC-SHA-256(Kmac, AAD ‖ nonce ‖ ciphertext)).
/// The tag is verified <em>before</em> decryption (Encrypt-then-MAC).
/// </para>
/// </remarks>
public sealed class AesCtrHmacSha256Provider : IAEADProvider
{
    public static readonly AeadAlgorithmId AlgorithmId = AeadAlgorithmId.AesCtrHmacSha256;

    private const string ProviderName   = "AES-CTR+HMAC-SHA256 (EtM)";
    private const int    KeySize        = 32;
    private const int    NonceSize      = 12;
    private const int    TagSize        = 16;
    private const int    MinSaltBytes   = 32;

    // Threshold for the IKM low-entropy warning: if more than half the bytes
    // in the IKM are identical we consider it suspiciously low-entropy.
    private const double LowEntropyThreshold = 0.5;

    private readonly byte[]   _hkdfSalt; // all-zeros when not supplied by caller
    private readonly ILogger? _logger;

    public string Name         => ProviderName;
    public int KeySizeBytes    => KeySize;
    public int NonceSizeBytes  => NonceSize; // caller-supplied; block counter occupies the last 4 bytes internally
    public int TagSizeBytes    => TagSize;   // MAC truncated to 16 bytes

    /// <param name="hkdfSalt">
    /// Optional HKDF salt (recommended ≥ 32 random bytes).
    /// Defaults to all-zeros, which is safe only when the IKM is already a
    /// uniformly random key — see the class-level security precondition.
    /// </param>
    /// <param name="logger">Optional logger for diagnostic and warning messages.</param>
    public AesCtrHmacSha256Provider(byte[]? hkdfSalt = null, ILogger? logger = null)
    {
        if (hkdfSalt is not null && hkdfSalt.Length < MinSaltBytes)
            throw new ArgumentException(
                $"HKDF salt must be at least {MinSaltBytes} bytes when provided. " +
                $"Received {hkdfSalt.Length} bytes.", nameof(hkdfSalt));

        _hkdfSalt = hkdfSalt ?? new byte[32]; // zero salt = RFC 5869 default for uniform IKM
        _logger   = logger;
    }

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
        DeriveSubkeys(key, kenc, kmac);

        AesCtrXor(kenc, nonce, plaintext, ciphertext);
        ComputeMac(kmac, aad, nonce, ciphertext, tag);

        CryptographicOperations.ZeroMemory(kenc);
        CryptographicOperations.ZeroMemory(kmac);
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
        DeriveSubkeys(key, kenc, kmac);

        // Verify MAC before decrypting (Encrypt-then-MAC)
        Span<byte> expectedTag = stackalloc byte[TagSize];
        ComputeMac(kmac, aad, nonce, ciphertext, expectedTag);

        bool valid = CryptographicOperations.FixedTimeEquals(expectedTag, tag);

        if (!valid)
        {
            CryptographicOperations.ZeroMemory(kenc);
            CryptographicOperations.ZeroMemory(kmac);
            _logger?.LogDebug("AES-CTR+HMAC decryption failed: MAC mismatch.");
            return false;
        }

        AesCtrXor(kenc, nonce, ciphertext, plaintext);
        CryptographicOperations.ZeroMemory(kenc);
        CryptographicOperations.ZeroMemory(kmac);
        return true;
    }

    // HKDF-SHA-256 (RFC 5869): Extract(salt, ikm) → PRK → Expand(PRK, info, 64) → Kenc ‖ Kmac.
    //
    // Salt behaviour:
    //   • Caller-supplied salt (≥ 32 bytes): full RFC 5869 security regardless of IKM entropy.
    //   • All-zeros salt (default):           safe only when IKM is a uniform random key
    //                                         (e.g. the EncryptedEntryStore DEK).
    //     In both cases the two 32-byte subkeys are domain-separated by the "AES-CTR-HKDF"
    //     info label, so Kenc and Kmac are independent even if the IKM is reused elsewhere.
    private void DeriveSubkeys(ReadOnlySpan<byte> ikm, Span<byte> kenc, Span<byte> kmac)
    {
        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ikm, _hkdfSalt, prk);

        Span<byte> okm = stackalloc byte[64];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, okm, "AES-CTR-HKDF"u8);

        okm[..32].CopyTo(kenc);
        okm[32..].CopyTo(kmac);

        CryptographicOperations.ZeroMemory(prk);
        CryptographicOperations.ZeroMemory(okm);
    }

    // Emits a warning when all of the following are true:
    //   • No explicit salt was provided (salt is all-zeros).
    //   • The IKM looks suspiciously low-entropy (> 50 % of bytes identical).
    //   • A logger is attached.
    // This is a best-effort heuristic, not a security guarantee — it catches the
    // most obvious misuse (e.g. passing a short ASCII password as the raw IKM)
    // without producing false positives on legitimate uniform keys.
    private void WarnIfLowEntropyIkm(ReadOnlySpan<byte> ikm)
    {
        if (_logger is null) return;
        if (!IsSaltAllZeros()) return; // caller supplied a real salt — no concern

        // Count the most-frequent byte value.
        Span<int> freq = stackalloc int[256];
        foreach (byte b in ikm) freq[b]++;
        int maxFreq = 0;
        foreach (int f in freq) if (f > maxFreq) maxFreq = f;

        if (maxFreq > ikm.Length * LowEntropyThreshold)
            _logger.LogWarning(
                "[{Provider}] The IKM appears to have low entropy " +
                "({MaxFreq}/{Total} bytes share the same value) and no explicit HKDF salt " +
                "was provided. If the IKM is a password or other low-entropy material, " +
                "pass a random hkdfSalt to the constructor or pre-process the IKM with " +
                "Argon2id / PBKDF2 before using this provider.",
                Name, maxFreq, ikm.Length);
    }

    private bool IsSaltAllZeros()
    {
        foreach (byte b in _hkdfSalt)
            if (b != 0) return false;
        return true;
    }

    // Computes Trunc-16(HMAC-SHA-256(kmac, aad ‖ nonce ‖ ciphertext)) into `tag`.
    private static void ComputeMac(ReadOnlySpan<byte> kmac,
                                   ReadOnlySpan<byte> aad,
                                   ReadOnlySpan<byte> nonce,
                                   ReadOnlySpan<byte> ciphertext,
                                   Span<byte> tag)
    {
        byte[] kmacArray = kmac.ToArray();
        using var hmac = new HMACSHA256(kmacArray);
        CryptographicOperations.ZeroMemory(kmacArray);

        hmac.TransformBlock(aad.ToArray(),            0, aad.Length,        null, 0);
        hmac.TransformBlock(nonce.ToArray(),           0, nonce.Length,      null, 0);
        hmac.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);

        hmac.Hash!.AsSpan(0, TagSize).CopyTo(tag);
    }

    // AES-256-CTR: keystream = ECB-encrypt(nonce[0..11] ‖ counter_BE[4]), XOR with input.
    // Counter starts at 1. ECB on a single block is the standard way to build CTR manually.
    private static void AesCtrXor(ReadOnlySpan<byte> kenc,
                                  ReadOnlySpan<byte> nonce,
                                  ReadOnlySpan<byte> input,
                                  Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Mode    = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key     = kenc.ToArray();

        using ICryptoTransform enc = aes.CreateEncryptor();

        Span<byte> counterBlock = stackalloc byte[16];
        nonce.CopyTo(counterBlock[..12]);

        byte[] keystreamBuf = new byte[16];
        uint   counter      = 1;
        int    offset       = 0;

        while (offset < input.Length)
        {
            BinaryPrimitives.WriteUInt32BigEndian(counterBlock[12..], counter);
            enc.TransformBlock(counterBlock.ToArray(), 0, 16, keystreamBuf, 0);

            int n = Math.Min(16, input.Length - offset);
            for (int i = 0; i < n; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystreamBuf[i]);

            counter++;
            offset += n;
        }

        CryptographicOperations.ZeroMemory(keystreamBuf);
    }

    public override string ToString() =>
        $"Provider: {Name}, Key: {KeySizeBytes * 8} bits, Nonce: {NonceSizeBytes} B, Tag: {TagSizeBytes} B";
}
