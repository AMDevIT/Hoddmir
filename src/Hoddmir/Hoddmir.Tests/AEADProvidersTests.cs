using Hoddmir.BouncyCastle.Encryption.AEAD;
using Hoddmir.Core.Encryption.AEAD;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Tests;

[TestClass]
public class AEADProvidersTests
{
    private static byte[] Rnd(int len) { var b = new byte[len]; RandomNumberGenerator.Fill(b); return b; }

    private static void RoundTripOnce(IAEADProvider p, byte[] pt, byte[] aad)
    {
        var key   = Rnd(p.KeySizeBytes);
        var nonce = Rnd(p.NonceSizeBytes);
        var ct    = new byte[pt.Length];
        var tag   = new byte[p.TagSizeBytes];

        p.Encrypt(key, nonce, aad, pt, ct, tag);

        var outPt = new byte[pt.Length];
        Assert.IsTrue(p.Decrypt(key, nonce, aad, ct, tag, outPt), $"{p.Name}: Decrypt returned false");
        CollectionAssert.AreEqual(pt, outPt, $"{p.Name}: plaintext mismatch after round-trip");
    }

    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void RoundTripVariousLengthsAndAAD(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");

        byte[][] plaintexts =
        [
            [],
            Encoding.UTF8.GetBytes("a"),
            Encoding.UTF8.GetBytes("hello"),
            Rnd(15), Rnd(16), Rnd(17), Rnd(1024),
        ];
        byte[][] aads = [[], Encoding.ASCII.GetBytes("AAD"), Rnd(7), Rnd(17)];

        foreach (var pt  in plaintexts)
        foreach (var aad in aads)
            RoundTripOnce(p, pt, aad);
    }

    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void RoundTripEmptyPlaintext(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");
        var key   = Rnd(p.KeySizeBytes);
        var nonce = Rnd(p.NonceSizeBytes);
        var aad   = Rnd(17);
        var tag   = new byte[p.TagSizeBytes];

        p.Encrypt(key, nonce, aad, [], [], tag);
        Assert.IsTrue(p.Decrypt(key, nonce, aad, [], tag, []), $"{p.Name}: empty-plaintext decrypt failed");
    }

    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void UniqueNonceProducesDifferentCiphertext(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");
        var key  = Rnd(p.KeySizeBytes);
        var aad  = Rnd(9);
        var pt   = Rnd(64);

        var nonce1 = Rnd(p.NonceSizeBytes);
        var nonce2 = Rnd(p.NonceSizeBytes);

        var ct1 = new byte[pt.Length]; var tag1 = new byte[p.TagSizeBytes];
        var ct2 = new byte[pt.Length]; var tag2 = new byte[p.TagSizeBytes];

        p.Encrypt(key, nonce1, aad, pt, ct1, tag1);
        p.Encrypt(key, nonce2, aad, pt, ct2, tag2);

        CollectionAssert.AreNotEqual(ct1,  ct2,  $"{p.Name}: same ciphertext with different nonces — possible nonce reuse");
        CollectionAssert.AreNotEqual(tag1, tag2, $"{p.Name}: same tag with different nonces");

        var out1 = new byte[pt.Length]; var out2 = new byte[pt.Length];
        Assert.IsTrue(p.Decrypt(key, nonce1, aad, ct1, tag1, out1), $"{p.Name}: decrypt with nonce1 failed");
        Assert.IsTrue(p.Decrypt(key, nonce2, aad, ct2, tag2, out2), $"{p.Name}: decrypt with nonce2 failed");
        CollectionAssert.AreEqual(pt, out1, $"{p.Name}: plaintext mismatch for nonce1");
        CollectionAssert.AreEqual(pt, out2, $"{p.Name}: plaintext mismatch for nonce2");
    }

    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void TamperDetection(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");
        var key   = Rnd(p.KeySizeBytes);
        var nonce = Rnd(p.NonceSizeBytes);
        var aad   = Rnd(11);
        var pt    = Rnd(128);
        var ct    = new byte[pt.Length];
        var tag   = new byte[p.TagSizeBytes];

        p.Encrypt(key, nonce, aad, pt, ct, tag);

        // Flip ciphertext
        var ctX = (byte[])ct.Clone(); ctX[0] ^= 0x01;
        Assert.IsFalse(p.Decrypt(key, nonce, aad, ctX, tag, new byte[pt.Length]),
                       $"{p.Name}: flipped CT not detected");

        // Flip tag
        var tagX = (byte[])tag.Clone(); tagX[^1] ^= 0x80;
        Assert.IsFalse(p.Decrypt(key, nonce, aad, ct, tagX, new byte[pt.Length]),
                       $"{p.Name}: flipped tag not detected");

        // Flip nonce
        var nonceX = (byte[])nonce.Clone(); nonceX[3] ^= 0x20;
        Assert.IsFalse(p.Decrypt(key, nonceX, aad, ct, tag, new byte[pt.Length]),
                       $"{p.Name}: flipped nonce not detected");

        // Flip AAD
        var aadX = (byte[])aad.Clone(); aadX[^1] ^= 0x10;
        Assert.IsFalse(p.Decrypt(key, nonce, aadX, ct, tag, new byte[pt.Length]),
                       $"{p.Name}: flipped AAD not detected");
    }

    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void WrongKeyFails(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");
        var key1  = Rnd(p.KeySizeBytes);
        var key2  = Rnd(p.KeySizeBytes);
        var nonce = Rnd(p.NonceSizeBytes);
        var pt    = Rnd(32);
        var ct    = new byte[pt.Length];
        var tag   = new byte[p.TagSizeBytes];

        p.Encrypt(key1, nonce, [], pt, ct, tag);
        Assert.IsFalse(p.Decrypt(key2, nonce, [], ct, tag, new byte[pt.Length]),
                       $"{p.Name}: wrong key should fail");
    }

    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void BadSizesThrowOrReturnFalse(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");
        var key   = Rnd(p.KeySizeBytes);
        var nonce = Rnd(p.NonceSizeBytes);
        var pt    = Rnd(8);
        var ct    = new byte[pt.Length];
        var tag   = new byte[p.TagSizeBytes];

        // Encrypt with wrong nonce length → ArgumentException
        Assert.ThrowsException<ArgumentException>(() =>
            p.Encrypt(key, Rnd(p.NonceSizeBytes + 1), [], pt, ct, tag),
            $"{p.Name}: wrong nonce length did not throw");

        // Decrypt with wrong tag length → false
        Assert.IsFalse(p.Decrypt(key, nonce, [], ct, Rnd(p.TagSizeBytes + 1), pt),
                       $"{p.Name}: wrong tag length did not return false");
    }

    // High-level extension methods
    [TestMethod]
    [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
    public void AeadExtensionsRoundTrip(IAEADProvider p)
    {
        Trace.WriteLine($"Provider: {p}");
        var key = Rnd(p.KeySizeBytes);
        var aad = Rnd(13);
        var pt  = Rnd(64);

        byte[] combined = p.Encrypt(key, aad, pt, out byte[] nonce);
        Assert.AreEqual(pt.Length + p.TagSizeBytes, combined.Length);

        byte[]? decrypted = p.TryDecrypt(key, nonce, aad, combined);
        Assert.IsNotNull(decrypted, $"{p.Name}: TryDecrypt returned null");
        CollectionAssert.AreEqual(pt, decrypted, $"{p.Name}: TryDecrypt plaintext mismatch");

        // Tamper → null
        combined[0] ^= 0xFF;
        Assert.IsNull(p.TryDecrypt(key, nonce, aad, combined), $"{p.Name}: tampered combined should return null");
    }

    // ── AesCtrHmacSha256Provider — HKDF salt (#5) ───────────────────────────

    [TestMethod]
    public void AesCtrHmac_ExplicitSalt_RoundTrip()
    {
        byte[] salt = Rnd(32);
        var p       = new AesCtrHmacSha256Provider(hkdfSalt: salt);

        var key   = Rnd(p.KeySizeBytes);
        var nonce = Rnd(p.NonceSizeBytes);
        var aad   = Rnd(13);
        var pt    = Rnd(64);
        var ct    = new byte[pt.Length];
        var tag   = new byte[p.TagSizeBytes];

        p.Encrypt(key, nonce, aad, pt, ct, tag);

        var outPt = new byte[pt.Length];
        Assert.IsTrue(p.Decrypt(key, nonce, aad, ct, tag, outPt),
                      "Decrypt with explicit salt failed.");
        CollectionAssert.AreEqual(pt, outPt, "Plaintext mismatch with explicit salt.");
    }

    [TestMethod]
    public void AesCtrHmac_DifferentSalts_ProduceDifferentCiphertext()
    {
        // Two providers with different salts must produce different ciphertexts
        // for the same key, nonce, and plaintext — proving the salt influences derivation.
        var p1 = new AesCtrHmacSha256Provider(hkdfSalt: Rnd(32));
        var p2 = new AesCtrHmacSha256Provider(hkdfSalt: Rnd(32));

        var key   = Rnd(32);
        var nonce = Rnd(12);
        var pt    = Rnd(64);

        var ct1 = new byte[pt.Length]; var tag1 = new byte[16];
        var ct2 = new byte[pt.Length]; var tag2 = new byte[16];

        p1.Encrypt(key, nonce, [], pt, ct1, tag1);
        p2.Encrypt(key, nonce, [], pt, ct2, tag2);

        CollectionAssert.AreNotEqual(ct1, ct2,
            "Different HKDF salts must produce different ciphertexts.");
    }

    [TestMethod]
    public void AesCtrHmac_ExplicitSaltIsolatesFromZeroSalt()
    {
        // A provider with an explicit random salt must not decrypt ciphertext
        // produced by the default zero-salt provider, confirming domain separation.
        var pZero    = new AesCtrHmacSha256Provider();
        var pExplicit = new AesCtrHmacSha256Provider(hkdfSalt: Rnd(32));

        var key   = Rnd(32);
        var nonce = Rnd(12);
        var pt    = Rnd(32);
        var ct    = new byte[pt.Length];
        var tag   = new byte[16];

        pZero.Encrypt(key, nonce, [], pt, ct, tag);

        // pExplicit must reject the ciphertext produced by pZero
        Assert.IsFalse(pExplicit.Decrypt(key, nonce, [], ct, tag, new byte[pt.Length]),
            "Provider with explicit salt must not decrypt ciphertext from zero-salt provider.");
    }

    [TestMethod]
    public void AesCtrHmac_ShortSaltThrows()
    {
        // Salt shorter than 32 bytes must be rejected at construction time.
        Assert.ThrowsException<ArgumentException>(() =>
            new AesCtrHmacSha256Provider(hkdfSalt: new byte[16]),
            "Salt shorter than 32 bytes should throw ArgumentException.");
    }

    [TestMethod]
    public void AesCtrHmac_LowEntropyIkmLogsWarning()
    {
        // Verify that a suspiciously low-entropy IKM (all same byte) triggers
        // a warning log when no explicit salt is provided.
        var logMessages = new List<string>();
        var logger      = new CapturingLogger(logMessages);
        var p           = new AesCtrHmacSha256Provider(logger: logger);

        // IKM = all 0x41 ('A') — obviously low entropy
        byte[] weakKey = new byte[32];
        Array.Fill(weakKey, (byte)0x41);
        var nonce = Rnd(12);
        var ct    = new byte[0];
        var tag   = new byte[16];

        p.Encrypt(weakKey, nonce, [], [], ct, tag);

        Assert.IsTrue(logMessages.Any(m => m.Contains("low entropy")),
            "Expected a low-entropy IKM warning to be logged.");
    }

    [TestMethod]
    public void AesCtrHmac_LowEntropyIkmWithExplicitSaltNoWarning()
    {
        // When an explicit salt is provided, no warning should be emitted
        // even for a low-entropy IKM — the caller has acknowledged the situation.
        var logMessages = new List<string>();
        var logger      = new CapturingLogger(logMessages);
        var p           = new AesCtrHmacSha256Provider(hkdfSalt: Rnd(32), logger: logger);

        byte[] weakKey = new byte[32];
        Array.Fill(weakKey, (byte)0x41);
        var nonce = Rnd(12);
        var ct    = new byte[0];
        var tag   = new byte[16];

        p.Encrypt(weakKey, nonce, [], [], ct, tag);

        Assert.IsFalse(logMessages.Any(m => m.Contains("low entropy")),
            "No low-entropy warning expected when an explicit salt is provided.");
    }

    private static IEnumerable<object[]> GetProviders()
    {
        IAEADProvider[] providers =
        [
            new AesGcmProvider(tagSizeBytes: 16),
            new ChaCha20Poly1305Provider(),
            new AesCtrHmacSha256Provider(),
        ];
        return providers.Select(p => new object[] { p });
    }
}

/// <summary>
/// Minimal <see cref="ILogger"/> implementation that captures log messages into a list.
/// Used by tests that verify warning/diagnostic output.
/// </summary>
internal sealed class CapturingLogger(List<string> messages) : ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
                            Exception? exception, Func<TState, Exception?, string> formatter)
        => messages.Add(formatter(state, exception));
}
