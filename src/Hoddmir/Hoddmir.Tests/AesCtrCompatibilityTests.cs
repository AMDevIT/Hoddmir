using Hoddmir.Core.Encryption.AEAD;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Hoddmir.Tests;

/// <summary>Compares the manual AES counter construction with an independent CTR implementation.</summary>
[TestClass]
public sealed class AesCtrCompatibilityTests
{
    #region Methods

    /// <summary>Checks empty, partial, full and multiple blocks, including a carry in the counter.</summary>
    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(15)]
    [DataRow(16)]
    [DataRow(17)]
    [DataRow(32)]
    [DataRow(33)]
    [DataRow(4097)]
    public void AesCtrHmacSha256_CiphertextMatchesBouncyCastleCtr(int length)
    {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000102030405060708090a0b");
        byte[] plaintext = new byte[length];
        byte[] subkeys = new byte[64];
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[length];
        byte[] recovered = new byte[length];
        AesCtrHmacSha256Provider provider = new();
        byte[] tag = new byte[provider.TagSizeBytes];
        BufferedBlockCipher reference = new(new SicBlockCipher(new AesEngine()));

        // Repeated plaintext blocks must still use different counter blocks.
        plaintext.AsSpan().Fill(0x5a);
        nonce.CopyTo(iv, 0);
        iv[^1] = 1;
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, key, subkeys, new byte[32], "AES-CTR-HKDF"u8);
            reference.Init(true, new ParametersWithIV(new KeyParameter(subkeys, 0, 32), iv));
            byte[] expectedCiphertext = reference.DoFinal(plaintext);

            provider.Encrypt(key, nonce, "ctr-compatibility"u8, plaintext, ciphertext, tag);
            CollectionAssert.AreEqual(expectedCiphertext, ciphertext, "AES-CTR must match the independent SIC/CTR implementation.");
            Assert.IsTrue(provider.Decrypt(key, nonce, "ctr-compatibility"u8, expectedCiphertext, tag, recovered));
            CollectionAssert.AreEqual(plaintext, recovered);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkeys);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    #endregion
}
