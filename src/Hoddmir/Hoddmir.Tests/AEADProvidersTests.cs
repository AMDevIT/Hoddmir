using Hoddmir.Core.Encryption;
using Hoddmir.Core.Encryption.AEAD;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Tests
{
    [TestClass]
    public class AEADProvidersTests
    {
        // Elenco provider da testare
        private static IAEADProvider[] Providers =>
        [
            new AesGcmProvider(tagSizeBytes: 16),
            new ChaCha20Poly1305Provider(),
            new AesCtrHmacSha256Provider(),
        ];

        // Helper: genera riempimenti riproducibili
        private static byte[] Rnd(int len)
        {
            var b = new byte[len];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        private static void RoundTripOnce(IAEADProvider p, byte[] pt, byte[] aad)
        {
            var key = Rnd(p.KeySizeBytes);
            var nonce = Rnd(p.NonceSizeBytes);

            var ct = new byte[pt.Length];
            var tag = new byte[p.TagSizeBytes];

            p.Encrypt(key, nonce, aad, pt, ct, tag);

            var outPt = new byte[pt.Length];
            var ok = p.Decrypt(key, nonce, aad, ct, tag, outPt);

            Assert.IsTrue(ok, $"{p.Name}: decrypt fallita");
            CollectionAssert.AreEqual(pt, outPt, $"{p.Name}: plaintext differente");
        }

        [TestMethod]
        public void RoundTripVariousLengthsAndAAD()
        {
            var pts = new[]
            {
                Array.Empty<byte>(),
                Encoding.UTF8.GetBytes("a"),
                Encoding.UTF8.GetBytes("hello"),
                Rnd(15),
                Rnd(16),
                Rnd(17),
                Rnd(1024),
            };

            var aads = new[]
            {
                Array.Empty<byte>(),
                Encoding.ASCII.GetBytes("AAD"),
                Rnd(7),
                Rnd(17),
            };

            foreach (var p in Providers)
            {
                foreach (var pt in pts)
                {
                    foreach (var aad in aads)
                    {
                        RoundTripOnce(p, pt, aad);
                    }
                }
            }
        }

        [TestMethod]
        public void RoundTripEmptyPlaintextTombstoneLike()
        {
            foreach (var p in Providers)
            {
                var key = Rnd(p.KeySizeBytes);
                var nonce = Rnd(p.NonceSizeBytes);
                var aad = Rnd(17);

                var ct = Array.Empty<byte>();
                var tag = new byte[p.TagSizeBytes];

                // Encrypt con pt vuoto
                p.Encrypt(key, nonce, aad, Array.Empty<byte>(), ct, tag);

                var outPt = Array.Empty<byte>();
                var ok = p.Decrypt(key, nonce, aad, ct, tag, outPt);
                Assert.IsTrue(ok, $"{p.Name}: decrypt empty-pt fallita");
            }
        }

        [TestMethod]
        public void DeterministicSameInputsProduceSameOutputs()
        {
            foreach (var p in Providers)
            {
                var key = Rnd(p.KeySizeBytes);
                var nonce = Rnd(p.NonceSizeBytes);
                var aad = Rnd(9);
                var pt = Rnd(64);

                var ct1 = new byte[pt.Length];
                var tag1 = new byte[p.TagSizeBytes];
                p.Encrypt(key, nonce, aad, pt, ct1, tag1);

                var ct2 = new byte[pt.Length];
                var tag2 = new byte[p.TagSizeBytes];
                p.Encrypt(key, nonce, aad, pt, ct2, tag2);

                CollectionAssert.AreEqual(ct1, ct2, $"{p.Name}: CT differente a parità di input");
                CollectionAssert.AreEqual(tag1, tag2, $"{p.Name}: TAG differente a parità di input");
            }
        }

        [TestMethod]
        public void TamperDetectionFailsOnCTTAGNONCEAAD()
        {
            foreach (var p in Providers)
            {
                var key = Rnd(p.KeySizeBytes);
                var nonce = Rnd(p.NonceSizeBytes);
                var aad = Rnd(11);
                var pt = Rnd(128);

                var ct = new byte[pt.Length];
                var tag = new byte[p.TagSizeBytes];

                p.Encrypt(key, nonce, aad, pt, ct, tag);

                byte[] ptOut;

                // Flip CT
                {
                    var ctX = (byte[])ct.Clone();
                    ctX[0] ^= 0x01;
                    ptOut = new byte[pt.Length];
                    var ok = p.Decrypt(key, nonce, aad, ctX, tag, ptOut);
                    Assert.IsFalse(ok, $"{p.Name}: tamper CT non rilevato");
                }

                // Flip TAG
                {
                    var tagX = (byte[])tag.Clone();
                    tagX[^1] ^= 0x80;
                    ptOut = new byte[pt.Length];
                    var ok = p.Decrypt(key, nonce, aad, ct, tagX, ptOut);
                    Assert.IsFalse(ok, $"{p.Name}: tamper TAG non rilevato");
                }

                // Flip NONCE
                {
                    var nonceX = (byte[])nonce.Clone();
                    nonceX[3] ^= 0x20;
                    ptOut = new byte[pt.Length];
                    var ok = p.Decrypt(key, nonceX, aad, ct, tag, ptOut);
                    Assert.IsFalse(ok, $"{p.Name}: tamper NONCE non rilevato");
                }

                // Flip AAD
                {
                    var aadX = (byte[])aad.Clone();
                    if (aadX.Length == 0) aadX = new byte[] { 0x00 };
                    aadX[^1] ^= 0x10;
                    ptOut = new byte[pt.Length];
                    var ok = p.Decrypt(key, nonce, aadX, ct, tag, ptOut);
                    Assert.IsFalse(ok, $"{p.Name}: tamper AAD non rilevato");
                }
            }
        }

        [TestMethod]
        public void WrongKeyFails()
        {
            foreach (var p in Providers)
            {
                var key1 = Rnd(p.KeySizeBytes);
                var key2 = Rnd(p.KeySizeBytes);
                var nonce = Rnd(p.NonceSizeBytes);
                var aad = Rnd(5);
                var pt = Rnd(32);

                var ct = new byte[pt.Length];
                var tag = new byte[p.TagSizeBytes];

                p.Encrypt(key1, nonce, aad, pt, ct, tag);

                var outPt = new byte[pt.Length];
                var ok = p.Decrypt(key2, nonce, aad, ct, tag, outPt);
                Assert.IsFalse(ok, $"{p.Name}: decrypt con chiave errata dovrebbe fallire");
            }
        }

        [TestMethod]
        public void SizeChecksThrowOrFailAsExpected()
        {
            foreach (var p in Providers)
            {
                var key = Rnd(p.KeySizeBytes);
                var nonce = Rnd(p.NonceSizeBytes);
                var aad = Array.Empty<byte>();
                var pt = Rnd(8);
                var ct = new byte[pt.Length];
                var tag = new byte[p.TagSizeBytes];

                // Encrypt con nonce sbagliato → ArgumentException
                Assert.ThrowsException<ArgumentException>(() =>
                {
                    var badNonce = Rnd(p.NonceSizeBytes + 1);
                    p.Encrypt(key, badNonce, aad, pt, ct, tag);
                }, $"{p.Name}: Encrypt con nonce len errata non ha lanciato");

                // Decrypt con tag sbagliato → false
                {
                    var badTag = Rnd(p.TagSizeBytes + 1);
                    var ok = p.Decrypt(key, nonce, aad, ct, badTag, pt);
                    Assert.IsFalse(ok, $"{p.Name}: Decrypt con tag len errata non ha fallito");
                }
            }
        }
    }
}
