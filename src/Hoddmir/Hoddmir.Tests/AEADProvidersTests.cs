using Hoddmir.Core.Encryption;
using Hoddmir.Core.Encryption.AEAD;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Tests
{
    [TestClass]
    public class AEADProvidersTests
    {
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
        [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
        public void RoundTripVariousLengthsAndAAD(IAEADProvider aeadProvider)
        {
            Trace.WriteLine($"Using provider: {aeadProvider}");

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

            try
            {
                foreach (var pt in pts)
                {
                    foreach (var aad in aads)
                    {
                        RoundTripOnce(aeadProvider, pt, aad);
                    }
                }
            }
            catch (NotSupportedException)
            {
#if NET8_0
                // AES-GCM not supported in .NET 8
                Trace.WriteLine($"Skipping {aeadProvider.Name} test: not supported in .NET");
#else
                Trace.WriteLine("AES-GCM is supported, rethrowing");
                throw;
#endif
            }
            catch
            {
                throw;
            }
        }

        [TestMethod]
        [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
        public void RoundTripEmptyPlaintextTombstoneLike(IAEADProvider aeadProvider)
        {
            Trace.WriteLine($"Using provider: {aeadProvider}");

            try
            {
                var key = Rnd(aeadProvider.KeySizeBytes);
                var nonce = Rnd(aeadProvider.NonceSizeBytes);
                var aad = Rnd(17);

                var ct = Array.Empty<byte>();
                var tag = new byte[aeadProvider.TagSizeBytes];

                // Encrypt con pt vuoto
                aeadProvider.Encrypt(key, nonce, aad, Array.Empty<byte>(), ct, tag);

                var outPt = Array.Empty<byte>();
                var ok = aeadProvider.Decrypt(key, nonce, aad, ct, tag, outPt);
                Assert.IsTrue(ok, $"{aeadProvider.Name}: decrypt empty-pt fallita");
            }
            catch (NotSupportedException)
            {
#if NET8_0
                // AES-GCM not supported in .NET 8
                Trace.WriteLine($"Skipping {aeadProvider.Name} test: not supported in .NET");
#else
                Trace.WriteLine("AES-GCM is supported, rethrowing");
                throw;
#endif
            }
            catch
            {
                throw;
            }
        }

        [TestMethod]
        [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
        public void DeterministicSameInputsProduceSameOutputs(IAEADProvider aeadProvider)
        {
            Trace.WriteLine($"Using provider: {aeadProvider}");

            try
            {

                var key = Rnd(aeadProvider.KeySizeBytes);
                var nonce = Rnd(aeadProvider.NonceSizeBytes);
                var aad = Rnd(9);
                var pt = Rnd(64);

                var ct1 = new byte[pt.Length];
                var tag1 = new byte[aeadProvider.TagSizeBytes];
                aeadProvider.Encrypt(key, nonce, aad, pt, ct1, tag1);

                var ct2 = new byte[pt.Length];
                var tag2 = new byte[aeadProvider.TagSizeBytes];
                aeadProvider.Encrypt(key, nonce, aad, pt, ct2, tag2);

                CollectionAssert.AreEqual(ct1, ct2, $"{aeadProvider.Name}: CT differente a parità di input");
                CollectionAssert.AreEqual(tag1, tag2, $"{aeadProvider.Name}: TAG differente a parità di input");
            }
            catch(NotSupportedException)
            {
#if NET8_0
                // AES-GCM not supported in .NET 8
                Trace.WriteLine($"Skipping {aeadProvider.Name} test: not supported in .NET");
#else
                Trace.WriteLine("AES-GCM is supported, rethrowing");
                throw;
#endif
            }
            catch
            {
                throw;
            }
        }

        [TestMethod]
        [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
        public void TamperDetectionFails(IAEADProvider aeadProvider)
        {
            Trace.WriteLine($"Using provider: {aeadProvider}");

            try
            {

                var key = Rnd(aeadProvider.KeySizeBytes);
                var nonce = Rnd(aeadProvider.NonceSizeBytes);
                var aad = Rnd(11);
                var pt = Rnd(128);

                var ct = new byte[pt.Length];
                var tag = new byte[aeadProvider.TagSizeBytes];

                aeadProvider.Encrypt(key, nonce, aad, pt, ct, tag);

                byte[] ptOut;

                // Flip CT
                {
                    var ctX = (byte[])ct.Clone();
                    ctX[0] ^= 0x01;
                    ptOut = new byte[pt.Length];
                    var ok = aeadProvider.Decrypt(key, nonce, aad, ctX, tag, ptOut);
                    Assert.IsFalse(ok, $"{aeadProvider.Name}: tamper CT non rilevato");
                }

                // Flip TAG
                {
                    var tagX = (byte[])tag.Clone();
                    tagX[^1] ^= 0x80;
                    ptOut = new byte[pt.Length];
                    var ok = aeadProvider.Decrypt(key, nonce, aad, ct, tagX, ptOut);
                    Assert.IsFalse(ok, $"{aeadProvider.Name}: tamper TAG non rilevato");
                }

                // Flip NONCE
                {
                    var nonceX = (byte[])nonce.Clone();
                    nonceX[3] ^= 0x20;
                    ptOut = new byte[pt.Length];
                    var ok = aeadProvider.Decrypt(key, nonceX, aad, ct, tag, ptOut);
                    Assert.IsFalse(ok, $"{aeadProvider.Name}: tamper NONCE non rilevato");
                }

                // Flip AAD
                {
                    byte[] aadX = (byte[])aad.Clone();
                    if (aadX.Length == 0)
                        aadX = [0x00];

                    aadX[^1] ^= 0x10;
                    ptOut = new byte[pt.Length];
                    var ok = aeadProvider.Decrypt(key, nonce, aadX, ct, tag, ptOut);
                    Assert.IsFalse(ok, $"{aeadProvider.Name}: tamper AAD non rilevato");
                }
            }
            catch (NotSupportedException)
            {
#if NET8_0
                // AES-GCM not supported in .NET 8
                Trace.WriteLine($"Skipping {aeadProvider.Name} test: not supported in .NET");
#else
                Trace.WriteLine("AES-GCM is supported, rethrowing");
                throw;
#endif
            }
            catch
            {
                throw;
            }
        }        

        [TestMethod]
        [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
        public void WrongKeyFails(IAEADProvider aeadProvider)
        {
            Trace.WriteLine($"Using provider: {aeadProvider}");

            try
            {

                var key1 = Rnd(aeadProvider.KeySizeBytes);
                var key2 = Rnd(aeadProvider.KeySizeBytes);
                var nonce = Rnd(aeadProvider.NonceSizeBytes);
                var aad = Rnd(5);
                var pt = Rnd(32);

                var ct = new byte[pt.Length];
                var tag = new byte[aeadProvider.TagSizeBytes];

                aeadProvider.Encrypt(key1, nonce, aad, pt, ct, tag);

                var outPt = new byte[pt.Length];
                var ok = aeadProvider.Decrypt(key2, nonce, aad, ct, tag, outPt);
                Assert.IsFalse(ok, $"{aeadProvider.Name}: decrypt con chiave errata dovrebbe fallire");
            }
            catch (NotSupportedException)
            {
#if NET8_0
                // AES-GCM not supported in .NET 8
                Trace.WriteLine($"Skipping {aeadProvider.Name} test: not supported in .NET");
#else
                Trace.WriteLine("AES-GCM is supported, rethrowing");
                throw;
#endif
            }
            catch
            {
                throw;
            }
        }

        [TestMethod]
        [DynamicData(nameof(GetProviders), DynamicDataSourceType.Method)]
        public void SizeChecksThrowOrFailAsExpected(IAEADProvider aeadProvider)
        {
            Trace.WriteLine($"Using provider: {aeadProvider}");
            var key = Rnd(aeadProvider.KeySizeBytes);
            var nonce = Rnd(aeadProvider.NonceSizeBytes);
            var aad = Array.Empty<byte>();
            var pt = Rnd(8);
            var ct = new byte[pt.Length];
            var tag = new byte[aeadProvider.TagSizeBytes];

#if NET8_0
            if (aeadProvider.Name == "AES-GCM")
            {
                // AES-GCM not supported in .NET 8
                Trace.WriteLine($"Skipping {aeadProvider.Name} test: not supported in .NET");
                return;
            }
#endif 

            // Encrypt con nonce sbagliato → ArgumentException
            Assert.ThrowsException<ArgumentException>(() =>
            {
                var badNonce = Rnd(aeadProvider.NonceSizeBytes + 1);
                aeadProvider.Encrypt(key, badNonce, aad, pt, ct, tag);
            }, $"{aeadProvider.Name}: Encrypt con nonce len errata non ha lanciato");

            // Decrypt con tag sbagliato → false
            {
                var badTag = Rnd(aeadProvider.TagSizeBytes + 1);
                var ok = aeadProvider.Decrypt(key, nonce, aad, ct, badTag, pt);
                Assert.IsFalse(ok, $"{aeadProvider.Name}: Decrypt con tag len errata non ha fallito");
            }
            
        }

        private static IEnumerable<object[]> GetProviders()
        {

            IAEADProvider[] providers =
            [
                new AesGcmProvider(tagSizeBytes: 16),
                new ChaCha20Poly1305Provider(),
                new AesCtrHmacSha256Provider(),
            ];

            return [.. providers.Select(p => new object[] { p })];
        }
    }
}
