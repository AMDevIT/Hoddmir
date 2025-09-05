using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hoddmir.Core.Encryption
{
    public sealed class AesCtrHmacSha256Provider 
        : IAEADProvider
    {
        #region Properties

        public string Name => "AES-CTR+HMAC-SHA256 (EtM)";
        public int KeySizeBytes => 32;   // input key
        public int NonceSizeBytes => 12; // user-supplied part; counter usa 4 byte BE
        public int TagSizeBytes => 16;   // MAC troncato a 16

        #endregion

        #region Methods

        public void Encrypt(ReadOnlySpan<byte> key, 
                            ReadOnlySpan<byte> nonce, 
                            ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> plaintext, 
                            Span<byte> ciphertext, 
                            Span<byte> tag)
        {
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16)
                throw new ArgumentException("Bad key/nonce/tag size");
            if (ciphertext.Length != plaintext.Length) throw new ArgumentException("ct size != pt size");

            // Deriva Kenc,Kmac via HKDF-SHA256
            Span<byte> kenc = stackalloc byte[32];
            Span<byte> kmac = stackalloc byte[32];
            HkdfSha256Expand(key, "EES-CTR-HKDF", kenc, kmac);

            AesCtrXor(kenc, nonce, plaintext, ciphertext); // CTR XOR

            // tag = Trunc16(HMAC(Kmac, aad || nonce || ct))
            using var h = new HMACSHA256(kmac.ToArray());
            h.TransformBlock(aad.ToArray(), 0, aad.Length, null, 0);
            h.TransformBlock(nonce.ToArray(), 0, nonce.Length, null, 0);
            h.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);
            var mac = h.Hash!;
            mac.AsSpan(0, 16).CopyTo(tag);

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
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16) 
                return false;

            if (plaintext.Length != ciphertext.Length) 
                return false;

            Span<byte> kenc = stackalloc byte[32];
            Span<byte> kmac = stackalloc byte[32];
            HkdfSha256Expand(key, "EES-CTR-HKDF", kenc, kmac);

            // Verifica MAC prima di decifrare
            using var h = new HMACSHA256(kmac.ToArray());
            h.TransformBlock(aad.ToArray(), 0, aad.Length, null, 0);
            h.TransformBlock(nonce.ToArray(), 0, nonce.Length, null, 0);
            h.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);

            var mac = h.Hash!;
            bool ok = CryptographicOperations.FixedTimeEquals(mac.AsSpan(0, 16), tag);

            if (!ok) 
            { 
                CryptographicOperations.ZeroMemory(kenc); 
                CryptographicOperations.ZeroMemory(kmac); 
                return false; 
            }

            AesCtrXor(kenc, nonce, ciphertext, plaintext); // CTR XOR
            CryptographicOperations.ZeroMemory(kenc);
            CryptographicOperations.ZeroMemory(kmac);
            return true;
        }
        
        // HKDF-Expand (implicit fixed salt) → two 32B blocks
        static void HkdfSha256Expand(ReadOnlySpan<byte> ikm, string info, Span<byte> kenc, Span<byte> kmac)
        {
            // PRK = HMAC(zeros, IKM)
            using var h = new HMACSHA256(new byte[32]);
            var prk = h.ComputeHash(ikm.ToArray()); // 32B

            byte[] T = Array.Empty<byte>();
            byte counter = 1;

            using var h2 = new HMACSHA256(prk);
            // Kenc
            h2.Initialize();
            h2.TransformBlock(T, 0, 0, null, 0);
            var infoBytes = System.Text.Encoding.ASCII.GetBytes(info);
            h2.TransformBlock(infoBytes, 0, infoBytes.Length, null, 0);
            h2.TransformFinalBlock(new[] { counter }, 0, 1);
            var okm1 = h2.Hash!;
            okm1.AsSpan(0, 32).CopyTo(kenc);
            T = okm1; counter++;

            // Kmac
            using var h3 = new HMACSHA256(prk);
            h3.TransformBlock(T, 0, T.Length, null, 0);
            h3.TransformBlock(infoBytes, 0, infoBytes.Length, null, 0);
            h3.TransformFinalBlock(new[] { counter }, 0, 1);
            var okm2 = h3.Hash!;
            okm2.AsSpan(0, 32).CopyTo(kmac);

            Array.Clear(T, 0, T.Length);
            CryptographicOperations.ZeroMemory(prk);
        }

        // AES-CTR (nonce 12B || counter 4B BE, starting at 1)
        static void AesCtrXor(ReadOnlySpan<byte> kenc, ReadOnlySpan<byte> nonce,
                              ReadOnlySpan<byte> input, Span<byte> output)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = kenc.ToArray();

            using var enc = aes.CreateEncryptor();
            Span<byte> counterBlock = stackalloc byte[16];
            nonce.CopyTo(counterBlock[..12]);
            uint counter = 1;

            int offset = 0;
            Span<byte> keystream = stackalloc byte[16];

            while (offset < input.Length)
            {
                BinaryPrimitives.WriteUInt32BigEndian(counterBlock[12..], counter);
                enc.TransformBlock(counterBlock.ToArray(), 0, 16, keystream.ToArray(), 0);
                // XOR
                int n = Math.Min(16, input.Length - offset);
                for (int i = 0; i < n; i++)
                    output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);

                counter++;
                offset += n;
            }
        }

        #endregion
    }
}
