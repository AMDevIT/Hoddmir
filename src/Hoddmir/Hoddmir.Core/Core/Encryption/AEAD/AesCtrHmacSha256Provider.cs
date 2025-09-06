using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Security.Cryptography;


namespace Hoddmir.Core.Encryption.AEAD
{
    public sealed class AesCtrHmacSha256Provider 
        : IAEADProvider
    {
        #region Consts

        private const string ProviderName = "AES-CTR+HMAC-SHA256 (EtM)";
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;

        #endregion

        #region Properties

        public string Name => ProviderName;
        public int KeySizeBytes => KeySize;   // input key
        public int NonceSizeBytes => NonceSize; // user-supplied part; counter usa 4 byte BE
        public int TagSizeBytes => TagSize;   // MAC troncato a 16

        private ILogger? Logger
        {
            get;
        }

        #endregion

        #region .ctor

        public AesCtrHmacSha256Provider()
            : this(null)
        {

        }

        public AesCtrHmacSha256Provider(ILogger? logger)
        {
            this.Logger = logger;
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
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16)
                throw new ArgumentException("Bad key/nonce/tag size");

            if (ciphertext.Length != plaintext.Length) 
                throw new ArgumentException("ct size != pt size");

            // Deriva Kenc,Kmac via HKDF-SHA256
            Span<byte> kenc = stackalloc byte[32];
            Span<byte> kmac = stackalloc byte[32];
            HkdfSha256Expand(key, "EES-CTR-HKDF", kenc, kmac);

            AesCtrXor(kenc, nonce, plaintext, ciphertext); // CTR XOR

            // tag = Trunc16(HMAC(Kmac, aad || nonce || ct))
            using var hmac = new HMACSHA256(kmac.ToArray());

            hmac.TransformBlock(aad.ToArray(), 0, aad.Length, null, 0);
            hmac.TransformBlock(nonce.ToArray(), 0, nonce.Length, null, 0);
            hmac.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);
            byte[] mac = hmac.Hash!;
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
            using HMACSHA256 hmac = new(kmac.ToArray());
            hmac.TransformBlock(aad.ToArray(), 0, aad.Length, null, 0);
            hmac.TransformBlock(nonce.ToArray(), 0, nonce.Length, null, 0);
            hmac.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);

            byte[] mac = hmac.Hash!;
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
            using HMACSHA256 hmac = new(new byte[32]);
            byte[] privateKey = hmac.ComputeHash(ikm.ToArray()); // 32B

            byte[] T = [];
            byte counter = 1;

            using HMACSHA256 hmacSecondPassage = new (privateKey);
            // Kenc
            hmacSecondPassage.Initialize();
            hmacSecondPassage.TransformBlock(T, 0, 0, null, 0);
            byte[] infoBytes = System.Text.Encoding.ASCII.GetBytes(info);
            hmacSecondPassage.TransformBlock(infoBytes, 0, infoBytes.Length, null, 0);
            hmacSecondPassage.TransformFinalBlock([counter], 0, 1);
            byte[] okm1 = hmacSecondPassage.Hash!;
            okm1.AsSpan(0, 32)
                .CopyTo(kenc);
            T = okm1; 
            counter++;

            // Kmac
            using HMACSHA256 h3 = new HMACSHA256(privateKey);
            h3.TransformBlock(T, 0, T.Length, null, 0);
            h3.TransformBlock(infoBytes, 0, infoBytes.Length, null, 0);
            h3.TransformFinalBlock([counter], 0, 1);
            byte[] okm2 = h3.Hash!;
            okm2.AsSpan(0, 32).CopyTo(kmac);

            Array.Clear(T, 0, T.Length);
            CryptographicOperations.ZeroMemory(privateKey);
        }

        // AES-CTR (nonce 12B || counter 4B BE, starting at 1)
        static void AesCtrXor(ReadOnlySpan<byte> kenc, 
                              ReadOnlySpan<byte> nonce,
                              ReadOnlySpan<byte> input, 
                              Span<byte> output)
        {
            using Aes aes = Aes.Create();

            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = kenc.ToArray();

            using ICryptoTransform enc = aes.CreateEncryptor();
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

        public override string ToString()
        {
            return $"Provider: {this.Name}, KeySize: {this.KeySizeBytes * 8} bits, " +
                   $"NonceSize: {this.NonceSizeBytes} bytes, " +
                   $"TagSize: {this.TagSizeBytes} bytes";
        }

        #endregion
    }
}
