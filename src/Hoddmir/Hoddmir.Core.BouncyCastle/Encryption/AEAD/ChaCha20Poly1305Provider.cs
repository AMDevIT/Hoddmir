using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using CryptographicOperations = System.Security.Cryptography.CryptographicOperations;


namespace Hoddmir.Core.Encryption.AEAD
{
    public sealed class ChaCha20Poly1305Provider 
        : IAEADProvider
    {
        #region Consts

        private const string ProviderName = "ChaCha20-Poly1305";
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;

        #endregion

        #region Properties

        public string Name => ProviderName;

        public int KeySizeBytes => KeySize;

        public int NonceSizeBytes => NonceSize;

        public int TagSizeBytes => TagSize;

        private  ILogger? Logger 
        { 
            get;
        }

        #endregion

        #region .ctor

        public ChaCha20Poly1305Provider()
        {
        }

        public ChaCha20Poly1305Provider(ILogger? logger)
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
                throw new ArgumentException("CipherText size != PlainText size");

            KeyParameter keyParameter;
            AeadParameters param;
            ChaCha20Poly1305 aead = new ();
           
            keyParameter = new (key.ToArray());
            param = new (keyParameter, 128, nonce.ToArray(), aad.ToArray());
            aead.Init(true, param);

            // BouncyCastle emit CT||TAG: we write on the buffer then we split

            byte[] outBuf = new byte[plaintext.Length + 16];
            int len = aead.ProcessBytes(plaintext.ToArray(), 
                                        0, 
                                        plaintext.Length, 
                                        outBuf, 
                                        0);
            _ = aead.DoFinal(outBuf, len);

            outBuf.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            outBuf.AsSpan(plaintext.Length, 16).CopyTo(tag);
            CryptographicOperations.ZeroMemory(outBuf);
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

            KeyParameter keyParameter;
            AeadParameters param;
            ChaCha20Poly1305 aead = new ChaCha20Poly1305();

            keyParameter = new (key.ToArray());
            param = new (keyParameter, 128, nonce.ToArray(), aad.ToArray());
            aead.Init(false, param);

            var inBuf = new byte[ciphertext.Length + tag.Length];
            ciphertext.CopyTo(inBuf.AsSpan(0, ciphertext.Length));
            tag.CopyTo(inBuf.AsSpan(ciphertext.Length, tag.Length));

            try
            {
                int len = aead.ProcessBytes(inBuf, 0, inBuf.Length, plaintext.ToArray(), 0);
                byte[] plainTextTemp = new byte[plaintext.Length];
                len += aead.DoFinal(plainTextTemp, len);

                if (len != plainTextTemp.Length)
                {
                    this.Logger?.LogDebug("AEAD processed len mismatch");
                    return false;
                }

                plainTextTemp.AsSpan().CopyTo(plaintext);
                CryptographicOperations.ZeroMemory(plainTextTemp);
                return true;
            }
            catch (InvalidCipherTextException) 
            { 
                this.Logger?.LogDebug("Error in ChaCha20-Poly1305 decryption: bad tag or data");
                return false; 
            }
            finally 
            { 
                CryptographicOperations.ZeroMemory(inBuf); 
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
