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
            {
                this.Logger?.LogDebug("Bad key/nonce/tag size: {keyLen}/{nonceLen}/{tagLen}",
                                      key.Length, nonce.Length, tag.Length);
                throw new ArgumentException("Bad key/nonce/tag size");
            }

            if (ciphertext.Length != plaintext.Length)
            {
                this.Logger?.LogDebug("cipherText size != plainText size: {ctLen}/{ptLen}",
                                      ciphertext.Length, plaintext.Length);
                throw new ArgumentException("ct size != pt size");
            }

            var aead = new ChaCha20Poly1305();
            aead.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));

            // AAD esplicita
            if (!aad.IsEmpty)
                aead.ProcessAadBytes(aad.ToArray(), 0, aad.Length);

            // out = CT||TAG
            var outBuf = new byte[plaintext.Length + 16];
            int outLen = aead.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, outBuf, 0);
            outLen += aead.DoFinal(outBuf, outLen); // aggiunge 16B di tag

            // split verso i buffer del chiamante
            outBuf.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            outBuf.AsSpan(plaintext.Length, 16).CopyTo(tag);

            CryptographicOperations.ZeroMemory(outBuf);
        }

        public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
        {
            if (key.Length != 32 || nonce.Length != 12 || tag.Length != 16)
            {
                this.Logger?.LogDebug("Bad key/nonce/tag size: {keyLen}/{nonceLen}/{tagLen}",
                                      key.Length, nonce.Length, tag.Length);
                return false;
            }

            if (plaintext.Length != ciphertext.Length)
            {
                this.Logger?.LogDebug("plainText size != cipherText size: {ptLen}/{ctLen}",
                                      plaintext.Length, ciphertext.Length);
                return false;
            }

            var aead = new ChaCha20Poly1305();
            aead.Init(false, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));

            if (!aad.IsEmpty)
                aead.ProcessAadBytes(aad.ToArray(), 0, aad.Length);

            // In decrypt, la cipher si aspetta CT seguito dal TAG (come input).
            // Possiamo passare CT e poi TAG come due ProcessBytes consecutivi.
            var ptTmp = new byte[plaintext.Length];
            try
            {
                int outLen = aead.ProcessBytes(ciphertext.ToArray(), 0, ciphertext.Length, ptTmp, 0);
                outLen += aead.ProcessBytes(tag.ToArray(), 0, tag.Length, ptTmp, outLen); // tipicamente 0
                outLen += aead.DoFinal(ptTmp, outLen); // verifica MAC; lancia se invalido

                // copia nei buffer del chiamante
                ptTmp.AsSpan(0, plaintext.Length).CopyTo(plaintext);
                return true;
            }
            catch (InvalidCipherTextException)
            {
                this.Logger?.LogDebug("Decryption failed: invalid tag/AAD/nonce/ct");
                return false; // tag/AAD/nonce/ct non validi
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ptTmp);
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
