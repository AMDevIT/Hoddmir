using Microsoft.Extensions.Logging;

#if NET9_0_OR_GREATER

using System.Security.Cryptography;

#endif 

namespace Hoddmir.Core.Encryption.AEAD
{
    public sealed class AesGcmProvider 
        : IAEADProvider
    {
        #region Consts

        private const string ProviderName = "AES-GCM";
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;

        #endregion

        #region Properties

        public string Name => ProviderName;

        public int KeySizeBytes => KeySize;

        public int NonceSizeBytes => NonceSize;

        public int TagSizeBytes 
        { 
            get; 
        }
        
        private ILogger? Logger
        {
            get;
        }

        #endregion

        #region .ctor

        public AesGcmProvider(int tagSizeBytes = TagSize)
            : this(tagSizeBytes, null)
        {

        }

        public AesGcmProvider(int tagSizeBytes = TagSize, ILogger? logger = null)
        {
            if (tagSizeBytes is not (12 or 13 or 14 or 15 or 16))
                throw new ArgumentOutOfRangeException(nameof(tagSizeBytes));
            this.TagSizeBytes = tagSizeBytes;
            this.Logger = logger;
        }

        #endregion

        #region Methods

        public void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
        {
#if NET9_0_OR_GREATER

            if (nonce.Length != NonceSizeBytes) 
                throw new ArgumentException("Bad nonce len");

            if (tag.Length != TagSizeBytes) 
                throw new ArgumentException("Bad tag len");

            if (key.Length != KeySizeBytes) 
                throw new ArgumentException("Bad key len");

            if (ciphertext.Length != plaintext.Length) 
                throw new ArgumentException("ct size != pt size");

            using AesGcm gcm = new AesGcm(key, TagSizeBytes);
            gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
#else
            throw new NotSupportedException("AES-GCM requires .NET 9 or later");
#endif  
        }

        public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
        {
#if NET9_0_OR_GREATER
            if (nonce.Length != NonceSizeBytes || tag.Length != TagSizeBytes || key.Length != KeySizeBytes)
                return false;

            if (plaintext.Length != ciphertext.Length) 
                return false;

            try
            {
                using AesGcm gcm = new (key, TagSizeBytes);
                gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                return true;
            }
            catch (CryptographicException) 
            {
                this.Logger?.LogDebug("Error in AES-GCM decryption: bad tag or data");
                return false;
            }
#else
            throw new NotSupportedException("AES-GCM requires .NET 9 or later");
#endif
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
