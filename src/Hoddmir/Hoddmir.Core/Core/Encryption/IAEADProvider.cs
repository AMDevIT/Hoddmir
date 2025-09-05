using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hoddmir.Core.Encryption
{
    public interface IAEADProvider
    {
        #region Properties

        string Name 
        { 
            get; 
        }

        int KeySizeBytes 
        { 
            get; 
        } // Example: 32

        int NonceSizeBytes 
        { 
            get; 
        } // Example: 12

        int TagSizeBytes 
        { 
            get; 
        } // Example: 16

        #endregion

        #region Methods

        // AEAD: CT = Encrypt(K, N, AAD, PT); Tag for verification (AAD included)
        void Encrypt(ReadOnlySpan<byte> key,
                     ReadOnlySpan<byte> nonce,
                     ReadOnlySpan<byte> aad,
                     ReadOnlySpan<byte> plaintext,
                     Span<byte> ciphertext,
                     Span<byte> tag);

        // True if authnetication ok (with plainthext full), false if tag/AAD/nonces are wrong.
        bool Decrypt(ReadOnlySpan<byte> key,
                     ReadOnlySpan<byte> nonce,
                     ReadOnlySpan<byte> aad,
                     ReadOnlySpan<byte> ciphertext,
                     ReadOnlySpan<byte> tag,
                     Span<byte> plaintext);

        #endregion
    }
}
