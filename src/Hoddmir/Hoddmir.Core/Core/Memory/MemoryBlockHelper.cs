using System.Security.Cryptography;

namespace Hoddmir.Core.Memory
{
    internal static class MemoryBlockHelper
    {
        #region Methods

        // Fill a byte array with cryptographically strong random bytes.
        public static byte[] RandomBytes(int n)
        {
            byte[] buffer = new byte[n];

            RandomNumberGenerator.Fill(buffer);
            return buffer;
        }

        public static Span<byte> GetSpanFromHandle(IntPtr handle, int length)
        {
            unsafe
            {
                Span<byte> span = new((void*)handle, length);
                return span;
            }
        }

        #endregion
    }
}
