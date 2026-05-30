using System.Security.Cryptography;

namespace Hoddmir.Memory;

internal static class MemoryBlockHelper
{
    /// <summary>Returns a new array filled with cryptographically strong random bytes.</summary>
    public static byte[] RandomBytes(int count)
    {
        var buffer = new byte[count];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }
}
