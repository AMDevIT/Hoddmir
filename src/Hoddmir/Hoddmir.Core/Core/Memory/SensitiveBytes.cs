using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Hoddmir.Core.Core.Memory
{
    public sealed class SensitiveBytes : SafeHandle
    {
        public int Length { get; }

        public SensitiveBytes(int len) 
            : base(IntPtr.Zero, ownsHandle: true)
        { 
            this.Length = len; SetHandle(Marshal.AllocHGlobal(len)); 
        }

        public Span<byte> AsSpan()
        {
            unsafe
            {
                Span<byte> ptr = new((void*)handle, Length);
                return ptr;
            }
        }
        public byte[] ToManagedCopy() { var tmp = new byte[Length]; AsSpan().CopyTo(tmp); return tmp; }
        protected override bool ReleaseHandle()
        { CryptographicOperations.ZeroMemory(AsSpan()); Marshal.FreeHGlobal(handle); return true; }
        public override bool IsInvalid => handle == IntPtr.Zero;
    }
}
