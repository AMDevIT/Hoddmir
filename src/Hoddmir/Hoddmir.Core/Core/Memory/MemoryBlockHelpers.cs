using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hoddmir.Core.Core.Memory
{
    internal static class MemoryBlockHelpers
    {
        #region Methods

        internal static Span<byte> GetSpanFromHandle(IntPtr handle, int length)
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
