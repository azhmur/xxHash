using System.Runtime.InteropServices;

namespace xxHash3.Native
{
    public static class xxHash3Native
    {
        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static ulong XXH3_64bits(ref byte data, UIntPtr length);

        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static ulong XXH3_64bits_withSeed(ref byte data, UIntPtr length, ulong seed);
    }
}