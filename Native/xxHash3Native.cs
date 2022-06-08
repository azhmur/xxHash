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

        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static ushort XXH_versionNumber();

        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static ulong XXH64(ref byte input, UIntPtr length, ulong seed);
        
        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static uint XXH32(ref byte input, UIntPtr length, uint seed);

        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static ulong XXH3_64bits_withSecret(ref byte input, UIntPtr length, ref byte secret, UIntPtr secretSize);

        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static XXH128_hash_t XXH3_128bits(ref byte input, UIntPtr length);

        [DllImport("xxhash")]
        [SuppressGCTransition]
        public extern static XXH128_hash_t XXH3_128bits_withSeed(ref byte input, UIntPtr length, ulong seed);
    }
}