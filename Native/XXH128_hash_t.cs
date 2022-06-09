using System.Runtime.InteropServices;

namespace XXHash.Native
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct XXH128_hash_t
    {
        public ulong low64;
        public ulong high64;
    }
}
