using System.Runtime.InteropServices;

namespace xxHash3.Native
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct XXH128_hash_t
    {
        ulong low64;
        ulong high64;
    }
}
