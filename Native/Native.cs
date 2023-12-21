using System.Runtime.InteropServices;

namespace XXHash.Native;

internal static partial class Native
{
    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ushort XXH_versionNumber();

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial uint XXH32(ref byte input, nuint length, uint seed);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH64(ref byte input, nuint length, ulong seed);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH3_64bits(ref byte data, nuint length);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH3_64bits_withSeed(ref byte data, nuint length, ulong seed);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH3_64bits_withSecret(ref byte input, nuint length, ref byte secret, nuint secretSize);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial XXH128_hash_t XXH3_128bits(ref byte input, nuint length);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial XXH128_hash_t XXH3_128bits_withSeed(ref byte input, nuint length, ulong seed);
}