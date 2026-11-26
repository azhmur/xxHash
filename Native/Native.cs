using System.Runtime.InteropServices;

namespace XXHash.Native;

internal static partial class Native
{
    // XXH3 entry points go through xxh_x86dispatch.c, which selects AVX-512 / AVX2 / SSE2 at runtime.
    // Returns the selected vector implementation: 0 = scalar, 1 = SSE2, 2 = AVX2, 3 = AVX-512.
    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial int XXH_featureTest();

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ushort XXH_versionNumber();

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial uint XXH32(ref byte input, nuint length, uint seed);

    [LibraryImport("xxhash", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH64(ref byte input, nuint length, ulong seed);

    [LibraryImport("xxhash", EntryPoint = "XXH3_64bits_dispatch", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH3_64bits(ref byte data, nuint length);

    [LibraryImport("xxhash", EntryPoint = "XXH3_64bits_withSeed_dispatch", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH3_64bits_withSeed(ref byte data, nuint length, ulong seed);

    [LibraryImport("xxhash", EntryPoint = "XXH3_64bits_withSecret_dispatch", SetLastError = false)]
    [SuppressGCTransition]
    public static partial ulong XXH3_64bits_withSecret(ref byte input, nuint length, ref byte secret, nuint secretSize);

    [LibraryImport("xxhash", EntryPoint = "XXH3_128bits_dispatch", SetLastError = false)]
    [SuppressGCTransition]
    public static partial XXH128_hash_t XXH3_128bits(ref byte input, nuint length);

    [LibraryImport("xxhash", EntryPoint = "XXH3_128bits_withSeed_dispatch", SetLastError = false)]
    [SuppressGCTransition]
    public static partial XXH128_hash_t XXH3_128bits_withSeed(ref byte input, nuint length, ulong seed);
}