using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace XXHash.Native;

public static class XXHashNative
{
    public static ulong XXHash3_64(ReadOnlySpan<byte> data)
    {
        return Native.XXH3_64bits(ref MemoryMarshal.GetReference(data), (nuint)data.Length);
    }

    public static ulong XXHash3_64(ReadOnlySpan<char> data)
    {   
        return Native.XXH3_64bits(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (nuint)(data.Length * 2));
    }

    public static ulong XXHash3_64(ReadOnlySpan<byte> data, ulong seed)
    {
        return Native.XXH3_64bits_withSeed(ref MemoryMarshal.GetReference(data), (nuint)data.Length, seed);
    }

    public static ulong XXHash3_64(ReadOnlySpan<char> data, ulong seed)
    {
        return Native.XXH3_64bits_withSeed(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (nuint)(data.Length * 2), seed);
    }

    public static ulong XXHash64(ReadOnlySpan<byte> data, ulong seed)
    {
        return Native.XXH64(ref MemoryMarshal.GetReference(data), (nuint)data.Length, seed);
    }

    public static ulong XXHash64(ReadOnlySpan<char> data, ulong seed)
    {
        return Native.XXH64(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (nuint)(data.Length * 2), seed);
    }

    public static ulong XXHash32(ReadOnlySpan<byte> data, uint seed)
    {
        return Native.XXH32(ref MemoryMarshal.GetReference(data), (nuint)data.Length, seed);
    }

    public static ulong XXHash32(ReadOnlySpan<char> data, uint seed)
    {
        return Native.XXH32(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (nuint)(data.Length * 2), seed);
    }

    public static XXH128_hash_t XXHash3_128(ReadOnlySpan<byte> data)
    {
        return Native.XXH3_128bits(ref MemoryMarshal.GetReference(data), (nuint)data.Length);
    }

    public static XXH128_hash_t XXHash3_128(ReadOnlySpan<char> data)
    {
        return Native.XXH3_128bits(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (nuint)(data.Length * 2));
    }

    public static XXH128_hash_t XXHash3_128(ReadOnlySpan<byte> data, ulong seed)
    {
        return Native.XXH3_128bits_withSeed(ref MemoryMarshal.GetReference(data), (nuint)data.Length, seed);
    }

    public static XXH128_hash_t XXHash3_128(ReadOnlySpan<char> data, ulong seed)
    {
        return Native.XXH3_128bits_withSeed(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (nuint)(data.Length * 2), seed);
    }
}
