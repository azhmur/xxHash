using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using static System.Runtime.Intrinsics.Arm.ArmBase;

namespace XXHash.Managed;

[SkipLocalsInit]
public static unsafe class XXHashShared
{
    public const uint XXH_STRIPE_LEN = 64;
    public const uint XXH_SECRET_CONSUME_RATE = 8;
    public const uint XXH_ACC_NB = XXH_STRIPE_LEN / sizeof(ulong);
    public const uint XXH3_SECRET_SIZE_MIN = 136;
    public const uint XXH_SECRET_DEFAULT_SIZE = 192;
    public const uint XXH3_MIDSIZE_STARTOFFSET = 3;
    public const uint XXH3_MIDSIZE_LASTOFFSET = 17;
    public const uint XXH_SECRET_MERGEACCS_START = 11;
    public const uint XXH3_INTERNALBUFFER_SIZE = 256;

    public static ReadOnlySpan<byte> XXH3_kSecret => new byte[] {
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
        0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
        0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
        0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
        0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
        0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
        0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
        0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
        0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
        0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
        0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
        0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    };

    public static ReadOnlySpan<ulong> XXH3_INIT_ACC => new ulong[] { XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3, XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1 };

    public const ulong XXH_PRIME64_1 = 0x9E3779B185EBCA87; /*!< 0b1001111000110111011110011011000110000101111010111100101010000111 */
    public const ulong XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4F; /*!< 0b1100001010110010101011100011110100100111110101001110101101001111 */
    public const ulong XXH_PRIME64_3 = 0x165667B19E3779F9; /*!< 0b0001011001010110011001111011000110011110001101110111100111111001 */
    public const ulong XXH_PRIME64_4 = 0x85EBCA77C2B2AE63; /*!< 0b1000010111101011110010100111011111000010101100101010111001100011 */
    public const ulong XXH_PRIME64_5 = 0x27D4EB2F165667C5; /*!< 0b0010011111010100111010110010111100010110010101100110011111000101 */

    public const ulong XXH_PRIME32_1 = 0x9E3779B1;  /*!< 0b10011110001101110111100110110001 */
    public const ulong XXH_PRIME32_2 = 0x85EBCA77;  /*!< 0b10000101111010111100101001110111 */
    public const ulong XXH_PRIME32_3 = 0xC2B2AE3D;  /*!< 0b11000010101100101010111000111101 */
    public const ulong XXH_PRIME32_4 = 0x27D4EB2F;  /*!< 0b00100111110101001110101100101111 */
    public const ulong XXH_PRIME32_5 = 0x165667B1;  /*!< 0b00010110010101100110011110110001 */

    public static readonly Vector128<uint> Prime32_128 = Vector128.Create((uint)XXH_PRIME32_1);
    public static readonly Vector256<uint> Prime32_256 = Vector256.Create((uint)XXH_PRIME32_1);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint GetSecret32(uint index)
    {
        return Unsafe.ReadUnaligned<uint>(ref Unsafe.AddByteOffset(ref MemoryMarshal.GetReference(XXH3_kSecret), index));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong GetSecret64(uint index)
    {
        return Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref MemoryMarshal.GetReference(XXH3_kSecret), index));
    }

    ////static xxh_u64 XXH64_avalanche(xxh_u64 h64)
    ////{
    ////    h64 ^= h64 >> 33;
    ////    h64 *= XXH_PRIME64_2;
    ////    h64 ^= h64 >> 29;
    ////    h64 *= XXH_PRIME64_3;
    ////    h64 ^= h64 >> 32;
    ////    return h64;
    ////}

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
    internal static ulong XXH64_avalanche(ulong h64)
    {
        h64 ^= h64 >> 33;
        h64 *= XXH_PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= XXH_PRIME64_3;
        h64 ^= h64 >> 32;
        return h64;
    }

    ////static xxh_u64
    ////XXH3_mul128_fold64(xxh_u64 lhs, xxh_u64 rhs)
    ////{
    ////    XXH128_hash_t product = XXH_mult64to128(lhs, rhs);
    ////    return product.low64 ^ product.high64;
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong XXH3_mul128_fold64(ulong lhs, ulong rhs)
    {
        var hash128 = XXH3_mul128(lhs, rhs);
        return hash128.Low ^ hash128.High;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static XXH128Hash XXH3_mul128(ulong lhs, ulong rhs)
    {
        ulong lowHalf;
        ulong highHalf;

        if (Bmi2.X64.IsSupported)
        {
            highHalf = Bmi2.X64.MultiplyNoFlags(lhs, rhs, &lowHalf);
        }
        else if (Arm64.IsSupported)
        {
            lowHalf = lhs * rhs;
            highHalf = Arm64.MultiplyHigh(lhs, rhs);
        }
        else
        {
            /* First calculate all of the cross products. */
            var lo_lo = XXH_mult32to64(lhs & 0xFFFFFFFF, rhs & 0xFFFFFFFF);
            var hi_lo = XXH_mult32to64(lhs >> 32, rhs & 0xFFFFFFFF);
            var lo_hi = XXH_mult32to64(lhs & 0xFFFFFFFF, rhs >> 32);
            var hi_hi = XXH_mult32to64(lhs >> 32, rhs >> 32);

            /* Now add the products together. These will never overflow. */
            var cross = (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi;
            highHalf = (hi_lo >> 32) + (cross >> 32) + hi_hi;
            lowHalf = (cross << 32) | (lo_lo & 0xFFFFFFFF);
        }

        return new XXH128Hash()
        {
            Low = lowHalf,
            High = highHalf
        };
    }

    ////XXH_FORCE_INLINE xxh_u64
    ////XXH_mult32to64(xxh_u64 x, xxh_u64 y)
    ////{
    ////    return (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF);
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong XXH_mult32to64(ulong x, ulong y)
    {
        return (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF);
    }

    ////static XXH64_hash_t XXH3_avalanche(xxh_u64 h64)
    ////{
    ////    h64 = XXH_xorshift64(h64, 37);
    ////    h64 *= 0x165667919E3779F9ULL;
    ////    h64 = XXH_xorshift64(h64, 32);
    ////    return h64;
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong XXH3_avalanche(ulong h64)
    {
        h64 = XXH_xorshift64(h64, 37);
        h64 *= 0x165667919E3779F9;
        h64 = XXH_xorshift64(h64, 32);
        return h64;
    }

    ////static XXH64_hash_t XXH3_rrmxmx(xxh_u64 h64, xxh_u64 len)
    ////{
    ////    /* this mix is inspired by Pelle Evensen's rrmxmx */
    ////    h64 ^= XXH_rotl64(h64, 49) ^ XXH_rotl64(h64, 24);
    ////    h64 *= 0x9FB21C651E98DF25ULL;
    ////    h64 ^= (h64 >> 35) + len;
    ////    h64 *= 0x9FB21C651E98DF25ULL;
    ////    return XXH_xorshift64(h64, 28);
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong XXH3_rrmxmx(ulong h64, uint len)
    {
        h64 ^= BitOperations.RotateLeft(h64, 49) ^ BitOperations.RotateLeft(h64, 24);
        h64 *= 0x9FB21C651E98DF25;
        h64 ^= (h64 >> 35) + len;
        h64 *= 0x9FB21C651E98DF25;
        return XXH_xorshift64(h64, 28);
    }

    ////XXH_FORCE_INLINE XXH_CONSTF xxh_u64 XXH_xorshift64(xxh_u64 v64, int shift)
    ////{
    ////    XXH_ASSERT(0 <= shift && shift < 64);
    ////    return v64 ^ (v64 >> shift);
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong XXH_xorshift64(ulong v64, int shift)
    {
        return v64 ^ (v64 >> shift);
    }

    ////XXH_FORCE_INLINE xxh_u64 XXH3_mix16B(const xxh_u8* XXH_RESTRICT input,
    ////                             const xxh_u8* XXH_RESTRICT secret, xxh_u64 seed64)
    ////{
    ////#if defined(__GNUC__) && !defined(__clang__) /* GCC, not Clang */ \
    ////    && defined(__i386__) && defined(__SSE2__)  /* x86 + SSE2 */ \
    ////    && !defined(XXH_ENABLE_AUTOVECTORIZE)      /* Define to disable like XXH32 hack */
    ////    /*
    ////        * UGLY HACK:
    ////        * GCC for x86 tends to autovectorize the 128-bit multiply, resulting in
    ////        * slower code.
    ////        *
    ////        * By forcing seed64 into a register, we disrupt the cost model and
    ////        * cause it to scalarize. See `XXH32_round()`
    ////        *
    ////        * FIXME: Clang's output is still _much_ faster -- On an AMD Ryzen 3600,
    ////        * XXH3_64bits @ len=240 runs at 4.6 GB/s with Clang 9, but 3.3 GB/s on
    ////        * GCC 9.2, despite both emitting scalar code.
    ////        *
    ////        * GCC generates much better scalar code than Clang for the rest of XXH3,
    ////        * which is why finding a more optimal codepath is an interest.
    ////        */
    ////    XXH_COMPILER_GUARD(seed64);
    ////#endif
    ////    {   xxh_u64 const input_lo = XXH_readLE64(input);
    ////        xxh_u64 const input_hi = XXH_readLE64(input + 8);
    ////        return XXH3_mul128_fold64(
    ////            input_lo ^ (XXH_readLE64(secret)   + seed64),
    ////            input_hi ^ (XXH_readLE64(secret+8) - seed64)
    ////        );
    ////    }
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong XXH3_mix16B(ref byte input, uint secretIndex, ulong seed64)
    {
        var input_lo = Unsafe.ReadUnaligned<ulong>(ref input);
        var input_hi = Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, 8));

        return XXH3_mul128_fold64(
            input_lo ^ (GetSecret64(secretIndex) + seed64),
            input_hi ^ (GetSecret64(secretIndex + 8) - seed64));
    }

    ////XXH_FORCE_INLINE XXH128_hash_t
    ////XXH128_mix32B(XXH128_hash_t acc, const xxh_u8* input_1, const xxh_u8* input_2,
    ////              const xxh_u8* secret, XXH64_hash_t seed)
    ////{
    ////    acc.low64  += XXH3_mix16B (input_1, secret+0, seed);
    ////    acc.low64  ^= XXH_readLE64(input_2) + XXH_readLE64(input_2 + 8);
    ////    acc.high64 += XXH3_mix16B (input_2, secret+16, seed);
    ////    acc.high64 ^= XXH_readLE64(input_1) + XXH_readLE64(input_1 + 8);
    ////    return acc;
    ////}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static XXH128Hash XXH128_mix32B(XXH128Hash acc, ref byte input_1, ref byte input_2, uint secretOffset, ulong seed)
    {
        acc.Low += XXH3_mix16B(ref input_1, secretOffset, seed);
        acc.Low ^= Unsafe.ReadUnaligned<ulong>(ref input_2) + Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input_2, 8));
        acc.High += XXH3_mix16B(ref input_2, secretOffset + 16, seed);
        acc.High ^= Unsafe.ReadUnaligned<ulong>(ref input_1) + Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input_1, 8));
        return acc;
    }
}
