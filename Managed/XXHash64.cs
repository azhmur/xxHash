using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XXHash.Managed
{
    [SkipLocalsInit]
    public static class XXHash64
    {
        ////static xxh_u64 XXH64_round(xxh_u64 acc, xxh_u64 input)
        ////{
        ////    acc += input * XXH_PRIME64_2;
        ////    acc = XXH_rotl64(acc, 31);
        ////    acc *= XXH_PRIME64_1;
        ////    return acc;
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static ulong XXH64_round(ulong acc, ulong input)
        {
            acc += input * XXHashShared.XXH_PRIME64_2;
            acc = BitOperations.RotateLeft(acc, 31);
            acc *= XXHashShared.XXH_PRIME64_1;
            return acc;
        }

        ////static xxh_u64 XXH64_mergeRound(xxh_u64 acc, xxh_u64 val)
        ////{
        ////    val = XXH64_round(0, val);
        ////    acc ^= val;
        ////    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
        ////    return acc;
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static ulong XXH64_mergeRound(ulong acc, ulong val)
        {
            val = XXH64_round(0, val);
            acc ^= val;
            acc = acc * XXHashShared.XXH_PRIME64_1 + XXHashShared.XXH_PRIME64_4;
            return acc;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong XXH64(ReadOnlySpan<char> input, ulong seed)
        {
            return XXH64(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(input)), (UIntPtr)(input.Length * 2), seed);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong XXH64(ReadOnlySpan<byte> input, ulong seed)
        {
            return XXH64(ref MemoryMarshal.GetReference(input), (UIntPtr)input.Length, seed);
        }

        ////XXH_PUBLIC_API XXH64_hash_t XXH64 (const void* input, size_t len, XXH64_hash_t seed)
        ////{
        ////#if 0
        ////    /* Simple version, good for code maintenance, but unfortunately slow for small inputs */
        ////    XXH64_state_t state;
        ////    XXH64_reset(&state, seed);
        ////    XXH64_update(&state, (const xxh_u8*)input, len);
        ////    return XXH64_digest(&state);
        ////#else
        ////    if (XXH_FORCE_ALIGN_CHECK) {
        ////        if ((((size_t)input) & 7)==0) {  /* Input is aligned, let's leverage the speed advantage */
        ////            return XXH64_endian_align((const xxh_u8*)input, len, seed, XXH_aligned);
        ////    }   }

        ////    return XXH64_endian_align((const xxh_u8*)input, len, seed, XXH_unaligned);

        ////#endif
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH64(ref byte input, UIntPtr len, ulong seed)
        {
            return XXH64_endian_align(ref input, len, seed);
        }

        ////XXH_FORCE_INLINE XXH_PUREF xxh_u64
        ////XXH64_endian_align(const xxh_u8* input, size_t len, xxh_u64 seed, XXH_alignment align)
        ////{
        ////    xxh_u64 h64;
        ////    if (input==NULL) XXH_ASSERT(len == 0);

        ////    if (len>=32) {
        ////        const xxh_u8* const bEnd = input + len;
        ////        const xxh_u8* const limit = bEnd - 31;
        ////        xxh_u64 v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        ////        xxh_u64 v2 = seed + XXH_PRIME64_2;
        ////        xxh_u64 v3 = seed + 0;
        ////        xxh_u64 v4 = seed - XXH_PRIME64_1;

        ////        do {
        ////            v1 = XXH64_round(v1, XXH_get64bits(input)); input+=8;
        ////            v2 = XXH64_round(v2, XXH_get64bits(input)); input+=8;
        ////            v3 = XXH64_round(v3, XXH_get64bits(input)); input+=8;
        ////            v4 = XXH64_round(v4, XXH_get64bits(input)); input+=8;
        ////        } while (input<limit);

        ////        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
        ////        h64 = XXH64_mergeRound(h64, v1);
        ////        h64 = XXH64_mergeRound(h64, v2);
        ////        h64 = XXH64_mergeRound(h64, v3);
        ////        h64 = XXH64_mergeRound(h64, v4);

        ////    } else {
        ////        h64  = seed + XXH_PRIME64_5;
        ////    }

        ////    h64 += (xxh_u64) len;

        ////    return XXH64_finalize(h64, input, len, align);
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static ulong XXH64_endian_align(ref byte input, nuint len, ulong seed)
        {
            ulong h64;

            if (len >= 32)
            {
                ref var limit = ref Unsafe.AddByteOffset(ref input, len - 31);

                var v1 = seed + XXHashShared.XXH_PRIME64_1 + XXHashShared.XXH_PRIME64_2;
                var v2 = seed + XXHashShared.XXH_PRIME64_2;
                var v3 = seed + 0;
                var v4 = seed - XXHashShared.XXH_PRIME64_1;

                do
                {
                    v1 = XXH64_round(v1, Unsafe.ReadUnaligned<ulong>(ref input));
                    v2 = XXH64_round(v2, Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, 8)));
                    v3 = XXH64_round(v3, Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, 16)));
                    v4 = XXH64_round(v4, Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, 24)));
                    input = ref Unsafe.AddByteOffset(ref input, 32);
                }
                while (Unsafe.IsAddressLessThan(ref input, ref limit));

                h64 = BitOperations.RotateLeft(v1, 1) + BitOperations.RotateLeft(v2, 7) + BitOperations.RotateLeft(v3, 12) + BitOperations.RotateLeft(v4, 18);
                h64 = XXH64_mergeRound(h64, v1);
                h64 = XXH64_mergeRound(h64, v2);
                h64 = XXH64_mergeRound(h64, v3);
                h64 = XXH64_mergeRound(h64, v4);
            }
            else
            {
                h64 = seed + XXHashShared.XXH_PRIME64_5;
            }

            h64 += len;

            return XXH64_finalize(h64, ref input, len);
        }

        ////static XXH_PUREF xxh_u64
        ////XXH64_finalize(xxh_u64 h64, const xxh_u8* ptr, size_t len, XXH_alignment align)
        ////{
        ////    if (ptr==NULL) XXH_ASSERT(len == 0);
        ////    len &= 31;
        ////    while (len >= 8) {
        ////        xxh_u64 const k1 = XXH64_round(0, XXH_get64bits(ptr));
        ////        ptr += 8;
        ////        h64 ^= k1;
        ////        h64  = XXH_rotl64(h64,27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        ////        len -= 8;
        ////    }
        ////    if (len >= 4) {
        ////        h64 ^= (xxh_u64)(XXH_get32bits(ptr)) * XXH_PRIME64_1;
        ////        ptr += 4;
        ////        h64 = XXH_rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        ////        len -= 4;
        ////    }
        ////    while (len > 0) {
        ////        h64 ^= (*ptr++) * XXH_PRIME64_5;
        ////        h64 = XXH_rotl64(h64, 11) * XXH_PRIME64_1;
        ////        --len;
        ////    }
        ////    return  XXH64_avalanche(h64);
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static ulong XXH64_finalize(ulong h64, ref byte input, nuint len)
        {
            len &= 31;

            switch (len)
            {
                case 32:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    break;
                case 31:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 28), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 29), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 30), h64);
                    break;
                case 30:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 28), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 29), h64);
                    break;
                case 29:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 28), h64);
                    break;
                case 28:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    break;
                case 27:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 25), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 26), h64);
                    break;
                case 26:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 25), h64);
                    break;
                case 25:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 24), h64);
                    break;
                case 24:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    break;
                case 23:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 20), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 21), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 22), h64);
                    break;
                case 22:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 20), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 21), h64);
                    break;
                case 21:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 20), h64);
                    break;
                case 20:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    break;
                case 19:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 17), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 18), h64);
                    break;
                case 18:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 17), h64);
                    break;
                case 17:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 16), h64);
                    break;
                case 16:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume8(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    break;
                case 15:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 12), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 13), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 14), h64);
                    break;
                case 14:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 12), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 13), h64);
                    break;
                case 13:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 12), h64);
                    break;
                case 12:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume4(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    break;
                case 11:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 9), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 10), h64);
                    break;
                case 10:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 9), h64);
                    break;
                case 9:
                    h64 = Consume8(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 8), h64);
                    break;
                case 8:
                    h64 = Consume8(ref input, h64);
                    break;
                case 7:
                    h64 = Consume4(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 4), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 5), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 6), h64);
                    break;
                case 6:
                    h64 = Consume4(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 4), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 5), h64);
                    break;
                case 5:
                    h64 = Consume4(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 4), h64);
                    break;
                case 4:
                    h64 = Consume4(ref input, h64);
                    break;
                case 3:
                    h64 = Consume1(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 1), h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 2), h64);
                    break;
                case 2:
                    h64 = Consume1(ref input, h64);
                    h64 = Consume1(ref Unsafe.AddByteOffset(ref input, 1), h64);
                    break;
                case 1:
                    h64 = Consume1(ref input, h64);
                    break;
            }

            return XXHashShared.XXH64_avalanche(h64);

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static ulong Consume8(ref byte input, ulong acc)
            {
                acc ^= XXH64_round(0, Unsafe.ReadUnaligned<ulong>(ref input));
                return BitOperations.RotateLeft(acc, 27) * XXHashShared.XXH_PRIME64_1 + XXHashShared.XXH_PRIME64_4;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static ulong Consume4(ref byte input, ulong acc)
            {
                acc ^= Unsafe.ReadUnaligned<uint>(ref input) * XXHashShared.XXH_PRIME64_1;
                return BitOperations.RotateLeft(acc, 23) * XXHashShared.XXH_PRIME64_2 + XXHashShared.XXH_PRIME64_3;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static ulong Consume1(ref byte input, ulong acc)
            {
                acc ^= input * XXHashShared.XXH_PRIME64_5;
                return BitOperations.RotateLeft(acc, 11) * XXHashShared.XXH_PRIME64_1;
            }
        }
    }
}
