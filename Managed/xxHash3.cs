using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace xxHash3.Core
{
    public unsafe static class xxHash3
    {
        private const uint XXH_STRIPE_LEN = 64;
        private const uint XXH_SECRET_CONSUME_RATE = 8;
        private const uint XXH_ACC_NB = XXH_STRIPE_LEN / sizeof(ulong);
        private const uint XXH3_SECRET_SIZE_MIN = 136;
        private const uint XXH_SECRET_DEFAULT_SIZE = 192;


        private static ReadOnlySpan<byte> XXH3_kSecret => new byte[] {
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

        private static ReadOnlySpan<ulong> XXH3_INIT_ACC => new ulong[] { XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3, XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1};

        private const ulong XXH_PRIME64_1 = 0x9E3779B185EBCA87; /*!< 0b1001111000110111011110011011000110000101111010111100101010000111 */
        private const ulong XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4F; /*!< 0b1100001010110010101011100011110100100111110101001110101101001111 */
        private const ulong XXH_PRIME64_3 = 0x165667B19E3779F9; /*!< 0b0001011001010110011001111011000110011110001101110111100111111001 */
        private const ulong XXH_PRIME64_4 = 0x85EBCA77C2B2AE63; /*!< 0b1000010111101011110010100111011111000010101100101010111001100011 */
        private const ulong XXH_PRIME64_5 = 0x27D4EB2F165667C5; /*!< 0b0010011111010100111010110010111100010110010101100110011111000101 */

        private const ulong XXH_PRIME32_1 = 0x9E3779B1;  /*!< 0b10011110001101110111100110110001 */
        private const ulong XXH_PRIME32_2 = 0x85EBCA77;  /*!< 0b10000101111010111100101001110111 */
        private const ulong XXH_PRIME32_3 = 0xC2B2AE3D;  /*!< 0b11000010101100101010111000111101 */
        private const ulong XXH_PRIME32_4 = 0x27D4EB2F;  /*!< 0b00100111110101001110101100101111 */
        private const ulong XXH_PRIME32_5 = 0x165667B1;  /*!< 0b00010110010101100110011110110001 */

        private static readonly Vector128<uint> Prime32 = Vector128.Create((uint)XXH_PRIME32_1);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint GetSecret32(uint index)
        {
            return Unsafe.ReadUnaligned<uint>(ref Unsafe.AddByteOffset(ref MemoryMarshal.GetReference(XXH3_kSecret), index));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong GetSecret64(uint index)
        {
            return Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref MemoryMarshal.GetReference(XXH3_kSecret), index));
        }

        /*XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
        XXH3_len_0to16_64b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        {
            XXH_ASSERT(len <= 16);
            {   if (XXH_likely(len >  8)) return XXH3_len_9to16_64b(input, len, secret, seed);
                if (XXH_likely(len >= 4)) return XXH3_len_4to8_64b(input, len, secret, seed);
                if (len) return XXH3_len_1to3_64b(input, len, secret, seed);
                return XXH64_avalanche(seed ^ (XXH_readLE64(secret+56) ^ XXH_readLE64(secret+64)));
            }
        }
        */
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong XXH3_len_0to16_64b(ref byte input, uint len, ulong seed)
        {
            if (len > 8) return XXH3_len_9to16_64b(ref input, len, seed);
            if (len >= 4) return XXH3_len_4to8_64b(ref input, len, seed);
            if (len != 0) return XXH3_len_1to3_64b(ref input, len, seed);
            return XXH64_avalanche(seed);
        }

        /*static xxh_u64 XXH64_avalanche(xxh_u64 h64)
        {
            h64 ^= h64 >> 33;
            h64 *= XXH_PRIME64_2;
            h64 ^= h64 >> 29;
            h64 *= XXH_PRIME64_3;
            h64 ^= h64 >> 32;
            return h64;
        }
        */
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH64_avalanche(ulong h64)
        {
            h64 ^= h64 >> 33;
            h64 *= XXH_PRIME64_2;
            h64 ^= h64 >> 29;
            h64 *= XXH_PRIME64_3;
            h64 ^= h64 >> 32;
            return h64;
        }

        ////static XXH64_hash_t XXH3_avalanche(xxh_u64 h64)
        ////{
        ////    h64 = XXH_xorshift64(h64, 37);
        ////    h64 *= 0x165667919E3779F9ULL;
        ////    h64 = XXH_xorshift64(h64, 32);
        ////    return h64;
        ////}
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_avalanche(ulong h64)
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
        private static ulong XXH3_rrmxmx(ulong h64, uint len)
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
        private static ulong XXH_xorshift64(ulong v64, int shift)
        {
            return v64 ^ (v64 >> shift);
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
        ////XXH3_len_1to3_64b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(input != NULL);
        ////        XXH_ASSERT(1 <= len && len <= 3);
        ////        XXH_ASSERT(secret != NULL);
        ////    /*
        ////     * len = 1: combined = { input[0], 0x01, input[0], input[0] }
        ////     * len = 2: combined = { input[1], 0x02, input[0], input[1] }
        ////     * len = 3: combined = { input[2], 0x03, input[0], input[1] }
        ////     */
        ////    {   xxh_u8 const c1 = input[0];
        ////        xxh_u8 const c2 = input[len >> 1];
        ////        xxh_u8 const c3 = input[len - 1];
        ////        xxh_u32 const combined = ((xxh_u32)c1 << 16) | ((xxh_u32)c2 << 24)
        ////                               | ((xxh_u32)c3 << 0) | ((xxh_u32)len << 8);
        ////        xxh_u64 const bitflip = (XXH_readLE32(secret) ^ XXH_readLE32(secret + 4)) + seed;
        ////        xxh_u64 const keyed = (xxh_u64)combined ^ bitflip;
        ////        return XXH64_avalanche(keyed);
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_1to3_64b(ref byte input, uint len, ulong seed)
        {
            byte c1 = Unsafe.ReadUnaligned<byte>(ref input);
            byte c2 = Unsafe.ReadUnaligned<byte>(ref Unsafe.AddByteOffset(ref input, len >> 1));
            byte c3 = Unsafe.ReadUnaligned<byte>(ref Unsafe.AddByteOffset(ref input, len - 1));

            uint combined = ((uint)c1 << 16) | ((uint)c2 << 24) | ((uint)c3 << 0) | ((uint)len << 8);
            ulong bitflip = (GetSecret32(0) ^ GetSecret32(4)) + seed;
            ulong keyed = (ulong)combined ^ bitflip;
            return XXH64_avalanche(keyed);
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
        ////XXH3_len_4to8_64b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(input != NULL);
        ////        XXH_ASSERT(secret != NULL);
        ////        XXH_ASSERT(4 <= len && len <= 8);
        ////        seed ^= (xxh_u64) XXH_swap32((xxh_u32) seed) << 32;
        ////    {   xxh_u32 const input1 = XXH_readLE32(input);
        ////        xxh_u32 const input2 = XXH_readLE32(input + len - 4);
        ////        xxh_u64 const bitflip = (XXH_readLE64(secret + 8) ^ XXH_readLE64(secret + 16)) - seed;
        ////        xxh_u64 const input64 = input2 + (((xxh_u64)input1) << 32);
        ////        xxh_u64 const keyed = input64 ^ bitflip;
        ////        return XXH3_rrmxmx(keyed, len);
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_4to8_64b(ref byte input, uint len, ulong seed)
        {
            seed ^= (ulong)BinaryPrimitives.ReverseEndianness((uint)seed) << 32;
            uint input1 = Unsafe.ReadUnaligned<uint>(ref input);
            uint input2 = Unsafe.ReadUnaligned<uint>(ref Unsafe.AddByteOffset(ref input, len - 4));
            ulong bitflip = (GetSecret64(8) ^ GetSecret64(16)) - seed;
            ulong input64 = input2 + (((ulong)input1) << 32);
            ulong keyed = input64 ^ bitflip;
            return XXH3_rrmxmx(keyed, len);
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
        ////XXH3_len_9to16_64b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(input != NULL);
        ////        XXH_ASSERT(secret != NULL);
        ////        XXH_ASSERT(9 <= len && len <= 16);
        ////    {   xxh_u64 const bitflip1 = (XXH_readLE64(secret + 24) ^ XXH_readLE64(secret + 32)) + seed;
        ////        xxh_u64 const bitflip2 = (XXH_readLE64(secret + 40) ^ XXH_readLE64(secret + 48)) - seed;
        ////        xxh_u64 const input_lo = XXH_readLE64(input) ^ bitflip1;
        ////        xxh_u64 const input_hi = XXH_readLE64(input + len - 8) ^ bitflip2;
        ////        xxh_u64 const acc = len
        ////                          + XXH_swap64(input_lo) + input_hi
        ////                          + XXH3_mul128_fold64(input_lo, input_hi);
        ////        return XXH3_avalanche(acc);
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_9to16_64b(ref byte input, uint len, ulong seed)
        {
            ulong bitflip1 = (GetSecret64(24) ^ GetSecret64(32)) + seed;
            ulong bitflip2 = (GetSecret64(40) ^ GetSecret64(48)) - seed;
            ulong input_lo = Unsafe.ReadUnaligned<ulong>(ref input) ^ bitflip1;
            ulong input_hi = Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, len - 8)) ^ bitflip2;
            ulong acc = len
                + BinaryPrimitives.ReverseEndianness(input_lo) + input_hi
                + XXH3_mul128_fold64(input_lo, input_hi);
            return XXH3_avalanche(acc);
        }

        ////static xxh_u64
        ////XXH3_mul128_fold64(xxh_u64 lhs, xxh_u64 rhs)
        ////{
        ////    XXH128_hash_t product = XXH_mult64to128(lhs, rhs);
        ////    return product.low64 ^ product.high64;
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_mul128_fold64(ulong lhs, ulong rhs)
        {
            ulong lowHalf;
            ulong highHalf = System.Runtime.Intrinsics.X86.Bmi2.X64.MultiplyNoFlags(lhs, rhs, &lowHalf);
            return lowHalf ^ highHalf;
        }

        ////XXH_FORCE_INLINE xxh_u64
        ////XXH_mult32to64(xxh_u64 x, xxh_u64 y)
        ////{
        ////    return (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF);
        ////}

        private static ulong XXH_mult32to64(ulong x, ulong y)
        {
            return (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF);
        }

        ////XXH_FORCE_INLINE void
        ////XXH3_scalarRound(void* XXH_RESTRICT acc,
        ////                 void const* XXH_RESTRICT input,
        ////                 void const* XXH_RESTRICT secret,
        ////                 size_t lane)
        ////{
        ////    xxh_u64* xacc = (xxh_u64*)acc;
        ////    xxh_u8 const* xinput = (xxh_u8 const*) input;
        ////    xxh_u8 const* xsecret = (xxh_u8 const*) secret;
        ////    XXH_ASSERT(lane<XXH_ACC_NB);
        ////        XXH_ASSERT(((size_t) acc & (XXH_ACC_ALIGN-1)) == 0);
        ////    {
        ////        xxh_u64 const data_val = XXH_readLE64(xinput + lane * 8);
        ////        xxh_u64 const data_key = data_val ^ XXH_readLE64(xsecret + lane * 8);
        ////        xacc[lane ^ 1] += data_val; /* swap adjacent lanes */
        ////        xacc[lane] += XXH_mult32to64(data_key & 0xFFFFFFFF, data_key >> 32);
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void XXH3_scalarRound(ref ulong acc, ref byte input, ref ulong secret, uint lane)
        {
            ulong data_val = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref input, lane * 8));
            ulong data_key = data_val ^ Unsafe.Add(ref secret, lane);
            Unsafe.Add(ref acc, lane ^1) += data_val;
            Unsafe.Add(ref acc, lane) += XXH_mult32to64(data_key & 0xFFFFFFFF, data_key >> 32);
        }

        /////*!
        //// * @internal
        //// * @brief Processes a 64 byte block of data using the scalar path.
        //// */
        ////XXH_FORCE_INLINE void
        ////XXH3_accumulate_512_scalar(void* XXH_RESTRICT acc,
        ////                         const void* XXH_RESTRICT input,
        ////                         const void* XXH_RESTRICT secret)
        ////{
        ////    size_t i;
        ////    /* ARM GCC refuses to unroll this loop, resulting in a 24% slowdown on ARMv6. */
        ////    #if defined(__GNUC__) && !defined(__clang__) \
        ////        && (defined(__arm__) || defined(__thumb2__)) \
        ////        && defined(__ARM_FEATURE_UNALIGNED) /* no unaligned access just wastes bytes */ \
        ////        && !defined(__OPTIMIZE_SIZE__)
        ////    #  pragma GCC unroll 8
        ////    #endif
        ////    for (i=0; i<XXH_ACC_NB; i++) {
        ////        XXH3_scalarRound(acc, input, secret, i);
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_accumulate_512_scalar(ref ulong acc, ref byte input, ref ulong secret)
        {
            //for (uint i = 0; i < XXH_ACC_NB; i++)
            //{
            //    XXH3_scalarRound(ref acc, ref input, ref secret, i);
            //}
            XXH3_scalarRound(ref acc, ref input, ref secret, 0);
            XXH3_scalarRound(ref acc, ref input, ref secret, 1);
            XXH3_scalarRound(ref acc, ref input, ref secret, 2);
            XXH3_scalarRound(ref acc, ref input, ref secret, 3);
            XXH3_scalarRound(ref acc, ref input, ref secret, 4);
            XXH3_scalarRound(ref acc, ref input, ref secret, 5);
            XXH3_scalarRound(ref acc, ref input, ref secret, 6);
            XXH3_scalarRound(ref acc, ref input, ref secret, 7);
        }

        /////*
        //// * XXH3_accumulate()
        //// * Loops over XXH3_accumulate_512().
        //// * Assumption: nbStripes will not overflow the secret size
        //// */
        ////XXH_FORCE_INLINE void
        ////XXH3_accumulate(xxh_u64* XXH_RESTRICT acc,
        ////        const xxh_u8* XXH_RESTRICT input,
        ////        const xxh_u8* XXH_RESTRICT secret,
        ////              size_t nbStripes,
        ////              XXH3_f_accumulate_512 f_acc512)
        ////{
        ////    size_t n;
        ////    for (n = 0; n<nbStripes; n++ ) {
        ////        const xxh_u8* const in = input + n* XXH_STRIPE_LEN;
        ////        XXH_PREFETCH(in + XXH_PREFETCH_DIST);
        ////        f_acc512(acc,
        ////                 in,
        ////                 secret + n* XXH_SECRET_CONSUME_RATE);
        ////    }
        ////}

        private static void XXH3_accumulate(ref ulong acc, ref byte input, ref ulong secret, uint nbStripes)
        {
            for (uint n = 0; n < nbStripes; n++)
            {
                ref byte inp = ref Unsafe.AddByteOffset(ref input, n * XXH_STRIPE_LEN);
                XXH3_accumulate_512(ref acc, ref inp, ref Unsafe.AddByteOffset(ref secret, n * XXH_SECRET_CONSUME_RATE));
            }
        }

        /*!
         * @internal
         * @brief Scalar scramble step for @ref XXH3_scrambleAcc_scalar().
         *
         * This is extracted to its own function because the NEON path uses a combination
         * of NEON and scalar.
         */
        ////XXH_FORCE_INLINE void
        ////XXH3_scalarScrambleRound(void* XXH_RESTRICT acc,
        ////                         void const* XXH_RESTRICT secret,
        ////                     size_t lane)
        ////{
        ////    xxh_u64* const xacc = (xxh_u64*)acc;   /* presumed aligned */
        ////        const xxh_u8* const xsecret = (const xxh_u8*) secret;   /* no alignment restriction */
        ////    XXH_ASSERT((((size_t) acc) & (XXH_ACC_ALIGN-1)) == 0);
        ////    XXH_ASSERT(lane<XXH_ACC_NB);
        ////    {
        ////        xxh_u64 const key64 = XXH_readLE64(xsecret + lane * 8);
        ////        xxh_u64 acc64 = xacc[lane];
        ////        acc64 = XXH_xorshift64(acc64, 47);
        ////        acc64 ^= key64;
        ////        acc64 *= XXH_PRIME32_1;
        ////        xacc[lane] = acc64;
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_scalarScrambleRound(ref ulong acc, uint lane, ref ulong secret)
        {
            ulong key64 = Unsafe.Add(ref secret, lane);
            ulong acc64 = Unsafe.Add(ref acc, lane);
            acc64 = XXH_xorshift64(acc64, 47);
            acc64 ^= key64;
            acc64 *= XXH_PRIME32_1;
            Unsafe.Add(ref acc, lane) = acc64;
        }

        /////*!
        //// * @internal
        //// * @brief Scrambles the accumulators after a large chunk has been read
        //// */
        ////XXH_FORCE_INLINE void
        ////XXH3_scrambleAcc_scalar(void* XXH_RESTRICT acc, const void* XXH_RESTRICT secret)
        ////{
        ////    size_t i;
        ////    for (i=0; i<XXH_ACC_NB; i++) {
        ////        XXH3_scalarScrambleRound(acc, secret, i);
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_scrambleAcc_scalar(ref ulong acc, ref ulong secret)
        {
            ////for (uint i = 0; i < XXH_ACC_NB; ++i)
            ////{
            ////    XXH3_scalarScrambleRound(ref acc, i, ref secret);
            ////}

            XXH3_scalarScrambleRound(ref acc, 0, ref secret);
            XXH3_scalarScrambleRound(ref acc, 1, ref secret);
            XXH3_scalarScrambleRound(ref acc, 2, ref secret);
            XXH3_scalarScrambleRound(ref acc, 3, ref secret);
            XXH3_scalarScrambleRound(ref acc, 4, ref secret);
            XXH3_scalarScrambleRound(ref acc, 5, ref secret);
            XXH3_scalarScrambleRound(ref acc, 6, ref secret);
            XXH3_scalarScrambleRound(ref acc, 7, ref secret);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_scrambleAcc(ref ulong acc, ref ulong secret)
        {
            if (Sse2.IsSupported)
            {
                XXH3_scrambleAcc_sse2(ref acc, ref secret);
            }
            else
            {
                XXH3_scrambleAcc_scalar(ref acc, ref secret);
            }
        }


        ////XXH_FORCE_INLINE XXH64_hash_t
        ////XXH3_64bits_internal(const void* XXH_RESTRICT input, size_t len,
        ////                     XXH64_hash_t seed64, const void* XXH_RESTRICT secret, size_t secretLen,
        ////                     XXH3_hashLong64_f f_hashLong)
        ////{
        ////    XXH_ASSERT(secretLen >= XXH3_SECRET_SIZE_MIN);
        ////    /*
        ////     * If an action is to be taken if `secretLen` condition is not respected,
        ////     * it should be done here.
        ////     * For now, it's a contract pre-condition.
        ////     * Adding a check and a branch here would cost performance at every hash.
        ////     * Also, note that function signature doesn't offer room to return an error.
        ////     */
        ////    if (len <= 16)
        ////        return XXH3_len_0to16_64b((const xxh_u8*)input, len, (const xxh_u8*)secret, seed64);
        ////    if (len <= 128)
        ////        return XXH3_len_17to128_64b((const xxh_u8*)input, len, (const xxh_u8*)secret, secretLen, seed64);
        ////    if (len <= XXH3_MIDSIZE_MAX)
        ////        return XXH3_len_129to240_64b((const xxh_u8*)input, len, (const xxh_u8*)secret, secretLen, seed64);
        ////    return f_hashLong(input, len, seed64, (const xxh_u8*)secret, secretLen);
        ////}

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static ulong XXH3(ref byte input, uint len, ulong seed64)
        {
            if (len <= 16)
            {
                return XXH3_len_0to16_64b(ref input, len, seed64);
            }
            if (len <= 128)
            {
                return XXH3_len_17to128_64b(ref input, len, seed64);
            }
            if (len <= 240)
            {
                return XXH3_len_129to240_64b(ref input, len, seed64);
            }

            return XXH3_long(ref input, len, seed64);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        [SkipLocalsInit]
        public static ulong XXH3_long(ref byte input, uint len, ulong seed64)
        {
            if (seed64 == 0)
            {
                return XXH3_hashLong_64b_internal(ref input, len, ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(XXH3_kSecret)), XXH_SECRET_DEFAULT_SIZE);
            }
            else
            {
                Span<ulong> customSecret = stackalloc ulong[(int)XXH_SECRET_DEFAULT_SIZE / sizeof(ulong)];
                Unsafe.CopyBlockUnaligned(ref Unsafe.As<ulong, byte>(ref MemoryMarshal.GetReference(customSecret)), ref MemoryMarshal.GetReference(XXH3_kSecret), XXH_SECRET_DEFAULT_SIZE);
                //XXH3_kSecret.CopyTo(MemoryMarshal.Cast<ulong, byte>(customSecret));
                XXH3_initCustomSecret_scalar(ref MemoryMarshal.GetReference(customSecret), seed64);
                return XXH3_hashLong_64b_internal(ref input, len, ref MemoryMarshal.GetReference(customSecret), XXH_SECRET_DEFAULT_SIZE);
            }
        }

        /////* For mid range keys, XXH3 uses a Mum-hash variant. */
        ////XXH_FORCE_INLINE XXH_PUREF XXH64_hash_t
        ////XXH3_len_17to128_64b(const xxh_u8* XXH_RESTRICT input, size_t len,
        ////             const xxh_u8* XXH_RESTRICT secret, size_t secretSize,
        ////             XXH64_hash_t seed)
        ////{
        ////    xxh_u64 acc = len * XXH_PRIME64_1;
        ////    if (len > 32) {
        ////        if (len > 64) {
        ////            if (len > 96) {
        ////                acc += XXH3_mix16B(input+48, secret+96, seed);
        ////                acc += XXH3_mix16B(input+len-64, secret+112, seed);
        ////            }
        ////            acc += XXH3_mix16B(input+32, secret+64, seed);
        ////            acc += XXH3_mix16B(input+len-48, secret+80, seed);
        ////        }
        ////        acc += XXH3_mix16B(input + 16, secret + 32, seed);
        ////        acc += XXH3_mix16B(input + len - 32, secret + 48, seed);
        ////    }
        ////    acc += XXH3_mix16B(input + 0, secret + 0, seed);
        ////    acc += XXH3_mix16B(input + len - 16, secret + 16, seed);

        ////    return XXH3_avalanche(acc);
        ////}

        private static ulong XXH3_len_17to128_64b(ref byte input, uint len, ulong seed)
        {
            ulong acc = len * XXH_PRIME64_1;
            if (len > 32) {
                if (len > 64) {
                    if (len > 96) {
                        acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 48), 96, seed);
                        acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 64), 112, seed);
                    }
                    acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 32), 64, seed);
                    acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 48), 80, seed);
                }
                acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 16), 32, seed);
                acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 32), 48, seed);
            }
            acc += XXH3_mix16B(ref input, 0, seed);
            acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 16), 16, seed);

            return XXH3_avalanche(acc);
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
        private static ulong XXH3_mix16B(ref byte input, uint secretIndex, ulong seed64)
        {
            var input_lo = Unsafe.ReadUnaligned<ulong>(ref input);
            var input_hi = Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, 8));

            return XXH3_mul128_fold64(
                input_lo ^ (GetSecret64(secretIndex) + seed64),
                input_hi ^ (GetSecret64(secretIndex + 8) - seed64));
        }

        ////XXH_NO_INLINE XXH_PUREF XXH64_hash_t
        ////XXH3_len_129to240_64b(const xxh_u8* XXH_RESTRICT input, size_t len,
        ////                      const xxh_u8* XXH_RESTRICT secret, size_t secretSize,
        ////                      XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
        ////    XXH_ASSERT(128 < len && len <= XXH3_MIDSIZE_MAX);

        ////    #define XXH3_MIDSIZE_STARTOFFSET 3
        ////    #define XXH3_MIDSIZE_LASTOFFSET  17

        ////    {   xxh_u64 acc = len * XXH_PRIME64_1;
        ////        int const nbRounds = (int)len / 16;
        ////        int i;
        ////        for (i=0; i<8; i++) {
        ////            acc += XXH3_mix16B(input+(16*i), secret+(16*i), seed);
        ////        }
        ////        acc = XXH3_avalanche(acc);
        ////        XXH_ASSERT(nbRounds >= 8);
        ////        #if defined(__clang__)                                /* Clang */ \
        ////            && (defined(__ARM_NEON) || defined(__ARM_NEON__)) /* NEON */ \
        ////            && !defined(XXH_ENABLE_AUTOVECTORIZE)             /* Define to disable */
        ////        /*
        ////         * UGLY HACK:
        ////         * Clang for ARMv7-A tries to vectorize this loop, similar to GCC x86.
        ////         * In everywhere else, it uses scalar code.
        ////         *
        ////         * For 64->128-bit multiplies, even if the NEON was 100% optimal, it
        ////         * would still be slower than UMAAL (see XXH_mult64to128).
        ////         *
        ////         * Unfortunately, Clang doesn't handle the long multiplies properly and
        ////         * converts them to the nonexistent "vmulq_u64" intrinsic, which is then
        ////         * scalarized into an ugly mess of VMOV.32 instructions.
        ////         *
        ////         * This mess is difficult to avoid without turning autovectorization
        ////         * off completely, but they are usually relatively minor and/or not
        ////         * worth it to fix.
        ////         *
        ////         * This loop is the easiest to fix, as unlike XXH32, this pragma
        ////         * _actually works_ because it is a loop vectorization instead of an
        ////         * SLP vectorization.
        ////         */
        ////        #pragma clang loop vectorize(disable)
        ////        #endif
        ////        for (i=8 ; i < nbRounds; i++) {
        ////            acc += XXH3_mix16B(input+(16*i), secret+(16*(i-8)) + XXH3_MIDSIZE_STARTOFFSET, seed);
        ////        }
        ////        /* last bytes */
        ////        acc += XXH3_mix16B(input + len - 16, secret + XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET, seed);
        ////        return XXH3_avalanche(acc);
        ////    }
        ////}

        private static ulong XXH3_len_129to240_64b(
            ref byte input,
            uint len,
            ulong seed)
        {
            const int XXH3_MIDSIZE_STARTOFFSET = 3;
            const int XXH3_MIDSIZE_LASTOFFSET = 17;

            ulong acc = len * XXH_PRIME64_1;
            int nbRounds = (int)len / 16;

            for (uint i = 0; i < 8; i++) 
            {
                acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 16 * i), 16 * i, seed);
            }

            acc = XXH3_avalanche(acc);

            for (uint i = 8; i < nbRounds; i++)
            {
                acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 16 * i), (16 * (i - 8)) + XXH3_MIDSIZE_STARTOFFSET, seed);
            }

            /* last bytes */
            acc += XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 16), XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET, seed);
            return XXH3_avalanche(acc);
        }


        ////XXH_FORCE_INLINE xxh_u64
        ////XXH3_mix2Accs(const xxh_u64* XXH_RESTRICT acc, const xxh_u8* XXH_RESTRICT secret)
        ////{
        ////    return XXH3_mul128_fold64(
        ////               acc[0] ^ XXH_readLE64(secret),
        ////               acc[1] ^ XXH_readLE64(secret+8) );
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_mix2Accs(ref ulong acc, ref ulong secret)
        {
            return XXH3_mul128_fold64(
                acc ^ secret,
                Unsafe.Add(ref acc, 1) ^ Unsafe.Add(ref secret, 1));
        }

        ////XXH_FORCE_INLINE XXH64_hash_t
        ////XXH3_hashLong_64b_internal(const void* XXH_RESTRICT input, size_t len,
        ////                           const void* XXH_RESTRICT secret, size_t secretSize,
        ////                           XXH3_f_accumulate_512 f_acc512,
        ////                           XXH3_f_scrambleAcc f_scramble)
        ////{
        ////    XXH_ALIGN(XXH_ACC_ALIGN) xxh_u64 acc[XXH_ACC_NB] = XXH3_INIT_ACC;

        ////    XXH3_hashLong_internal_loop(acc, (const xxh_u8*)input, len, (const xxh_u8*)secret, secretSize, f_acc512, f_scramble);

        ////    /* converge into final hash */
        ////    XXH_STATIC_ASSERT(sizeof(acc) == 64);
        ////    /* do not align on 8, so that the secret is different from the accumulator */
        ////#define XXH_SECRET_MERGEACCS_START 11
        ////    XXH_ASSERT(secretSize >= sizeof(acc) + XXH_SECRET_MERGEACCS_START);
        ////    return XXH3_mergeAccs(acc, (const xxh_u8*)secret + XXH_SECRET_MERGEACCS_START, (xxh_u64)len * XXH_PRIME64_1);
        ////}

        [SkipLocalsInit]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_hashLong_64b_internal(ref byte input, uint len, ref ulong secret, uint secretSize)
        {
            Span<ulong> acc = stackalloc ulong[(int)XXH_ACC_NB];

            XXH3_INIT_ACC.CopyTo(acc);

            XXH3_hashLong_internal_loop(ref MemoryMarshal.GetReference(acc), ref input, len, ref secret, secretSize);
            
            const uint XXH_SECRET_MERGEACCS_START = 11;
            
            return XXH3_mergeAccs(ref MemoryMarshal.GetReference(acc), ref Unsafe.AddByteOffset(ref secret, XXH_SECRET_MERGEACCS_START), len * XXH_PRIME64_1);
        }


        ////XXH_FORCE_INLINE void
        ////XXH3_hashLong_internal_loop(xxh_u64* XXH_RESTRICT acc,
        ////                      const xxh_u8* XXH_RESTRICT input, size_t len,
        ////                      const xxh_u8* XXH_RESTRICT secret, size_t secretSize,
        ////                            XXH3_f_accumulate_512 f_acc512,
        ////                            XXH3_f_scrambleAcc f_scramble)
        ////{
        ////    size_t const nbStripesPerBlock = (secretSize - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE;
        ////    size_t const block_len = XXH_STRIPE_LEN * nbStripesPerBlock;
        ////    size_t const nb_blocks = (len - 1) / block_len;

        ////    size_t n;

        ////    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN);

        ////    for (n = 0; n < nb_blocks; n++) {
        ////        XXH3_accumulate(acc, input + n*block_len, secret, nbStripesPerBlock, f_acc512);
        ////        f_scramble(acc, secret + secretSize - XXH_STRIPE_LEN);
        ////    }

        ////    /* last partial block */
        ////    XXH_ASSERT(len > XXH_STRIPE_LEN);
        ////    {   size_t const nbStripes = ((len - 1) - (block_len * nb_blocks)) / XXH_STRIPE_LEN;
        ////        XXH_ASSERT(nbStripes <= (secretSize / XXH_SECRET_CONSUME_RATE));
        ////        XXH3_accumulate(acc, input + nb_blocks*block_len, secret, nbStripes, f_acc512);

        ////        /* last stripe */
        ////        {   const xxh_u8* const p = input + len - XXH_STRIPE_LEN;
        ////#define XXH_SECRET_LASTACC_START 7  /* not aligned on 8, last secret is different from acc & scrambler */
        ////            f_acc512(acc, p, secret + secretSize - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START);
        ////    }   }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void XXH3_hashLong_internal_loop(ref ulong acc, ref byte input, uint len, ref ulong secret, uint secretSize)
        {
            uint nbStripesPerBlock = (secretSize - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE;
            uint block_len = XXH_STRIPE_LEN * nbStripesPerBlock;
            uint nb_blocks = (len - 1) / block_len;

            for (var n = 0; n < nb_blocks; n++)
            {
                XXH3_accumulate(ref acc, ref Unsafe.AddByteOffset(ref input, (nuint)n * block_len), ref secret, nbStripesPerBlock);
                XXH3_scrambleAcc(ref acc, ref Unsafe.AddByteOffset(ref secret, secretSize - XXH_STRIPE_LEN));
            }

            uint nbStripes = ((len - 1) - (block_len * nb_blocks)) / XXH_STRIPE_LEN;
            XXH3_accumulate(ref acc, ref Unsafe.AddByteOffset(ref input, nb_blocks * block_len), ref secret, nbStripes);

            /* last stripe */
            ref byte p = ref Unsafe.AddByteOffset(ref input, len - XXH_STRIPE_LEN);
            const int XXH_SECRET_LASTACC_START = 7; /* not aligned on 8, last secret is different from acc & scrambler */
            XXH3_accumulate_512(ref acc, ref p, ref Unsafe.AddByteOffset(ref secret, secretSize - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START));
        }

        ////static XXH64_hash_t
        ////XXH3_mergeAccs(const xxh_u64* XXH_RESTRICT acc, const xxh_u8* XXH_RESTRICT secret, xxh_u64 start)
        ////{
        ////    xxh_u64 result64 = start;
        ////    size_t i = 0;

        ////    for (i = 0; i < 4; i++) {
        ////        result64 += XXH3_mix2Accs(acc+2*i, secret + 16*i);
        ////#if defined(__clang__)                                /* Clang */ \
        ////    && (defined(__arm__) || defined(__thumb__))       /* ARMv7 */ \
        ////    && (defined(__ARM_NEON) || defined(__ARM_NEON__)) /* NEON */  \
        ////    && !defined(XXH_ENABLE_AUTOVECTORIZE)             /* Define to disable */
        ////        /*
        ////         * UGLY HACK:
        ////         * Prevent autovectorization on Clang ARMv7-a. Exact same problem as
        ////         * the one in XXH3_len_129to240_64b. Speeds up shorter keys > 240b.
        ////         * XXH3_64bits, len == 256, Snapdragon 835:
        ////         *   without hack: 2063.7 MB/s
        ////         *   with hack:    2560.7 MB/s
        ////         */
        ////        XXH_COMPILER_GUARD(result64);
        ////#endif
        ////    }

        ////    return XXH3_avalanche(result64);
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_mergeAccs(ref ulong acc, ref ulong secret, ulong start)
        {
            for (uint i = 0; i < 4; i++)
            {
                start += XXH3_mix2Accs(ref Unsafe.Add(ref acc, 2 * i), ref Unsafe.AddByteOffset(ref secret, 16 * i));
            }

            return XXH3_avalanche(start);
        }

        ////XXH_FORCE_INLINE void
        ////XXH3_initCustomSecret_scalar(void* XXH_RESTRICT customSecret, xxh_u64 seed64)
        ////{
        ////    /*
        ////     * We need a separate pointer for the hack below,
        ////     * which requires a non-const pointer.
        ////     * Any decent compiler will optimize this out otherwise.
        ////     */
        ////    const xxh_u8* kSecretPtr = XXH3_kSecret;
        ////    XXH_STATIC_ASSERT((XXH_SECRET_DEFAULT_SIZE & 15) == 0);

        ////#if defined(__clang__) && defined(__aarch64__)
        ////    /*
        ////     * UGLY HACK:
        ////     * Clang generates a bunch of MOV/MOVK pairs for aarch64, and they are
        ////     * placed sequentially, in order, at the top of the unrolled loop.
        ////     *
        ////     * While MOVK is great for generating constants (2 cycles for a 64-bit
        ////     * constant compared to 4 cycles for LDR), it fights for bandwidth with
        ////     * the arithmetic instructions.
        ////     *
        ////     *   I   L   S
        ////     * MOVK
        ////     * MOVK
        ////     * MOVK
        ////     * MOVK
        ////     * ADD
        ////     * SUB      STR
        ////     *          STR
        ////     * By forcing loads from memory (as the asm line causes Clang to assume
        ////     * that XXH3_kSecretPtr has been changed), the pipelines are used more
        ////     * efficiently:
        ////     *   I   L   S
        ////     *      LDR
        ////     *  ADD LDR
        ////     *  SUB     STR
        ////     *          STR
        ////     *
        ////     * See XXH3_NEON_LANES for details on the pipsline.
        ////     *
        ////     * XXH3_64bits_withSeed, len == 256, Snapdragon 835
        ////     *   without hack: 2654.4 MB/s
        ////     *   with hack:    3202.9 MB/s
        ////     */
        ////    XXH_COMPILER_GUARD(kSecretPtr);
        ////#endif
        ////    /*
        ////     * Note: in debug mode, this overrides the asm optimization
        ////     * and Clang will emit MOVK chains again.
        ////     */
        ////    XXH_ASSERT(kSecretPtr == XXH3_kSecret);

        ////    {   int const nbRounds = XXH_SECRET_DEFAULT_SIZE / 16;
        ////        int i;
        ////        for (i=0; i < nbRounds; i++) {
        ////            /*
        ////             * The asm hack causes Clang to assume that kSecretPtr aliases with
        ////             * customSecret, and on aarch64, this prevented LDP from merging two
        ////             * loads together for free. Putting the loads together before the stores
        ////             * properly generates LDP.
        ////             */
        ////            xxh_u64 lo = XXH_readLE64(kSecretPtr + 16*i)     + seed64;
        ////            xxh_u64 hi = XXH_readLE64(kSecretPtr + 16*i + 8) - seed64;
        ////            XXH_writeLE64((xxh_u8*)customSecret + 16*i,     lo);
        ////            XXH_writeLE64((xxh_u8*)customSecret + 16*i + 8, hi);
        ////    }   }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void XXH3_initCustomSecret_scalar(ref ulong customSecret, ulong seed64)
        {
            const uint nbRounds = XXH_SECRET_DEFAULT_SIZE / 16;

            for (uint i = 0; i < nbRounds; i++)
            {
                Unsafe.AddByteOffset(ref customSecret, 16 * i) += seed64;
                Unsafe.AddByteOffset(ref customSecret, 16 * i + 8) -= seed64;
            }
        }


        ////XXH_FORCE_INLINE XXH_TARGET_SSE2 void
        ////XXH3_accumulate_512_sse2( void* XXH_RESTRICT acc,
        ////                    const void* XXH_RESTRICT input,
        ////                    const void* XXH_RESTRICT secret)
        ////{
        ////    /* SSE2 is just a half-scale version of the AVX2 version. */
        ////    XXH_ASSERT((((size_t)acc) & 15) == 0);
        ////    {   __m128i* const xacc    =       (__m128i *) acc;
        ////        /* Unaligned. This is mainly for pointer arithmetic, and because
        ////         * _mm_loadu_si128 requires a const __m128i * pointer for some reason. */
        ////        const         __m128i* const xinput  = (const __m128i *) input;
        ////        /* Unaligned. This is mainly for pointer arithmetic, and because
        ////         * _mm_loadu_si128 requires a const __m128i * pointer for some reason. */
        ////        const         __m128i* const xsecret = (const __m128i *) secret;

        ////        size_t i;
        ////        for (i=0; i < XXH_STRIPE_LEN/sizeof(__m128i); i++) {
        ////            /* data_vec    = xinput[i]; */
        ////            __m128i const data_vec    = _mm_loadu_si128   (xinput+i);
        ////            /* key_vec     = xsecret[i]; */
        ////            __m128i const key_vec     = _mm_loadu_si128   (xsecret+i);
        ////            /* data_key    = data_vec ^ key_vec; */
        ////            __m128i const data_key    = _mm_xor_si128     (data_vec, key_vec);
        ////            /* data_key_lo = data_key >> 32; */
        ////            __m128i const data_key_lo = _mm_shuffle_epi32 (data_key, _MM_SHUFFLE(0, 3, 0, 1));
        ////            /* product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff); */
        ////            __m128i const product     = _mm_mul_epu32     (data_key, data_key_lo);
        ////            /* xacc[i] += swap(data_vec); */
        ////            __m128i const data_swap = _mm_shuffle_epi32(data_vec, _MM_SHUFFLE(1,0,3,2));
        ////            __m128i const sum       = _mm_add_epi64(xacc[i], data_swap);
        ////            /* xacc[i] += product; */
        ////            xacc[i] = _mm_add_epi64(product, sum);
        ////    }   }
        ////}    

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static unsafe void XXH3_accumulate_512_sse2(ref ulong acc, ref byte input, ref ulong secret)
        {
            const uint blockSize = 16;
            const byte shuffle1 = (((0) << 6) | ((3) << 4) | ((0) << 2) | ((1)));
            const byte shuffle2 = (((1) << 6) | ((0) << 4) | ((3) << 2) | ((2)));

            ////for (uint i = 0; i < XXH_STRIPE_LEN / blockSize; ++i)
            ////{
            ////    Round(ref acc, ref input, ref secret, i);
            ////}

            Round(ref acc, ref input, ref secret, 0);
            Round(ref acc, ref input, ref secret, 1);
            Round(ref acc, ref input, ref secret, 2);
            Round(ref acc, ref input, ref secret, 3);

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static void Round(ref ulong acc, ref byte input, ref ulong secret, uint i)
            {
                var dataVec = Sse2.LoadVector128((ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref input, i * blockSize)));
                var keyVec = Sse2.LoadVector128((ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref secret, i * blockSize)));
                var dataKey = Sse2.Xor(dataVec, keyVec).AsUInt32();
                var dataKeyLo = Sse2.Shuffle(dataKey, shuffle1);
                var product = Sse2.Multiply(dataKey, dataKeyLo);
                var data_swap = Sse2.Shuffle(dataVec.AsUInt32(), shuffle2).AsUInt64();
                var accLine = (ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref acc, i * blockSize));
                var xacc = Sse2.LoadVector128(accLine);
                var sum = Sse2.Add(xacc, data_swap);
                var sum2 = Sse2.Add(product, sum);
                Sse2.Store(accLine, sum2);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static unsafe void XXH3_accumulate_512(ref ulong acc, ref byte input, ref ulong secret)
        {
            if (Sse2.IsSupported)
            {
                XXH3_accumulate_512_sse2(ref acc, ref input, ref secret);
            }
            else
            {
                XXH3_accumulate_512_scalar(ref acc, ref input, ref secret);
            }
        }

        ////XXH_FORCE_INLINE XXH_TARGET_SSE2 void
        ////XXH3_scrambleAcc_sse2(void* XXH_RESTRICT acc, const void* XXH_RESTRICT secret)
        ////{
        ////    XXH_ASSERT((((size_t)acc) & 15) == 0);
        ////    {   __m128i* const xacc = (__m128i*) acc;
        ////        /* Unaligned. This is mainly for pointer arithmetic, and because
        ////         * _mm_loadu_si128 requires a const __m128i * pointer for some reason. */
        ////        const         __m128i* const xsecret = (const __m128i *) secret;
        ////        const __m128i prime32 = _mm_set1_epi32((int)XXH_PRIME32_1);

        ////        size_t i;
        ////        for (i=0; i < XXH_STRIPE_LEN/sizeof(__m128i); i++) {
        ////            /* xacc[i] ^= (xacc[i] >> 47) */
        ////            __m128i const acc_vec     = xacc[i];
        ////            __m128i const shifted     = _mm_srli_epi64    (acc_vec, 47);
        ////            __m128i const data_vec    = _mm_xor_si128     (acc_vec, shifted);
        ////            /* xacc[i] ^= xsecret[i]; */
        ////            __m128i const key_vec     = _mm_loadu_si128   (xsecret+i);
        ////            __m128i const data_key    = _mm_xor_si128     (data_vec, key_vec);

        ////            /* xacc[i] *= XXH_PRIME32_1; */
        ////            __m128i const data_key_hi = _mm_shuffle_epi32 (data_key, _MM_SHUFFLE(0, 3, 0, 1));
        ////            __m128i const prod_lo     = _mm_mul_epu32     (data_key, prime32);
        ////            __m128i const prod_hi     = _mm_mul_epu32     (data_key_hi, prime32);
        ////            xacc[i] = _mm_add_epi64(prod_lo, _mm_slli_epi64(prod_hi, 32));
        ////        }
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_scrambleAcc_sse2(ref ulong acc, ref ulong secret)
        {
            const uint blockSize = 16;
            const byte shuffle1 = (((0) << 6) | ((3) << 4) | ((0) << 2) | ((1)));

            Round(ref acc, ref secret, 0);
            Round(ref acc, ref secret, 1);
            Round(ref acc, ref secret, 2);
            Round(ref acc, ref secret, 3);

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static void Round(ref ulong acc, ref ulong secret, uint i)
            {
                var accLine = (ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref acc, i * blockSize));
                var accVec = Sse2.LoadVector128(accLine);
                var shifted = Sse2.ShiftRightLogical(accVec, 47);
                var dataVec = Sse2.Xor(accVec, shifted);
                var keyVec = Sse2.LoadVector128((ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref secret, i * blockSize)));
                var dataKey = Sse2.Xor(dataVec, keyVec).AsUInt32();
                var dataKeyHi = Sse2.Shuffle(dataKey, shuffle1);
                var prodLo = Sse2.Multiply(dataKey, Prime32);
                var prodHi = Sse2.Multiply(dataKeyHi, Prime32);
                Sse2.Store(accLine, Sse2.Add(prodLo.AsUInt64(), Sse2.ShiftLeftLogical(prodHi, 32)));
            }
        }
    }
}
