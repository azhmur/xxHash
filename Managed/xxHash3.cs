using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.Intrinsics.Arm.AdvSimd;

namespace XXHash.Managed
{
    [SkipLocalsInit()]
    public unsafe static class XXHash3
    {
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
        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_0to16_64b(ref byte input, uint len, ulong seed)
        {
            if (len > 8) return XXH3_len_9to16_64b(ref input, len, seed);
            if (len >= 4) return XXH3_len_4to8_64b(ref input, len, seed);
            if (len != 0) return XXH3_len_1to3_64b(ref input, len, seed);
            return XXHashShared.XXH64_avalanche(seed ^ XXHashShared.GetSecret64(56) ^ XXHashShared.GetSecret64(64));
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_1to3_64b(ref byte input, uint len, ulong seed)
        {
            byte c1 = Unsafe.ReadUnaligned<byte>(ref input);
            byte c2 = Unsafe.ReadUnaligned<byte>(ref Unsafe.AddByteOffset(ref input, len >> 1));
            byte c3 = Unsafe.ReadUnaligned<byte>(ref Unsafe.AddByteOffset(ref input, len - 1));

            uint combined = ((uint)c1 << 16) | ((uint)c2 << 24) | ((uint)c3 << 0) | ((uint)len << 8);
            ulong bitflip = (XXHashShared.GetSecret32(0) ^ XXHashShared.GetSecret32(4)) + seed;
            ulong keyed = (ulong)combined ^ bitflip;
            return XXHashShared.XXH64_avalanche(keyed);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_4to8_64b(ref byte input, uint len, ulong seed)
        {
            seed ^= (ulong)BinaryPrimitives.ReverseEndianness((uint)seed) << 32;
            uint input1 = Unsafe.ReadUnaligned<uint>(ref input);
            uint input2 = Unsafe.ReadUnaligned<uint>(ref Unsafe.AddByteOffset(ref input, len - 4));
            ulong bitflip = (XXHashShared.GetSecret64(8) ^ XXHashShared.GetSecret64(16)) - seed;
            ulong input64 = input2 + (((ulong)input1) << 32);
            ulong keyed = input64 ^ bitflip;
            return XXHashShared.XXH3_rrmxmx(keyed, len);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_9to16_64b(ref byte input, uint len, ulong seed)
        {
            ulong bitflip1 = (XXHashShared.GetSecret64(24) ^ XXHashShared.GetSecret64(32)) + seed;
            ulong bitflip2 = (XXHashShared.GetSecret64(40) ^ XXHashShared.GetSecret64(48)) - seed;
            ulong input_lo = Unsafe.ReadUnaligned<ulong>(ref input) ^ bitflip1;
            ulong input_hi = Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, len - 8)) ^ bitflip2;
            ulong acc = len
                + BinaryPrimitives.ReverseEndianness(input_lo) + input_hi
                + XXHashShared.XXH3_mul128_fold64(input_lo, input_hi);
            return XXHashShared.XXH3_avalanche(acc);
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
            Unsafe.Add(ref acc, lane) += XXHashShared.XXH_mult32to64(data_key & 0xFFFFFFFF, data_key >> 32);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_accumulate(ref ulong acc, ref byte input, ref ulong secret, uint nbStripes)
        {
            for (uint n = 0; n < nbStripes; n++)
            {
                ref byte inp = ref Unsafe.AddByteOffset(ref input, n * XXHashShared.XXH_STRIPE_LEN);
                XXH3_accumulate_512(ref acc, ref inp, ref Unsafe.AddByteOffset(ref secret, n * XXHashShared.XXH_SECRET_CONSUME_RATE));
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
            acc64 = XXHashShared.XXH_xorshift64(acc64, 47);
            acc64 ^= key64;
            acc64 *= XXHashShared.XXH_PRIME32_1;
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
            if (Avx2.IsSupported)
            {
                XXH3_scrambleAcc_avx2(ref acc, ref secret);
            }
            else if (Sse2.IsSupported)
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong XXH3_64(ReadOnlySpan<byte> data, ulong seed)
        {
            return XXH3_64(ref MemoryMarshal.GetReference(data), (uint)data.Length, seed);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong XXH3_64(ReadOnlySpan<char> data, ulong seed)
        {
            return XXH3_64(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (uint)(data.Length * 2), seed);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_64(ref byte input, uint len, ulong seed64)
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
        private static ulong XXH3_long(ref byte input, uint len, ulong seed64)
        {
            if (seed64 == 0)
            {
                return XXH3_hashLong_64b_internal(ref input, len, ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(XXHashShared.XXH3_kSecret)), XXHashShared.XXH_SECRET_DEFAULT_SIZE);
            }
            else
            {
                Span<ulong> customSecret = stackalloc ulong[(int)XXHashShared.XXH_SECRET_DEFAULT_SIZE / sizeof(ulong)];
                XXH3_initCustomSecret_scalar(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(XXHashShared.XXH3_kSecret)), ref MemoryMarshal.GetReference(customSecret), seed64);
                return XXH3_hashLong_64b_internal(ref input, len, ref MemoryMarshal.GetReference(customSecret), XXHashShared.XXH_SECRET_DEFAULT_SIZE);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_len_17to128_64b(ref byte input, uint len, ulong seed)
        {
            ulong acc = len * XXHashShared.XXH_PRIME64_1;
            if (len > 32) {
                if (len > 64) {
                    if (len > 96) {
                        acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 48), 96, seed);
                        acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 64), 112, seed);
                    }
                    acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 32), 64, seed);
                    acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 48), 80, seed);
                }
                acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 16), 32, seed);
                acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 32), 48, seed);
            }
            acc += XXHashShared.XXH3_mix16B(ref input, 0, seed);
            acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 16), 16, seed);

            return XXHashShared.XXH3_avalanche(acc);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static ulong XXH3_len_129to240_64b(
            ref byte input,
            uint len,
            ulong seed)
        {
            ulong acc = len * XXHashShared.XXH_PRIME64_1;
            int nbRounds = (int)len / 16;

            for (uint i = 0; i < 8; i++) 
            {
                acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 16 * i), 16 * i, seed);
            }

            acc = XXHashShared.XXH3_avalanche(acc);

            for (uint i = 8; i < nbRounds; i++)
            {
                acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, 16 * i), (16 * (i - 8)) + XXHashShared.XXH3_MIDSIZE_STARTOFFSET, seed);
            }

            /* last bytes */
            acc += XXHashShared.XXH3_mix16B(ref Unsafe.AddByteOffset(ref input, len - 16), XXHashShared.XXH3_SECRET_SIZE_MIN - XXHashShared.XXH3_MIDSIZE_LASTOFFSET, seed);
            return XXHashShared.XXH3_avalanche(acc);
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
            return XXHashShared.XXH3_mul128_fold64(
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong XXH3_hashLong_64b_internal(ref byte input, uint len, ref ulong secret, uint secretSize)
        {
            Span<ulong> acc = stackalloc ulong[(int)XXHashShared.XXH_ACC_NB];

            XXHashShared.XXH3_INIT_ACC.CopyTo(acc);

            XXH3_hashLong_internal_loop(ref MemoryMarshal.GetReference(acc), ref input, len, ref secret, secretSize);
            
            return XXH3_mergeAccs(ref MemoryMarshal.GetReference(acc), ref Unsafe.AddByteOffset(ref secret, XXHashShared.XXH_SECRET_MERGEACCS_START), len * XXHashShared.XXH_PRIME64_1);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_hashLong_internal_loop(ref ulong acc, ref byte input, uint len, ref ulong secret, uint secretSize)
        {
            uint nbStripesPerBlock = (secretSize - XXHashShared.XXH_STRIPE_LEN) / XXHashShared.XXH_SECRET_CONSUME_RATE;
            uint block_len = XXHashShared.XXH_STRIPE_LEN * nbStripesPerBlock;
            uint nb_blocks = (len - 1) / block_len;

            for (var n = 0; n < nb_blocks; n++)
            {
                XXH3_accumulate(ref acc, ref Unsafe.AddByteOffset(ref input, (nuint)n * block_len), ref secret, nbStripesPerBlock);
                XXH3_scrambleAcc(ref acc, ref Unsafe.AddByteOffset(ref secret, secretSize - XXHashShared.XXH_STRIPE_LEN));
            }

            uint nbStripes = ((len - 1) - (block_len * nb_blocks)) / XXHashShared.XXH_STRIPE_LEN;
            XXH3_accumulate(ref acc, ref Unsafe.AddByteOffset(ref input, nb_blocks * block_len), ref secret, nbStripes);

            /* last stripe */
            ref byte p = ref Unsafe.AddByteOffset(ref input, len - XXHashShared.XXH_STRIPE_LEN);
            const int XXH_SECRET_LASTACC_START = 7; /* not aligned on 8, last secret is different from acc & scrambler */
            XXH3_accumulate_512(ref acc, ref p, ref Unsafe.AddByteOffset(ref secret, secretSize - XXHashShared.XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START));
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

            return XXHashShared.XXH3_avalanche(start);
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
        private static void XXH3_initCustomSecret_scalar(ref ulong basicSecret, ref ulong customSecret, ulong seed64)
        {
            const uint nbRounds = XXHashShared.XXH_SECRET_DEFAULT_SIZE / 16;

            for (uint i = 0; i < nbRounds; i++)
            {
                Unsafe.AddByteOffset(ref customSecret, 16 * i) = Unsafe.AddByteOffset(ref basicSecret, 16 * i) + seed64;
                Unsafe.AddByteOffset(ref customSecret, 16 * i + 8) = Unsafe.AddByteOffset(ref basicSecret, 16 * i + 8) - seed64;
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
            if (Avx2.IsSupported)
            {
                XXH3_accumulate_512_avx2(ref acc, ref input, ref secret);
            }
            else if (Sse2.IsSupported)
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
                var prodLo = Sse2.Multiply(dataKey, XXHashShared.Prime32_128);
                var prodHi = Sse2.Multiply(dataKeyHi, XXHashShared.Prime32_128);
                Sse2.Store(accLine, Sse2.Add(prodLo.AsUInt64(), Sse2.ShiftLeftLogical(prodHi, 32)));
            }
        }

        ////XXH_FORCE_INLINE XXH_TARGET_AVX2 void
        ////XXH3_accumulate_512_avx2( void* XXH_RESTRICT acc,
        ////                    const void* XXH_RESTRICT input,
        ////                    const void* XXH_RESTRICT secret)
        ////{
        ////    XXH_ASSERT((((size_t)acc) & 31) == 0);
        ////    {   __m256i* const xacc    =       (__m256i *) acc;
        ////        /* Unaligned. This is mainly for pointer arithmetic, and because
        ////         * _mm256_loadu_si256 requires  a const __m256i * pointer for some reason. */
        ////        const         __m256i* const xinput  = (const __m256i *) input;
        ////        /* Unaligned. This is mainly for pointer arithmetic, and because
        ////         * _mm256_loadu_si256 requires a const __m256i * pointer for some reason. */
        ////        const         __m256i* const xsecret = (const __m256i *) secret;

        ////        size_t i;
        ////        for (i=0; i < XXH_STRIPE_LEN/sizeof(__m256i); i++) {
        ////            /* data_vec    = xinput[i]; */
        ////            __m256i const data_vec    = _mm256_loadu_si256    (xinput+i);
        ////            /* key_vec     = xsecret[i]; */
        ////            __m256i const key_vec     = _mm256_loadu_si256   (xsecret+i);
        ////            /* data_key    = data_vec ^ key_vec; */
        ////            __m256i const data_key    = _mm256_xor_si256     (data_vec, key_vec);
        ////            /* data_key_lo = data_key >> 32; */
        ////            __m256i const data_key_lo = _mm256_shuffle_epi32 (data_key, _MM_SHUFFLE(0, 3, 0, 1));
        ////            /* product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff); */
        ////            __m256i const product     = _mm256_mul_epu32     (data_key, data_key_lo);
        ////            /* xacc[i] += swap(data_vec); */
        ////            __m256i const data_swap = _mm256_shuffle_epi32(data_vec, _MM_SHUFFLE(1, 0, 3, 2));
        ////            __m256i const sum       = _mm256_add_epi64(xacc[i], data_swap);
        ////            /* xacc[i] += product; */
        ////            xacc[i] = _mm256_add_epi64(product, sum);
        ////    }   }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static unsafe void XXH3_accumulate_512_avx2(ref ulong acc, ref byte input, ref ulong secret)
        {
            const uint blockSize = 32;
            const byte shuffle1 = (((0) << 6) | ((3) << 4) | ((0) << 2) | ((1)));
            const byte shuffle2 = (((1) << 6) | ((0) << 4) | ((3) << 2) | ((2)));


            Round(ref acc, ref input, ref secret, 0);
            Round(ref acc, ref input, ref secret, 1);

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static void Round(ref ulong acc, ref byte input, ref ulong secret, uint i)
            {
                var dataVec = Avx2.LoadVector256((ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref input, i * blockSize)));
                var keyVec = Avx2.LoadVector256((ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref secret, i * blockSize)));
                var dataKey = Avx2.Xor(dataVec, keyVec).AsUInt32();
                var dataKeyLo = Avx2.Shuffle(dataKey, shuffle1);
                var product = Avx2.Multiply(dataKey, dataKeyLo);
                var data_swap = Avx2.Shuffle(dataVec.AsUInt32(), shuffle2).AsUInt64();
                var accLine = (ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref acc, i * blockSize));
                var xacc = Avx2.LoadVector256(accLine);
                var sum = Avx2.Add(xacc, data_swap);
                var sum2 = Avx2.Add(product, sum);
                Avx2.Store(accLine, sum2);
            }
        }

        ////XXH_FORCE_INLINE XXH_TARGET_AVX2 void
        ////XXH3_scrambleAcc_avx2(void* XXH_RESTRICT acc, const void* XXH_RESTRICT secret)
        ////{
        ////    XXH_ASSERT((((size_t)acc) & 31) == 0);
        ////    {   __m256i* const xacc = (__m256i*) acc;
        ////        /* Unaligned. This is mainly for pointer arithmetic, and because
        ////         * _mm256_loadu_si256 requires a const __m256i * pointer for some reason. */
        ////        const         __m256i* const xsecret = (const __m256i *) secret;
        ////        const __m256i prime32 = _mm256_set1_epi32((int)XXH_PRIME32_1);

        ////        size_t i;
        ////        for (i=0; i < XXH_STRIPE_LEN/sizeof(__m256i); i++) {
        ////            /* xacc[i] ^= (xacc[i] >> 47) */
        ////            __m256i const acc_vec     = xacc[i];
        ////            __m256i const shifted     = _mm256_srli_epi64    (acc_vec, 47);
        ////            __m256i const data_vec    = _mm256_xor_si256     (acc_vec, shifted);
        ////            /* xacc[i] ^= xsecret; */
        ////            __m256i const key_vec     = _mm256_loadu_si256   (xsecret+i);
        ////            __m256i const data_key    = _mm256_xor_si256     (data_vec, key_vec);

        ////            /* xacc[i] *= XXH_PRIME32_1; */
        ////            __m256i const data_key_hi = _mm256_shuffle_epi32 (data_key, _MM_SHUFFLE(0, 3, 0, 1));
        ////            __m256i const prod_lo     = _mm256_mul_epu32     (data_key, prime32);
        ////            __m256i const prod_hi     = _mm256_mul_epu32     (data_key_hi, prime32);
        ////            xacc[i] = _mm256_add_epi64(prod_lo, _mm256_slli_epi64(prod_hi, 32));
        ////        }
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void XXH3_scrambleAcc_avx2(ref ulong acc, ref ulong secret)
        {
            const uint blockSize = 32;
            const byte shuffle1 = (((0) << 6) | ((3) << 4) | ((0) << 2) | ((1)));

            Round(ref acc, ref secret, 0);
            Round(ref acc, ref secret, 1);

            [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
            static void Round(ref ulong acc, ref ulong secret, uint i)
            {
                var accLine = (ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref acc, i * blockSize));
                var accVec = Avx2.LoadVector256(accLine);
                var shifted = Avx2.ShiftRightLogical(accVec, 47);
                var dataVec = Avx2.Xor(accVec, shifted);
                var keyVec = Avx2.LoadVector256((ulong*)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref secret, i * blockSize)));
                var dataKey = Avx2.Xor(dataVec, keyVec).AsUInt32();
                var dataKeyHi = Avx2.Shuffle(dataKey, shuffle1);
                var prodLo = Avx2.Multiply(dataKey, XXHashShared.Prime32_256);
                var prodHi = Avx2.Multiply(dataKeyHi, XXHashShared.Prime32_256);
                Avx2.Store(accLine, Avx2.Add(prodLo.AsUInt64(), Avx2.ShiftLeftLogical(prodHi, 32)));
            }
        }

        /////*
        //// * Assumption: `secret` size is >= XXH3_SECRET_SIZE_MIN
        //// */
        ////XXH_FORCE_INLINE XXH_PUREF XXH128_hash_t
        ////XXH3_len_0to16_128b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(len <= 16);
        ////    {   if (len > 8) return XXH3_len_9to16_128b(input, len, secret, seed);
        ////        if (len >= 4) return XXH3_len_4to8_128b(input, len, secret, seed);
        ////        if (len) return XXH3_len_1to3_128b(input, len, secret, seed);
        ////        {   XXH128_hash_t h128;
        ////            xxh_u64 const bitflipl = XXH_readLE64(secret+64) ^ XXH_readLE64(secret+72);
        ////            xxh_u64 const bitfliph = XXH_readLE64(secret+80) ^ XXH_readLE64(secret+88);
        ////            h128.low64 = XXH64_avalanche(seed ^ bitflipl);
        ////            h128.high64 = XXH64_avalanche( seed ^ bitfliph);
        ////            return h128;
        ////    }   }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static XXH128Hash XXH3_len_0to16_128b(ref byte input, uint len, ulong seed)
        {
            if (len > 8)
                return XXH3_len_9to16_128b(ref input, len, seed);

            if (len >= 4) 
                return XXH3_len_4to8_128b(ref input, len, seed);

            if (len > 0) 
                return XXH3_len_1to3_128b(ref input, len, seed);

            XXH128Hash h128;
            ulong bitflipl = XXHashShared.GetSecret64(64) ^ XXHashShared.GetSecret64(72);
            ulong bitfliph = XXHashShared.GetSecret64(80) ^ XXHashShared.GetSecret64(88);
            h128.Low = XXHashShared.XXH64_avalanche(seed ^ bitflipl);
            h128.High = XXHashShared.XXH64_avalanche(seed ^ bitfliph);
            return h128;
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH128_hash_t
        ////XXH3_len_1to3_128b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    /* A doubled version of 1to3_64b with different constants. */
        ////    XXH_ASSERT(input != NULL);
        ////        XXH_ASSERT(1 <= len && len <= 3);
        ////        XXH_ASSERT(secret != NULL);
        ////    /*
        ////     * len = 1: combinedl = { input[0], 0x01, input[0], input[0] }
        ////     * len = 2: combinedl = { input[1], 0x02, input[0], input[1] }
        ////     * len = 3: combinedl = { input[2], 0x03, input[0], input[1] }
        ////     */
        ////    {   xxh_u8 const c1 = input[0];
        ////        xxh_u8 const c2 = input[len >> 1];
        ////        xxh_u8 const c3 = input[len - 1];
        ////        xxh_u32 const combinedl = ((xxh_u32)c1 << 16) | ((xxh_u32)c2 << 24)
        ////                                | ((xxh_u32)c3 << 0) | ((xxh_u32)len << 8);
        ////        xxh_u32 const combinedh = XXH_rotl32(XXH_swap32(combinedl), 13);
        ////        xxh_u64 const bitflipl = (XXH_readLE32(secret) ^ XXH_readLE32(secret + 4)) + seed;
        ////        xxh_u64 const bitfliph = (XXH_readLE32(secret + 8) ^ XXH_readLE32(secret + 12)) - seed;
        ////        xxh_u64 const keyed_lo = (xxh_u64)combinedl ^ bitflipl;
        ////        xxh_u64 const keyed_hi = (xxh_u64)combinedh ^ bitfliph;
        ////        XXH128_hash_t h128;
        ////        h128.low64  = XXH64_avalanche(keyed_lo);
        ////        h128.high64 = XXH64_avalanche(keyed_hi);
        ////        return h128;
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static XXH128Hash XXH3_len_1to3_128b(ref byte input, uint len, ulong seed)
        {
            byte c1 = input;
            byte c2 = Unsafe.AddByteOffset(ref input, len >> 1);
            byte c3 = Unsafe.AddByteOffset(ref input, len - 1);

            uint combinedl = ((uint)c1 << 16) | ((uint)c2 << 24) | ((uint)c3 << 0) | ((uint)len << 8);
            uint combinedh = BitOperations.RotateLeft(BinaryPrimitives.ReverseEndianness(combinedl), 13);
            ulong bitflipl = (XXHashShared.GetSecret32(0) ^ XXHashShared.GetSecret32(4)) + seed;
            ulong bitfliph = (XXHashShared.GetSecret32(8) ^ XXHashShared.GetSecret32(12)) - seed;
            ulong keyed_lo = (ulong)combinedl ^ bitflipl;
            ulong keyed_hi = (ulong)combinedh ^ bitfliph;

            return new XXH128Hash()
            {
                High = XXHashShared.XXH64_avalanche(keyed_hi),
                Low = XXHashShared.XXH64_avalanche(keyed_lo)
            };
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH128_hash_t
        ////XXH3_len_4to8_128b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(input != NULL);
        ////        XXH_ASSERT(secret != NULL);
        ////        XXH_ASSERT(4 <= len && len <= 8);
        ////        seed ^= (xxh_u64) XXH_swap32((xxh_u32) seed) << 32;
        ////    {   xxh_u32 const input_lo = XXH_readLE32(input);
        ////        xxh_u32 const input_hi = XXH_readLE32(input + len - 4);
        ////        xxh_u64 const input_64 = input_lo + ((xxh_u64)input_hi << 32);
        ////        xxh_u64 const bitflip = (XXH_readLE64(secret + 16) ^ XXH_readLE64(secret + 24)) + seed;
        ////        xxh_u64 const keyed = input_64 ^ bitflip;

        ////        /* Shift len to the left to ensure it is even, this avoids even multiplies. */
        ////        XXH128_hash_t m128 = XXH_mult64to128(keyed, XXH_PRIME64_1 + (len << 2));

        ////        m128.high64 += (m128.low64 << 1);
        ////        m128.low64  ^= (m128.high64 >> 3);

        ////        m128.low64   = XXH_xorshift64(m128.low64, 35);
        ////        m128.low64  *= 0x9FB21C651E98DF25ULL;
        ////        m128.low64   = XXH_xorshift64(m128.low64, 28);
        ////        m128.high64  = XXH3_avalanche(m128.high64);
        ////        return m128;
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static XXH128Hash XXH3_len_4to8_128b(ref byte input, uint len, ulong seed)
        {
            seed ^= (ulong)BinaryPrimitives.ReverseEndianness((uint)seed) << 32;
            uint input_lo = Unsafe.ReadUnaligned<uint>(ref input);
            uint input_hi = Unsafe.ReadUnaligned<uint>(ref Unsafe.AddByteOffset(ref input, len - 4));
            ulong input_64 = input_lo + ((ulong)input_hi << 32);
            ulong bitflip = (XXHashShared.GetSecret64(16) ^ XXHashShared.GetSecret64(24)) + seed;
            ulong keyed = input_64 ^ bitflip;

            XXH128Hash m128 = XXHashShared.XXH3_mul128(keyed, XXHashShared.XXH_PRIME64_1 + (len << 2));
            m128.High += (m128.Low << 1);
            m128.Low ^= (m128.High >> 3);

            m128.Low = XXHashShared.XXH_xorshift64(m128.Low, 35);
            m128.Low *= 0x9FB21C651E98DF25UL;
            m128.Low = XXHashShared.XXH_xorshift64(m128.Low, 28);
            m128.High = XXHashShared.XXH3_avalanche(m128.High);

            return m128;
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH128_hash_t
        ////XXH3_len_9to16_128b(const xxh_u8* input, size_t len, const xxh_u8* secret, XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(input != NULL);
        ////    XXH_ASSERT(secret != NULL);
        ////    XXH_ASSERT(9 <= len && len <= 16);
        ////    {   xxh_u64 const bitflipl = (XXH_readLE64(secret+32) ^ XXH_readLE64(secret+40)) - seed;
        ////        xxh_u64 const bitfliph = (XXH_readLE64(secret+48) ^ XXH_readLE64(secret+56)) + seed;
        ////        xxh_u64 const input_lo = XXH_readLE64(input);
        ////        xxh_u64       input_hi = XXH_readLE64(input + len - 8);
        ////        XXH128_hash_t m128 = XXH_mult64to128(input_lo ^ input_hi ^ bitflipl, XXH_PRIME64_1);
        ////        /*
        ////         * Put len in the middle of m128 to ensure that the length gets mixed to
        ////         * both the low and high bits in the 128x64 multiply below.
        ////         */
        ////        m128.low64 += (xxh_u64)(len - 1) << 54;
        ////        input_hi   ^= bitfliph;
        ////        /*
        ////         * Add the high 32 bits of input_hi to the high 32 bits of m128, then
        ////         * add the long product of the low 32 bits of input_hi and XXH_PRIME32_2 to
        ////         * the high 64 bits of m128.
        ////         *
        ////         * The best approach to this operation is different on 32-bit and 64-bit.
        ////         */
        ////        if (sizeof(void *) < sizeof(xxh_u64)) { /* 32-bit */
        ////            /*
        ////             * 32-bit optimized version, which is more readable.
        ////             *
        ////             * On 32-bit, it removes an ADC and delays a dependency between the two
        ////             * halves of m128.high64, but it generates an extra mask on 64-bit.
        ////             */
        ////            m128.high64 += (input_hi & 0xFFFFFFFF00000000ULL) + XXH_mult32to64((xxh_u32)input_hi, XXH_PRIME32_2);
        ////        } else {
        ////            /*
        ////             * 64-bit optimized (albeit more confusing) version.
        ////             *
        ////             * Uses some properties of addition and multiplication to remove the mask:
        ////             *
        ////             * Let:
        ////             *    a = input_hi.lo = (input_hi & 0x00000000FFFFFFFF)
        ////             *    b = input_hi.hi = (input_hi & 0xFFFFFFFF00000000)
        ////             *    c = XXH_PRIME32_2
        ////             *
        ////             *    a + (b * c)
        ////             * Inverse Property: x + y - x == y
        ////             *    a + (b * (1 + c - 1))
        ////             * Distributive Property: x * (y + z) == (x * y) + (x * z)
        ////             *    a + (b * 1) + (b * (c - 1))
        ////             * Identity Property: x * 1 == x
        ////             *    a + b + (b * (c - 1))
        ////             *
        ////             * Substitute a, b, and c:
        ////             *    input_hi.hi + input_hi.lo + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
        ////             *
        ////             * Since input_hi.hi + input_hi.lo == input_hi, we get this:
        ////             *    input_hi + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
        ////             */
        ////            m128.high64 += input_hi + XXH_mult32to64((xxh_u32)input_hi, XXH_PRIME32_2 - 1);
        ////        }
        ////        /* m128 ^= XXH_swap64(m128 >> 64); */
        ////        m128.low64  ^= XXH_swap64(m128.high64);

        ////        {   /* 128x64 multiply: h128 = m128 * XXH_PRIME64_2; */
        ////            XXH128_hash_t h128 = XXH_mult64to128(m128.low64, XXH_PRIME64_2);
        ////            h128.high64 += m128.high64 * XXH_PRIME64_2;

        ////            h128.low64   = XXH3_avalanche(h128.low64);
        ////            h128.high64  = XXH3_avalanche(h128.high64);
        ////            return h128;
        ////    }   }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static XXH128Hash XXH3_len_9to16_128b(ref byte input, uint len, ulong seed)
        {
            ulong bitflipl = (XXHashShared.GetSecret64(32) ^ XXHashShared.GetSecret64(40)) - seed;
            ulong bitfliph = (XXHashShared.GetSecret64(48) ^ XXHashShared.GetSecret64(56)) + seed;
            ulong input_lo = Unsafe.ReadUnaligned<ulong>(ref input);
            ulong input_hi = Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref input, len - 8));
            
            XXH128Hash m128 = XXHashShared.XXH3_mul128(input_lo ^ input_hi ^ bitflipl, XXHashShared.XXH_PRIME64_1);
            m128.Low += (ulong)(len - 1) << 54;
            input_hi ^= bitfliph;

            m128.High += input_hi + XXHashShared.XXH_mult32to64((uint)input_hi, XXHashShared.XXH_PRIME32_2 - 1);
            m128.Low ^= BinaryPrimitives.ReverseEndianness(m128.High);

            XXH128Hash h128 = XXHashShared.XXH3_mul128(m128.Low, XXHashShared.XXH_PRIME64_2);
            h128.High += m128.High * XXHashShared.XXH_PRIME64_2;
            h128.Low = XXHashShared.XXH3_avalanche(h128.Low);
            h128.High = XXHashShared.XXH3_avalanche(h128.High);

            return h128;
        }

        ////XXH_FORCE_INLINE XXH128_hash_t
        ////XXH3_128bits_internal(const void* input, size_t len,
        ////                      XXH64_hash_t seed64, const void* XXH_RESTRICT secret, size_t secretLen,
        ////                      XXH3_hashLong128_f f_hl128)
        ////{
        ////    XXH_ASSERT(secretLen >= XXH3_SECRET_SIZE_MIN);
        ////    /*
        ////     * If an action is to be taken if `secret` conditions are not respected,
        ////     * it should be done here.
        ////     * For now, it's a contract pre-condition.
        ////     * Adding a check and a branch here would cost performance at every hash.
        ////     */
        ////    if (len <= 16)
        ////        return XXH3_len_0to16_128b((const xxh_u8*)input, len, (const xxh_u8*)secret, seed64);
        ////    if (len <= 128)
        ////        return XXH3_len_17to128_128b((const xxh_u8*)input, len, (const xxh_u8*)secret, secretLen, seed64);
        ////    if (len <= XXH3_MIDSIZE_MAX)
        ////        return XXH3_len_129to240_128b((const xxh_u8*)input, len, (const xxh_u8*)secret, secretLen, seed64);
        ////    return f_hl128(input, len, seed64, secret, secretLen);
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static XXH128Hash XXH3_128(ref byte input, uint len, ulong seed64)
        {
            if (len <= 16)
            {
                return XXH3_len_0to16_128b(ref input, len, seed64);
            }
            if (len <= 128)
            {
                return XXH3_len_17to128_128b(ref input, len, seed64);
            }
            if (len <= 240)
            {
                return XXH3_len_129to240_128b(ref input, len, seed64);
            }

            return XXH3_long128(ref input, len, seed64);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static XXH128Hash XXH3_128(ReadOnlySpan<byte> data, ulong seed)
        {
            return XXH3_128(ref MemoryMarshal.GetReference(data), (uint)data.Length, seed);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static XXH128Hash XXH3_128(ReadOnlySpan<char> data, ulong seed)
        {
            return XXH3_128(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), (uint)(data.Length * 2), seed);
        }

        ////XXH_FORCE_INLINE XXH_PUREF XXH128_hash_t
        ////XXH3_len_17to128_128b(const xxh_u8* XXH_RESTRICT input, size_t len,
        ////                      const xxh_u8* XXH_RESTRICT secret, size_t secretSize,
        ////                      XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
        ////    XXH_ASSERT(16 < len && len <= 128);

        ////    {   XXH128_hash_t acc;
        ////        acc.low64 = len * XXH_PRIME64_1;
        ////        acc.high64 = 0;

        ////#if XXH_SIZE_OPT >= 1
        ////        {
        ////            /* Smaller, but slightly slower. */
        ////            unsigned int i = (unsigned int)(len - 1) / 32;
        ////            do {
        ////                acc = XXH128_mix32B(acc, input+16*i, input+len-16*(i+1), secret+32*i, seed);
        ////            } while (i-- != 0);
        ////        }
        ////#else
        ////        if (len > 32) {
        ////            if (len > 64) {
        ////                if (len > 96) {
        ////                    acc = XXH128_mix32B(acc, input+48, input+len-64, secret+96, seed);
        ////                }
        ////                acc = XXH128_mix32B(acc, input+32, input+len-48, secret+64, seed);
        ////            }
        ////            acc = XXH128_mix32B(acc, input+16, input+len-32, secret+32, seed);
        ////        }
        ////        acc = XXH128_mix32B(acc, input, input+len-16, secret, seed);
        ////#endif
        ////        {   XXH128_hash_t h128;
        ////            h128.low64  = acc.low64 + acc.high64;
        ////            h128.high64 = (acc.low64    * XXH_PRIME64_1)
        ////                        + (acc.high64   * XXH_PRIME64_4)
        ////                        + ((len - seed) * XXH_PRIME64_2);
        ////            h128.low64  = XXH3_avalanche(h128.low64);
        ////            h128.high64 = (XXH64_hash_t)0 - XXH3_avalanche(h128.high64);
        ////            return h128;
        ////        }
        ////    }
        ////}
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static XXH128Hash XXH3_len_17to128_128b(ref byte input, uint len, ulong seed)
        {
            XXH128Hash acc;
            acc.Low = len * XXHashShared.XXH_PRIME64_1;
            acc.High = 0;

            if (len > 32)
            {
                if (len > 64)
                {
                    if (len > 96)
                    {
                        acc = XXHashShared.XXH128_mix32B(acc, ref Unsafe.AddByteOffset(ref input, 48), ref Unsafe.AddByteOffset(ref input, len - 64), 96, seed);
                    }
                    acc = XXHashShared.XXH128_mix32B(acc, ref Unsafe.AddByteOffset(ref input, 32), ref Unsafe.AddByteOffset(ref input, len - 48), 64, seed);
                }
                acc = XXHashShared.XXH128_mix32B(acc, ref Unsafe.AddByteOffset(ref input, 16), ref Unsafe.AddByteOffset(ref input, len - 32), 32, seed);
            }
            acc = XXHashShared.XXH128_mix32B(acc, ref input, ref Unsafe.AddByteOffset(ref input, len - 16), 0, seed);

            XXH128Hash h128;
            h128.Low = acc.Low + acc.High;
            h128.High = (acc.Low * XXHashShared.XXH_PRIME64_1)
                        + (acc.High * XXHashShared.XXH_PRIME64_4)
                        + ((len - seed) * XXHashShared.XXH_PRIME64_2);
            h128.Low = XXHashShared.XXH3_avalanche(h128.Low);
            h128.High = 0 - XXHashShared.XXH3_avalanche(h128.High);
            return h128;
        }

        ////XXH_NO_INLINE XXH_PUREF XXH128_hash_t
        ////XXH3_len_129to240_128b(const xxh_u8* XXH_RESTRICT input, size_t len,
        ////                       const xxh_u8* XXH_RESTRICT secret, size_t secretSize,
        ////                       XXH64_hash_t seed)
        ////{
        ////    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
        ////    XXH_ASSERT(128 < len && len <= XXH3_MIDSIZE_MAX);

        ////    {   XXH128_hash_t acc;
        ////        unsigned i;
        ////        acc.low64 = len * XXH_PRIME64_1;
        ////        acc.high64 = 0;
        ////        /*
        ////         *  We set as `i` as offset + 32. We do this so that unchanged
        ////         * `len` can be used as upper bound. This reaches a sweet spot
        ////         * where both x86 and aarch64 get simple agen and good codegen
        ////         * for the loop.
        ////         */
        ////        for (i = 32; i < 160; i += 32) {
        ////            acc = XXH128_mix32B(acc,
        ////                                input  + i - 32,
        ////                                input  + i - 16,
        ////                                secret + i - 32,
        ////                                seed);
        ////        }
        ////        acc.low64 = XXH3_avalanche(acc.low64);
        ////        acc.high64 = XXH3_avalanche(acc.high64);
        ////        /*
        ////         * NB: `i <= len` will duplicate the last 32-bytes if
        ////         * len % 32 was zero. This is an unfortunate necessity to keep
        ////         * the hash result stable.
        ////         */
        ////        for (i=160; i <= len; i += 32) {
        ////            acc = XXH128_mix32B(acc,
        ////                                input + i - 32,
        ////                                input + i - 16,
        ////                                secret + XXH3_MIDSIZE_STARTOFFSET + i - 160,
        ////                                seed);
        ////        }
        ////        /* last bytes */
        ////        acc = XXH128_mix32B(acc,
        ////                            input + len - 16,
        ////                            input + len - 32,
        ////                            secret + XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET - 16,
        ////                            (XXH64_hash_t)0 - seed);

        ////        {   XXH128_hash_t h128;
        ////            h128.low64  = acc.low64 + acc.high64;
        ////            h128.high64 = (acc.low64    * XXH_PRIME64_1)
        ////                        + (acc.high64   * XXH_PRIME64_4)
        ////                        + ((len - seed) * XXH_PRIME64_2);
        ////            h128.low64  = XXH3_avalanche(h128.low64);
        ////            h128.high64 = (XXH64_hash_t)0 - XXH3_avalanche(h128.high64);
        ////            return h128;
        ////        }
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static XXH128Hash XXH3_len_129to240_128b(ref byte input, uint len, ulong seed)
        {
            XXH128Hash acc;
            acc.Low = len * XXHashShared.XXH_PRIME64_1;
            acc.High = 0;

            for (uint i = 32; i < 160; i += 32)
            {
                acc = XXHashShared.XXH128_mix32B(acc, ref Unsafe.AddByteOffset(ref input, i - 32), ref Unsafe.AddByteOffset(ref input, i - 16), i - 32, seed);
            }

            acc.Low = XXHashShared.XXH3_avalanche(acc.Low);
            acc.High = XXHashShared.XXH3_avalanche(acc.High);

            for (uint i = 160; i <= len; i += 32) 
            {
                acc = XXHashShared.XXH128_mix32B(acc, ref Unsafe.AddByteOffset(ref input, i - 32), ref Unsafe.AddByteOffset(ref input, i - 16), XXHashShared.XXH3_MIDSIZE_STARTOFFSET + i - 160, seed);
            }

            acc = XXHashShared.XXH128_mix32B(acc, ref Unsafe.AddByteOffset(ref input, len - 16), ref Unsafe.AddByteOffset(ref input, len - 32), XXHashShared.XXH3_SECRET_SIZE_MIN - XXHashShared.XXH3_MIDSIZE_LASTOFFSET - 16, 0 - seed);

            XXH128Hash h128;
            h128.Low = acc.Low + acc.High;
            h128.High = (acc.Low * XXHashShared.XXH_PRIME64_1)
                        + (acc.High * XXHashShared.XXH_PRIME64_4)
                        + ((len - seed) * XXHashShared.XXH_PRIME64_2);
            h128.Low = XXHashShared.XXH3_avalanche(h128.Low);
            h128.High = 0 - XXHashShared.XXH3_avalanche(h128.High);
            return h128;
        }

        ////XXH_FORCE_INLINE XXH128_hash_t
        ////XXH3_hashLong_128b_internal(const void* XXH_RESTRICT input, size_t len,
        ////                            const xxh_u8* XXH_RESTRICT secret, size_t secretSize,
        ////                            XXH3_f_accumulate f_acc,
        ////                            XXH3_f_scrambleAcc f_scramble)
        ////{
        ////    XXH_ALIGN(XXH_ACC_ALIGN) xxh_u64 acc[XXH_ACC_NB] = XXH3_INIT_ACC;

        ////    XXH3_hashLong_internal_loop(acc, (const xxh_u8*)input, len, secret, secretSize, f_acc, f_scramble);

        ////    /* converge into final hash */
        ////    XXH_STATIC_ASSERT(sizeof(acc) == 64);
        ////    XXH_ASSERT(secretSize >= sizeof(acc) + XXH_SECRET_MERGEACCS_START);
        ////    {   XXH128_hash_t h128;
        ////        h128.low64  = XXH3_mergeAccs(acc,
        ////                                     secret + XXH_SECRET_MERGEACCS_START,
        ////                                     (xxh_u64)len * XXH_PRIME64_1);
        ////        h128.high64 = XXH3_mergeAccs(acc,
        ////                                     secret + secretSize
        ////                                            - sizeof(acc) - XXH_SECRET_MERGEACCS_START,
        ////                                     ~((xxh_u64)len * XXH_PRIME64_2));
        ////        return h128;
        ////    }
        ////}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static XXH128Hash XXH3_hashLong_128b_internal(ref byte input, uint len, ref ulong secret, uint secretSize)
        {
            Span<ulong> acc = stackalloc ulong[(int)XXHashShared.XXH_ACC_NB];

            XXHashShared.XXH3_INIT_ACC.CopyTo(acc);

            XXH3_hashLong_internal_loop(ref MemoryMarshal.GetReference(acc), ref input, len, ref secret, secretSize);

            XXH128Hash h128;

            h128.Low = XXH3_mergeAccs(ref MemoryMarshal.GetReference(acc), ref Unsafe.AddByteOffset(ref secret, XXHashShared.XXH_SECRET_MERGEACCS_START), len * XXHashShared.XXH_PRIME64_1);
            h128.High = XXH3_mergeAccs(ref MemoryMarshal.GetReference(acc), ref Unsafe.AddByteOffset(ref secret, secretSize - XXHashShared.XXH_ACC_NB * sizeof(ulong) - XXHashShared.XXH_SECRET_MERGEACCS_START), ~(len * XXHashShared.XXH_PRIME64_2));

            return h128;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static XXH128Hash XXH3_long128(ref byte input, uint len, ulong seed64)
        {
            if (seed64 == 0)
            {
                return XXH3_hashLong_128b_internal(ref input, len, ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(XXHashShared.XXH3_kSecret)), XXHashShared.XXH_SECRET_DEFAULT_SIZE);
            }
            else
            {
                Span<ulong> customSecret = stackalloc ulong[(int)XXHashShared.XXH_SECRET_DEFAULT_SIZE / sizeof(ulong)];
                XXH3_initCustomSecret_scalar(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(XXHashShared.XXH3_kSecret)), ref MemoryMarshal.GetReference(customSecret), seed64);
                return XXH3_hashLong_128b_internal(ref input, len, ref MemoryMarshal.GetReference(customSecret), XXHashShared.XXH_SECRET_DEFAULT_SIZE);
            }
        }
    }
}
