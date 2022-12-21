using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace XXHash.Managed
{
    public class BloomFilter
    {
        public static readonly Vector256<uint> Multipliers = Vector256.Create(0x00000001, 0x9e3779b9, 0xe35e67b1, 0x734297e9, 0x35fbe861, 0xdeb7c719, 0x448b211, 0x3459b749);

        // False positive rate of a standard Bloom filter, for given ratio of
        // filter memory bits to added keys, and number of probes per operation.
        // (The false positive rate is effectively independent of scale, assuming
        // the implementation scales OK.)
        /*static double StandardFpRate(double bits_per_key, int num_probes)
        {
            // Standard very-good-estimate formula. See
            // https://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
            return std::pow(1.0 - std::exp(-num_probes / bits_per_key), num_probes);
        }*/

        static double StandardFpRate(double bits_per_key, int num_probes) 
            => Math.Pow(1.0 - Math.Exp(-num_probes / bits_per_key), num_probes);

        // False positive rate of a "blocked"/"shareded"/"cache-local" Bloom filter,
        // for given ratio of filter memory bits to added keys, number of probes per
        // operation (all within the given block or cache line size), and block or
        // cache line size.
        /*static double CacheLocalFpRate(double bits_per_key, int num_probes,
                                       int cache_line_bits)
        {
            if (bits_per_key <= 0.0)
            {
                // Fix a discontinuity
                return 1.0;
            }
            double keys_per_cache_line = cache_line_bits / bits_per_key;
            // A reasonable estimate is the average of the FP rates for one standard
            // deviation above and below the mean bucket occupancy. See
            // https://github.com/facebook/rocksdb/wiki/RocksDB-Bloom-Filter#the-math
            double keys_stddev = std::sqrt(keys_per_cache_line);
            double crowded_fp = StandardFpRate(
                cache_line_bits / (keys_per_cache_line + keys_stddev), num_probes);
            double uncrowded_fp = StandardFpRate(
                cache_line_bits / (keys_per_cache_line - keys_stddev), num_probes);
            return (crowded_fp + uncrowded_fp) / 2;
        }*/

        static double CacheLocalFpRate(double bits_per_key, int num_probes, int cache_line_bits)
        {
            if (bits_per_key <= 0.0)
            {
                // Fix a discontinuity
                return 1.0;
            }
            double keys_per_cache_line = cache_line_bits / bits_per_key;
            double keys_stddev = Math.Sqrt(keys_per_cache_line);
            double crowded_fp = StandardFpRate(
                cache_line_bits / (keys_per_cache_line + keys_stddev), num_probes);
            double uncrowded_fp = StandardFpRate(
                cache_line_bits / (keys_per_cache_line - keys_stddev), num_probes);
            return (crowded_fp + uncrowded_fp) / 2;
        }

        // False positive rate of querying a new item against `num_keys` items, all
        // hashed to `fingerprint_bits` bits. (This assumes the fingerprint hashes
        // themselves are stored losslessly. See Section 4 of
        // http://www.ccs.neu.edu/home/pete/pub/bloom-filters-verification.pdf)
        /*static double FingerprintFpRate(size_t num_keys, int fingerprint_bits)
        {
            double inv_fingerprint_space = std::pow(0.5, fingerprint_bits);
            // Base estimate assumes each key maps to a unique fingerprint.
            // Could be > 1 in extreme cases.
            double base_estimate = num_keys * inv_fingerprint_space;
            // To account for potential overlap, we choose between two formulas
            if (base_estimate > 0.0001)
            {
                // A very good formula assuming we don't construct a floating point
                // number extremely close to 1. Always produces a probability < 1.
                return 1.0 - std::exp(-base_estimate);
            }
            else
            {
                // A very good formula when base_estimate is far below 1. (Subtract
                // away the integral-approximated sum that some key has same hash as
                // one coming before it in a list.)
                return base_estimate - (base_estimate * base_estimate * 0.5);
            }
        }*/

        static double FingerprintFpRate(ulong num_keys, int fingerprint_bits)
        {
            double inv_fingerprint_space = Math.Pow(0.5, fingerprint_bits);

            double base_estimate = num_keys * inv_fingerprint_space;

            if (base_estimate > 0.0001)
            {
                return 1.0 - Math.Exp(-base_estimate);
            }
            else
            {
                return base_estimate - (base_estimate * base_estimate * 0.5);
            }
        }

        // Returns the probably of either of two independent(-ish) events
        // happening, given their probabilities. (This is useful for combining
        // results from StandardFpRate or CacheLocalFpRate with FingerprintFpRate
        // for a hash-efficient Bloom filter's FP rate. See Section 4 of
        // http://www.ccs.neu.edu/home/pete/pub/bloom-filters-verification.pdf)
        /*static double IndependentProbabilitySum(double rate1, double rate2)
        {
            // Use formula that avoids floating point extremely close to 1 if
            // rates are extremely small.
            return rate1 + rate2 - (rate1 * rate2);
        }*/

        static double IndependentProbabilitySum(double rate1, double rate2) 
            => rate1 + rate2 - (rate1 * rate2);

        // NOTE: this has only been validated to enough accuracy for producing
        // reasonable warnings / user feedback, not for making functional decisions.
        /*static double EstimatedFpRate(size_t keys, size_t bytes, int num_probes,
                                      int hash_bits)
        {
            return BloomMath::IndependentProbabilitySum(
                BloomMath::CacheLocalFpRate(8.0 * bytes / keys, num_probes, 512),
                BloomMath::FingerprintFpRate(keys, hash_bits));
        }*/

        static double EstimatedFpRate(ulong keys, ulong bytes, int num_probes, int hash_bits) => 
            IndependentProbabilitySum(
                CacheLocalFpRate(8.0 * bytes / keys, num_probes, 512),
                FingerprintFpRate(keys, hash_bits));

        /*static inline int ChooseNumProbes(int millibits_per_key)
        {
            // Since this implementation can (with AVX2) make up to 8 probes
            // for the same cost, we pick the most accurate num_probes, based
            // on actual tests of the implementation. Note that for higher
            // bits/key, the best choice for cache-local Bloom can be notably
            // smaller than standard bloom, e.g. 9 instead of 11 @ 16 b/k.
            if (millibits_per_key <= 2080)
            {
                return 1;
            }
            else if (millibits_per_key <= 3580)
            {
                return 2;
            }
            else if (millibits_per_key <= 5100)
            {
                return 3;
            }
            else if (millibits_per_key <= 6640)
            {
                return 4;
            }
            else if (millibits_per_key <= 8300)
            {
                return 5;
            }
            else if (millibits_per_key <= 10070)
            {
                return 6;
            }
            else if (millibits_per_key <= 11720)
            {
                return 7;
            }
            else if (millibits_per_key <= 14001)
            {
                // Would be something like <= 13800 but sacrificing *slightly* for
                // more settings using <= 8 probes.
                return 8;
            }
            else if (millibits_per_key <= 16050)
            {
                return 9;
            }
            else if (millibits_per_key <= 18300)
            {
                return 10;
            }
            else if (millibits_per_key <= 22001)
            {
                return 11;
            }
            else if (millibits_per_key <= 25501)
            {
                return 12;
            }
            else if (millibits_per_key > 50000)
            {
                // Top out at 24 probes (three sets of 8)
                return 24;
            }
            else
            {
                // Roughly optimal choices for remaining range
                // e.g.
                // 28000 -> 12, 28001 -> 13
                // 50000 -> 23, 50001 -> 24
                return (millibits_per_key - 1) / 2000 - 1;
            }
        }*/

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static int ChooseNumProbes(int millibits_per_key) => 
            millibits_per_key switch
        {
            <= 2080 => 1,
            <= 3580 => 2,
            <= 5100 => 3,
            <= 6640 => 4,
            <= 8300 => 5,
            <= 10070 => 6,
            <= 11720 => 7,
            <= 14001 => 8,
            <= 16050 => 9,
            <= 18300 => 10,
            <= 22001 => 11,
            <= 25501 => 12,
            > 50000 => 24,
            _ => (millibits_per_key - 1) / 2000 - 1
        };


        /*static inline void AddHashPrepared(uint32_t h2, int num_probes,
                                           char* data_at_cache_line)
        {
            uint32_t h = h2;
            for (int i = 0; i < num_probes; ++i, h *= uint32_t{ 0x9e3779b9}) {
                // 9-bit address within 512 bit cache line
                int bitpos = h >> (32 - 9);
                data_at_cache_line[bitpos >> 3] |= (uint8_t{ 1} << (bitpos & 7));
            }
        }*/

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void AddHashPrepared(uint h2, int num_probes, ref byte data_at_cache_line)
        {
            uint h = h2;
            for (int i = 0; i < num_probes; ++i, h *= 0x9e3779b9) 
            {
                uint bitpos = h >> (32 - 9);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref data_at_cache_line, bitpos >> 3), (byte)(1 << (byte)(bitpos & 7)));
            }
        }


        //static inline void PrepareHash(uint32_t h1, uint32_t len_bytes,
        //                         const char* data,
        //                         uint32_t /*out*/ *byte_offset) {
        //    uint32_t bytes_to_cache_line = FastRange32(len_bytes >> 6, h1) << 6;
        //    PREFETCH(data + bytes_to_cache_line, 0 /* rw */, 1 /* locality */);
        //    PREFETCH(data + bytes_to_cache_line + 63, 0 /* rw */, 1 /* locality */);
        //    *byte_offset = bytes_to_cache_line;
        //}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static unsafe void PrepareHash(uint h1, uint len_bytes, ref byte data, ref byte byte_offset) 
        {
            uint bytes_to_cache_line = FastRange32(len_bytes >> 6, h1) << 6;
            if (Sse.IsSupported)
            {
                Sse.Prefetch1(Unsafe.AsPointer(ref Unsafe.Add(ref data, bytes_to_cache_line)));
                Sse.Prefetch1(Unsafe.AsPointer(ref Unsafe.Add(ref data, bytes_to_cache_line + 63)));
            }

            Unsafe.WriteUnaligned(ref byte_offset, bytes_to_cache_line);
        }

        static uint FastRange32(uint hash, uint range)
        {
            var product = (ulong)hash * range;
            return (uint)(product >> 32);
        }

        /*static inline bool HashMayMatch(uint32_t h1, uint32_t h2, uint32_t len_bytes,
                                  int num_probes, const char *data) {
            uint32_t bytes_to_cache_line = FastRange32(len_bytes >> 6, h1) << 6;
            return HashMayMatchPrepared(h2, num_probes, data + bytes_to_cache_line);
        }*/

        static bool HashMayMatch(uint h1, uint h2, uint len_bytes, int num_probes, ref byte data)
        {
            uint bytes_to_cache_line = FastRange32(len_bytes >> 6, h1) << 6;
            return HashMayMatchPrepared(h2, num_probes, data + bytes_to_cache_line);
        }

        /*static inline bool HashMayMatchPrepared(uint32_t h2, int num_probes,
                                          const char *data_at_cache_line) {
            uint32_t h = h2;
        #ifdef HAVE_AVX2
            int rem_probes = num_probes;

            // NOTE: For better performance for num_probes in {1, 2, 9, 10, 17, 18,
            // etc.} one can insert specialized code for rem_probes <= 2, bypassing
            // the SIMD code in those cases. There is a detectable but minor overhead
            // applied to other values of num_probes (when not statically determined),
            // but smoother performance curve vs. num_probes. But for now, when
            // in doubt, don't add unnecessary code.

            // Powers of 32-bit golden ratio, mod 2**32.
            const __m256i multipliers =
                _mm256_setr_epi32(0x00000001, 0x9e3779b9, 0xe35e67b1, 0x734297e9,
                                  0x35fbe861, 0xdeb7c719, 0x448b211, 0x3459b749);

            for (;;) {
              // Eight copies of hash
              __m256i hash_vector = _mm256_set1_epi32(h);

              // Same effect as repeated multiplication by 0x9e3779b9 thanks to
              // associativity of multiplication.
              hash_vector = _mm256_mullo_epi32(hash_vector, multipliers);

              // Now the top 9 bits of each of the eight 32-bit values in
              // hash_vector are bit addresses for probes within the cache line.
              // While the platform-independent code uses byte addressing (6 bits
              // to pick a byte + 3 bits to pick a bit within a byte), here we work
              // with 32-bit words (4 bits to pick a word + 5 bits to pick a bit
              // within a word) because that works well with AVX2 and is equivalent
              // under little-endian.

              // Shift each right by 28 bits to get 4-bit word addresses.
              const __m256i word_addresses = _mm256_srli_epi32(hash_vector, 28);

              // Gather 32-bit values spread over 512 bits by 4-bit address. In
              // essence, we are dereferencing eight pointers within the cache
              // line.
              //
              // Option 1: AVX2 gather (seems to be a little slow - understandable)
              // const __m256i value_vector =
              //     _mm256_i32gather_epi32(static_cast<const int
              //     *>(data_at_cache_line),
              //                            word_addresses,
              //                            4);
              // END Option 1
              // Potentially unaligned as we're not *always* cache-aligned -> loadu
              const __m256i *mm_data =
                  reinterpret_cast<const __m256i *>(data_at_cache_line);
              __m256i lower = _mm256_loadu_si256(mm_data);
              __m256i upper = _mm256_loadu_si256(mm_data + 1);
              // Option 2: AVX512VL permute hack
              // Only negligibly faster than Option 3, so not yet worth supporting
              // const __m256i value_vector =
              //    _mm256_permutex2var_epi32(lower, word_addresses, upper);
              // END Option 2
              // Option 3: AVX2 permute+blend hack
              // Use lowest three bits to order probing values, as if all from same
              // 256 bit piece.
              lower = _mm256_permutevar8x32_epi32(lower, word_addresses);
              upper = _mm256_permutevar8x32_epi32(upper, word_addresses);
              // Just top 1 bit of address, to select between lower and upper.
              const __m256i upper_lower_selector = _mm256_srai_epi32(hash_vector, 31);
              // Finally: the next 8 probed 32-bit values, in probing sequence order.
              const __m256i value_vector =
                  _mm256_blendv_epi8(lower, upper, upper_lower_selector);
              // END Option 3

              // We might not need to probe all 8, so build a mask for selecting only
              // what we need. (The k_selector(s) could be pre-computed but that
              // doesn't seem to make a noticeable performance difference.)
              const __m256i zero_to_seven = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
              // Subtract rem_probes from each of those constants
              __m256i k_selector =
                  _mm256_sub_epi32(zero_to_seven, _mm256_set1_epi32(rem_probes));
              // Negative after subtract -> use/select
              // Keep only high bit (logical shift right each by 31).
              k_selector = _mm256_srli_epi32(k_selector, 31);

              // Strip off the 4 bit word address (shift left)
              __m256i bit_addresses = _mm256_slli_epi32(hash_vector, 4);
              // And keep only 5-bit (32 - 27) bit-within-32-bit-word addresses.
              bit_addresses = _mm256_srli_epi32(bit_addresses, 27);
              // Build a bit mask
              const __m256i bit_mask = _mm256_sllv_epi32(k_selector, bit_addresses);

              // Like ((~value_vector) & bit_mask) == 0)
              bool match = _mm256_testc_si256(value_vector, bit_mask) != 0;

              // This check first so that it's easy for branch predictor to optimize
              // num_probes <= 8 case, making it free of unpredictable branches.
              if (rem_probes <= 8) {
                return match;
              } else if (!match) {
                return false;
              }
              // otherwise
              // Need another iteration. 0xab25f4c1 == golden ratio to the 8th power
              h *= 0xab25f4c1;
              rem_probes -= 8;
            }
        #else
            for (int i = 0; i < num_probes; ++i, h *= uint32_t{0x9e3779b9}) {
              // 9-bit address within 512 bit cache line
              int bitpos = h >> (32 - 9);
              if ((data_at_cache_line[bitpos >> 3] & (char(1) << (bitpos & 7))) == 0) {
                return false;
              }
            }
            return true;
        #endif
        }*/

        static unsafe bool HashMayMatchPrepared(uint h2, int num_probes, ref byte data_at_cache_line)
        {
            uint h = h2;

            if (!Avx2.IsSupported)
            {
                for (int i = 0; i < num_probes; ++i)
                {
                    h *= (uint)0x9e3779b9;

                    int bitpos = (int)(h >> (32 - 9));

                    if ((Unsafe.Add(ref data_at_cache_line, bitpos >> 3) & (1 << (bitpos & 7))) == 0)
                    {
                        return false;
                    }
                }
                
                return true;
            }
            else
            {
                int rem_probes = num_probes;
                while (true)
                {
                    var hash_vector = Vector256.Create(h);
                    hash_vector = Avx2.MultiplyLow(hash_vector, Multipliers);
                    var word_addresses = Avx2.ShiftRightLogical(hash_vector, 28);
                    var lower = Avx2.LoadVector256((uint *)Unsafe.AsPointer(ref data_at_cache_line));
                    var upper = Avx2.LoadVector256((uint *)Unsafe.AsPointer(ref Unsafe.AddByteOffset(ref data_at_cache_line, 32)));
                    lower = Avx2.PermuteVar8x32(lower, word_addresses);
                    upper = Avx2.PermuteVar8x32(upper, word_addresses);
                    Avx2.ShiftRightArithmetic(hash_vector, 31);
                }
            }
        }
    }
}
