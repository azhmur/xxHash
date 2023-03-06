using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XXHash.Managed;

////struct XXH3_state_s {
////    XXH_ALIGN_MEMBER(64, XXH64_hash_t acc[8]);
////    /*!< The 8 accumulators. See @ref XXH32_state_s::v and @ref XXH64_state_s::v */
////    XXH_ALIGN_MEMBER(64, unsigned char customSecret[XXH3_SECRET_DEFAULT_SIZE]);
////    /*!< Used to store a custom secret generated from a seed. */
////    XXH_ALIGN_MEMBER(64, unsigned char buffer[XXH3_INTERNALBUFFER_SIZE]);
////    /*!< The internal buffer. @see XXH32_state_s::mem32 */
////    XXH32_hash_t bufferedSize;
////    /*!< The amount of memory in @ref buffer, @see XXH32_state_s::memsize */
////    XXH32_hash_t useSeed;
////    /*!< Reserved field. Needed for padding on 64-bit. */
////    size_t nbStripesSoFar;
////    /*!< Number or stripes processed. */
////    XXH64_hash_t totalLen;
////    /*!< Total length hashed. 64-bit even on 32-bit targets. */
////    size_t nbStripesPerBlock;
////    /*!< Number of stripes per block. */
////    size_t secretLimit;
////    /*!< Size of @ref customSecret or @ref extSecret */
////    XXH64_hash_t seed;
////    /*!< Seed for _withSeed variants. Must be zero otherwise, @see XXH3_INITSTATE() */
////    XXH64_hash_t reserved64;
////    /*!< Reserved field. */
////    const unsigned char* extSecret;
////    /*!< Reference to an external secret for the _withSecret variants, NULL
////     *   for other variants. */
////    /* note: there may be some padding at the end due to alignment on 64 bytes */
////};

internal struct XXH3State {
    public ulong[] Accumulator;
    public byte[] CustomSecret;
    public byte[] Buffer;
    public int BufferedSize;
    public nuint NumberOfStripesProcessed;
    public ulong TotalLength;
    public ulong Seed;
}