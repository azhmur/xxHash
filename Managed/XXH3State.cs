using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

public sealed class XXH3State 
{
    internal ulong[] Accumulator;
    internal ulong[] CustomSecret;
    internal byte[] Buffer;
    internal int BufferedSize;
    internal ulong NumberOfStripesProcessed;
    internal ulong TotalLength;
    internal ulong Seed;

    public XXH3State(ulong seed = 0)
    {
        this.Reset(seed);
    }

    ////static void
    ////XXH3_reset_internal(XXH3_state_t* statePtr,
    ////                    XXH64_hash_t seed,
    ////                    const void* secret, size_t secretSize)
    ////{
    ////    size_t const initStart = offsetof(XXH3_state_t, bufferedSize);
    ////    size_t const initLength = offsetof(XXH3_state_t, nbStripesPerBlock) - initStart;
    ////    XXH_ASSERT(offsetof(XXH3_state_t, nbStripesPerBlock) > initStart);
    ////    XXH_ASSERT(statePtr != NULL);
    ////    /* set members from bufferedSize to nbStripesPerBlock (excluded) to 0 */
    ////    memset((char*)statePtr + initStart, 0, initLength);
    ////    statePtr->acc[0] = XXH_PRIME32_3;
    ////    statePtr->acc[1] = XXH_PRIME64_1;
    ////    statePtr->acc[2] = XXH_PRIME64_2;
    ////    statePtr->acc[3] = XXH_PRIME64_3;
    ////    statePtr->acc[4] = XXH_PRIME64_4;
    ////    statePtr->acc[5] = XXH_PRIME32_2;
    ////    statePtr->acc[6] = XXH_PRIME64_5;
    ////    statePtr->acc[7] = XXH_PRIME32_1;
    ////    statePtr->seed = seed;
    ////    statePtr->useSeed = (seed != 0);
    ////    statePtr->extSecret = (const unsigned char*)secret;
    ////    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN);
    ////    statePtr->secretLimit = secretSize - XXH_STRIPE_LEN;
    ////    statePtr->nbStripesPerBlock = statePtr->secretLimit / XXH_SECRET_CONSUME_RATE;
    ////}
    [MemberNotNull(nameof(Accumulator))]
    [MemberNotNull(nameof(CustomSecret))]
    [MemberNotNull(nameof(Buffer))]
    public void Reset(ulong seed = 0)
    {
        this.NumberOfStripesProcessed = 0;
        this.TotalLength = 0;
        this.BufferedSize = 0;
        this.Seed = seed;

        if (this.Buffer != null)
        {
            this.Buffer.AsSpan().Clear();
        }
        else
        {
            this.Buffer = new byte[XXHashShared.XXH3_INTERNALBUFFER_SIZE];
        }

        if (this.Accumulator == null)
        {
            this.Accumulator = new ulong[8];
        }

        XXHashShared.XXH3_INIT_ACC.CopyTo(this.Accumulator);

        if (this.CustomSecret == null)
        {
            this.CustomSecret = new ulong[(int)XXHashShared.XXH_SECRET_DEFAULT_SIZE / sizeof(ulong)];
        }

        XXHash3.XXH3_initCustomSecret_scalar(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(XXHashShared.XXH3_kSecret)), ref MemoryMarshal.GetReference<ulong>(this.CustomSecret), seed);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ulong GetXXH3_64()
    {
        return XXHash3.XXH3_64bits_digest(this);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public XXH128Hash GetXXH3_128()
    {
        return XXHash3.XXH3_128bits_digest(this);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(byte[] data)
    {
        XXHash3.XXH3_update(this, ref MemoryMarshal.GetReference<byte>(data), (uint)data.Length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ReadOnlySpan<byte> data)
    {
        XXHash3.XXH3_update(this, ref MemoryMarshal.GetReference<byte>(data), (uint)data.Length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ReadOnlyMemory<byte> data)
    {
        XXHash3.XXH3_update(this, ref MemoryMarshal.GetReference<byte>(data.Span), (uint)data.Length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ReadOnlySpan<char> data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(data)), ((uint)data.Length) * 2);
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(short data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<short, byte>(ref data), sizeof(short));
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ushort data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<ushort, byte>(ref data), sizeof(ushort));
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(int data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<int, byte>(ref data), sizeof(int));
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(long data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<long, byte>(ref data), sizeof(long));
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(uint data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<uint, byte>(ref data), sizeof(uint));
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(ulong data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<ulong, byte>(ref data), sizeof(ulong));
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(UInt128 data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<UInt128, byte>(ref data), (uint)Unsafe.SizeOf<UInt128>());
    }

    // this is slow method, use of larger chunks is recomended
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Append(Int128 data)
    {
        XXHash3.XXH3_update(this, ref Unsafe.As<Int128, byte>(ref data), (uint)Unsafe.SizeOf<Int128>());
    }

    // decimal, double, float, datetime, timespan require complex conversion to match their equality rules

    public void Append(ReadOnlySequence<byte> data)
    {
        foreach (var segment in data)
        {
            XXHash3.XXH3_update(this, ref MemoryMarshal.GetReference<byte>(segment.Span), (uint)data.Length);
        }
    }

    public void Append(Stream stream, int blockSize = 1 << 16)
    {
        var block = ArrayPool<byte>.Shared.Rent(blockSize);

        try
        {
            int readBytes;
            while ((readBytes = stream.Read(block, 0, blockSize)) != 0)
            {
                this.Append(block.AsSpan(..readBytes));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(block);
        }
    }

    public async ValueTask AppendAsync(Stream stream, int blockSize = 1 << 16, CancellationToken cancellationToken = default)
    {
        var block = ArrayPool<byte>.Shared.Rent(blockSize);

        try
        {
            int readBytes;
            while ((readBytes = await stream.ReadAsync(block, cancellationToken)) != 0)
            {
                this.Append(block.AsSpan(..readBytes));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(block);   
        }
    }
}