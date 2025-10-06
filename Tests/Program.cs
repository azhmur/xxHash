using System.Data;
using System.Data.HashFunction.xxHash;
using BloomFilter;
using XXHash.Managed;

namespace XXHash.Tests;

internal class Program
{
    static void Main(string[] args)
    {
        Validate();
    }

    static void RandomTest()
    {
        var seed = (ulong)Random.Shared.NextInt64();
        var data = new byte[102400];
        Random.Shared.NextBytes(data);
        var golden = XXHash.Native.XXHashNative.XXHash3_64(data, seed);
        Console.WriteLine(golden);
        Console.WriteLine(XXHash3NET.XXHash3.Hash64(data, seed));
        Console.WriteLine(XXHash.Managed.XXHash3.XXH3_64(data, seed));

        Console.WriteLine("===");
        var golden2 = XXHash.Native.XXHashNative.XXHash64(data, seed);
        Console.WriteLine(golden2);
        Console.WriteLine(Standart.Hash.xxHash.xxHash64.ComputeHash(data, data.Length, seed));
        Console.WriteLine(K4os.Hash.xxHash.XXH64.DigestOf(data));
        Console.WriteLine(BitConverter.ToUInt64(System.Data.HashFunction.xxHash.xxHashFactory.Instance.Create(new xxHashConfig() { Seed = seed, HashSizeInBits = 64 }).ComputeHash(data).Hash));
        Console.WriteLine(BitConverter.ToUInt64(Extensions.Data.XXHash64.Create(seed).ComputeHash(data)));
        Console.WriteLine(XXHash.Managed.XXHash64.XXH64(data, seed));
    }

    static void Validate()
    {
        for (int i = 0; i < 1025; ++i)
        {
            var seed = (ulong)Random.Shared.NextInt64();
            var data = new byte[i];
            Random.Shared.NextBytes(data);
            
            var golden64 = XXHash.Native.XXHashNative.XXHash64(data, seed);
            var golden3_64 = XXHash.Native.XXHashNative.XXHash3_64(data, seed);
            var golden3_128 = XXHash.Native.XXHashNative.XXHash3_128(data, seed);

            var managed64 = XXHash64.XXH64(data, seed);
            var managed3_64 = XXHash3.XXH3_64(data, seed);
            var managed3_128 = XXHash3.XXH3_128(data, seed);

            if (golden3_64 != managed3_64)
            {
                Console.WriteLine($"xx3_64 verification failed at length {i}");
                return;
            }

            if (golden64 != managed64)
            {
                Console.WriteLine($"xx64 verification failed at length {i}");
                return;
            }


            if (managed3_128 != golden3_128.ToUInt128())
            {
                Console.WriteLine($"xx3_128 verification failed at length {i}");
                return;
            }
        }

        Console.WriteLine("Validation succeded");
    }

    static void BloomFilterTest2()
    {
        //const int millibitsPerKey = 7000;
        //const int sizeInBytes = 11700;
        const int elementCount = 10000;
        const double fpRate = 0.001;

        IBloomFilter bloomFilter = FilterBuilder.Build(elementCount, fpRate);

        for (int i = 0; i < elementCount; ++i)
        {
            bloomFilter.Add($"hash{i}");
        }

        for (int i = 0; i < elementCount; ++i)
        {
            if (!bloomFilter.Contains($"hash{i}"))
            {
                Console.WriteLine("False negative for hash{i}");
                return;
            }
        }

        var fpCount = 0;
        for (int i = 0; i < elementCount; ++i)
        {
            if (bloomFilter.Contains($"non{i}"))
            {
                ++fpCount;
            }
        }

        Console.WriteLine("Measured FP rate:" + (double)fpCount / elementCount);
    }

    static void BloomFilterTest()
    {
        const int millibitsPerKey = 32000;
        const int sizeInBytes = 1 << 16;
        const int elementCount = 10000;
        //const double fpRate = 0.001;

        //var (sizeInBytes, millibitsPerKey) = XXHash.Managed.BloomFilter.GenericSizeEstimation(elementCount, fpRate);
        var bloomFilter = new XXHash.Managed.BloomFilter(millibitsPerKey, sizeInBytes);

        for (int i = 0; i < elementCount; ++i)
        {
            bloomFilter.AddHash($"hash{i}");
        }


        Console.WriteLine(bloomFilter.SizeInBytes);
        Console.WriteLine("Estimated FP rate: " + XXHash.Managed.BloomFilter.EstimatedFpRate(elementCount, (ulong)bloomFilter.SizeInBytes, XXHash.Managed.BloomFilter.ChooseNumProbes(millibitsPerKey), 32));

        for (int i = 0; i < elementCount; ++i)
        {
            if (!bloomFilter.HashMayMatch($"hash{i}"))
            {
                Console.WriteLine("False negative for hash{i}");
                return;
            }
        }

        var fpCount = 0;
        for (int i = 0; i < elementCount; ++i)
        {
            if (bloomFilter.HashMayMatch($"non{i}"))
            {
                ++fpCount;
            }
        }

        Console.WriteLine("Measured FP rate:" + (double)fpCount / elementCount);
    }
}