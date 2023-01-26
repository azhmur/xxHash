using System.Data.HashFunction.xxHash;

namespace XXHash.Tests
{
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

                var managed64 = XXHash.Managed.XXHash64.XXH64(data, seed);
                var managed3_64 = XXHash.Managed.XXHash3.XXH3_64(data, seed);
                var managed3_128 = XXHash.Managed.XXHash3.XXH3_128(data, seed);

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


                if (golden3_128.low64 != managed3_128.Low || golden3_128.high64 != managed3_128.High)
                {
                    Console.WriteLine($"xx3_128 verification failed at length {i}");
                    return;
                }
            }

            Console.WriteLine("Validation succeded");
        }
    }
}