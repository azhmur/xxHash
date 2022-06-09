using System.Data.HashFunction.xxHash;

namespace XXHash.Tests
{
    internal class Program
    {
        static void Main(string[] args)
        {
            RandomTest();
        }

        static void RandomTest()
        {
            var seed = (ulong)Random.Shared.NextInt64();
            var data = new byte[Random.Shared.Next(5000)];
            Random.Shared.NextBytes(data);
            var golden = XXHash.Native.XXHashNative.XXHash3_64(data, seed);
            Console.WriteLine(golden);
            Console.WriteLine(XXHash3NET.XXHash3.Hash64(data, seed));
            Console.WriteLine(XXHash.Managed.XXHash3.XXHash3_64(data, seed));

            Console.WriteLine("===");
            var golden2 = XXHash.Native.XXHashNative.XXHash64(data, seed);
            Console.WriteLine(golden2);
            Console.WriteLine(Standart.Hash.xxHash.xxHash64.ComputeHash(data, data.Length, seed));
            Console.WriteLine(K4os.Hash.xxHash.XXH64.DigestOf(data));
            Console.WriteLine(BitConverter.ToUInt64(System.Data.HashFunction.xxHash.xxHashFactory.Instance.Create(new xxHashConfig() { Seed = seed, HashSizeInBits = 64 }).ComputeHash(data).Hash));
            Console.WriteLine(BitConverter.ToUInt64(Extensions.Data.XXHash64.Create(seed).ComputeHash(data)));
        }
    }
}