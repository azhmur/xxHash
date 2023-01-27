using BenchmarkDotNet.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using XXHash.Managed;
using XXHash.Native;

namespace XXHash.Benchmarks
{
    public class StringTests
    {
        private static readonly ulong seed = unchecked((ulong)Random.Shared.NextInt64());

        [Params(/*1,2,3,4,5,6,7,8,9,10,*/11/*,12,13,14,15,16,51200*/)]
        public int length;

        public string str;

        [GlobalSetup]
        public void GlobalSetup()
        {
            var bytes = new byte[length];
            var random = new Random();
            random.NextBytes(bytes);
            str = Encoding.ASCII.GetString(bytes);
        }

        //[Benchmark]
        public void StringGetHashCode()
        {
            var hash = str.GetHashCode();
        }

        //[Benchmark]
        public void K4osXXhash64()
        {
            var hash = K4os.Hash.xxHash.XXH64.DigestOf(MemoryMarshal.AsBytes(str.AsSpan()));
        }

        //[Benchmark]
        public void StandartXXHash64()
        {
            var bytes = MemoryMarshal.AsBytes(str.AsSpan());
            var hash = Standart.Hash.xxHash.xxHash64.ComputeHash(bytes, bytes.Length);
        }

        //[Benchmark]
        public void StandartXXHash3()
        {
            var bytes = MemoryMarshal.AsBytes(str.AsSpan());
            var hash = Standart.Hash.xxHash.xxHash3.ComputeHash(bytes, bytes.Length);
        }

        //[Benchmark]
        public void StandartXXHash3_128()
        {
            var bytes = MemoryMarshal.AsBytes(str.AsSpan());
            var hash = Standart.Hash.xxHash.xxHash128.ComputeHash(bytes, bytes.Length).low64;
        }

        //[Benchmark]
        public void Wyhash()
        {
            var hash = WyHash.WyHash64.ComputeHash64(MemoryMarshal.AsBytes(str.AsSpan()));
        }

        //[Benchmark]
        public void xxh3_64_Native()
        {
            var hash = XXHashNative.XXHash3_64(str, seed); 
        }

        [Benchmark]
        public XXH128_hash_t xxh3_128_Native() => XXHashNative.XXHash3_128(str, seed);

        //[Benchmark]
        public void Xxh3Net()
        {
            var hash = XXHash3NET.XXHash3.Hash64(MemoryMarshal.Cast<char, byte>(str.AsSpan()), seed); 
        }

        [Benchmark()]
        public XXH128Hash Xxh3_128_NewManaged() => XXHash3.XXH3_128(str, seed);

        //[Benchmark(Baseline = true)]
        public void Xxh3_NewManaged()
        {
            var hash = XXHash3.XXH3_64(str, seed);
        }

        //[Benchmark()]
        public void Xxh64_NewManaged()
        {
            var hash = XXHash64.XXH64(str, seed);
        }

        //[Benchmark]
        public void HashCodeAddBytes()
        {
            var hashCode = new HashCode();
            hashCode.AddBytes(MemoryMarshal.AsBytes(str.AsSpan()));
            var hash = hashCode.ToHashCode();
        }

        //[Benchmark]
        public void GetNonRandomizedHashCode()
        {
            var hash = GetNonRandomizedHashCode(this.str);
        }

        //[Benchmark]
        public void SystemXXHash64()
        {
            var hash = System.IO.Hashing.XxHash64.Hash(MemoryMarshal.AsBytes(str.AsSpan()), (long)seed);
        }

        private static unsafe int GetNonRandomizedHashCode(string str)
        {
            fixed (char* src = str)
            {
                uint hash1 = (5381 << 16) + 5381;
                uint hash2 = hash1;

                uint* ptr = (uint*)src;
                int length = str.Length;

                while (length > 2)
                {
                    length -= 4;
                    // Where length is 4n-1 (e.g. 3,7,11,15,19) this additionally consumes the null terminator
                    hash1 = (BitOperations.RotateLeft(hash1, 5) + hash1) ^ ptr[0];
                    hash2 = (BitOperations.RotateLeft(hash2, 5) + hash2) ^ ptr[1];
                    ptr += 2;
                }

                if (length > 0)
                {
                    // Where length is 4n-3 (e.g. 1,5,9,13,17) this additionally consumes the null terminator
                    hash2 = (BitOperations.RotateLeft(hash2, 5) + hash2) ^ ptr[0];
                }

                return (int)(hash1 + (hash2 * 1566083941));
            }
        }

        //[Benchmark]
        public unsafe void GetHashCodeSha256()
        {
            var data = MemoryMarshal.Cast<char, byte>(str.AsSpan());

            Span<byte> result = stackalloc byte[32];

            SHA256.HashData(data, result);
        }
    }
}
