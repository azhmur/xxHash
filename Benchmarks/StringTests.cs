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
using xxHash3;
using xxHash3.Native;

namespace xxHash3.Benchmarks
{
    public class StringTests
    {
        private static readonly ulong seed = unchecked((ulong)Random.Shared.NextInt64());

        [Params(/*1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,*/51200)]
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
            var v = str.GetHashCode();
        }

        [Benchmark]
        public ulong K4osXXhash64()
        {
            return K4os.Hash.xxHash.XXH64.DigestOf(MemoryMarshal.AsBytes(str.AsSpan()));
        }

        [Benchmark]
        public ulong StandartXXHash()
        {
            var bytes = MemoryMarshal.AsBytes(str.AsSpan());
            return Standart.Hash.xxHash.xxHash64.ComputeHash(bytes, bytes.Length);
        }

        [Benchmark]
        public ulong StandartXXHash3_128()
        {
            var bytes = MemoryMarshal.AsBytes(str.AsSpan());
            return Standart.Hash.xxHash.xxHash128.ComputeHash(bytes, bytes.Length).low64;
        }

        [Benchmark]
        public void Wyhash()
        {
            var bytes = MemoryMarshal.AsBytes(str.AsSpan());
            WyHash.WyHash64.ComputeHash64(bytes);
        }

        [Benchmark]
        public unsafe ulong xxh3_64_Native()
        {
            return xxHash3Native.XXH3_64bits_withSeed(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(str.AsSpan())), (UIntPtr)(str.Length * 2), seed); 
        }

        [Benchmark]
        public ulong Xxh3Net()
        {
            return XXHash3NET.XXHash3.Hash64(MemoryMarshal.Cast<char, byte>(str.AsSpan()), seed); 
        }

        [Benchmark(Baseline = true)]
        public unsafe ulong Xxh3_NewManaged()
        {
            return Core.xxHash3.XXH3(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(str.AsSpan())), (uint)str.Length * 2, seed);
        }

        //[Benchmark]
        public unsafe void HashCodeAddBytes()
        {
            var hashCode = new HashCode();
            hashCode.AddBytes(MemoryMarshal.AsBytes(str.AsSpan()));
            hashCode.ToHashCode();
        }

        //[Benchmark]
        public unsafe int GetNonRandomizedHashCode()
        {
            fixed (char* src = this.str)
            {
                uint hash1 = (5381 << 16) + 5381;
                uint hash2 = hash1;

                uint* ptr = (uint*)src;
                int length = this.str.Length;

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
