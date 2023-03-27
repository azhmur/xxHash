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

namespace XXHash.Benchmarks;

public class StringTests
{
    private static readonly ulong seed = unchecked((ulong)Random.Shared.NextInt64());

    [Params(/*1,2,3,4,5,6,7,*/8/*,9,10,11,12,13,14,15,16,51200*/)]
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

    [Benchmark]
    public void StringGetHashCode() => str.GetHashCode();

    [Benchmark]
    public ulong K4osXXhash64() => K4os.Hash.xxHash.XXH64.DigestOf(MemoryMarshal.AsBytes(str.AsSpan()));

    [Benchmark]
    public ulong StandartXXHash64()
    {
        var bytes = MemoryMarshal.AsBytes(str.AsSpan());
        return Standart.Hash.xxHash.xxHash64.ComputeHash(bytes, bytes.Length);
    }

    [Benchmark]
    public ulong StandartXXHash3()
    {
        var bytes = MemoryMarshal.AsBytes(str.AsSpan());
        return Standart.Hash.xxHash.xxHash3.ComputeHash(bytes, bytes.Length);
    }

    [Benchmark]
    public Standart.Hash.xxHash.uint128 StandartXXHash3_128()
    {
        var bytes = MemoryMarshal.AsBytes(str.AsSpan());
        return Standart.Hash.xxHash.xxHash128.ComputeHash(bytes, bytes.Length);
    }

    [Benchmark]
    public ulong Wyhash() => WyHash.WyHash64.ComputeHash64(MemoryMarshal.AsBytes(str.AsSpan()));

    [Benchmark]
    public ulong xxh3_64_Native() => XXHashNative.XXHash3_64(str, seed);

    [Benchmark]
    public XXH128_hash_t xxh3_128_Native() => XXHashNative.XXHash3_128(str, seed);

    [Benchmark]
    public ulong Xxh3Net() => XXHash3NET.XXHash3.Hash64(MemoryMarshal.Cast<char, byte>(str.AsSpan()), seed);

    [Benchmark()]
    public XXH128Hash Xxh3_128_NewManaged() => XXHash3.XXH3_128(str, seed);

    [Benchmark(Baseline = true)]
    public ulong Xxh3_NewManaged() => XXHash3.XXH3_64(str, seed);

    [Benchmark()]
    public ulong Xxh64_NewManaged() => XXHash64.XXH64(str, seed);

    //[Benchmark]
    public int HashCodeAddBytes()
    {
        var hashCode = new HashCode();
        hashCode.AddBytes(MemoryMarshal.AsBytes(str.AsSpan()));
        return hashCode.ToHashCode();
    }

    [Benchmark]
    public int GetNonRandomizedHashCode() => GetNonRandomizedHashCode(this.str);

    [Benchmark]
    public ulong SystemXXHash64() => System.IO.Hashing.XxHash64.HashToUInt64(MemoryMarshal.AsBytes(str.AsSpan()), (long)seed);

    [Benchmark]
    public ulong SystemXXHash3_64() => System.IO.Hashing.XxHash3.HashToUInt64(MemoryMarshal.AsBytes(str.AsSpan()), (long)seed);

    [Benchmark]
    public UInt128 SystemXXHash3_128() => System.IO.Hashing.XxHash128.HashToUInt128(MemoryMarshal.AsBytes(str.AsSpan()), (long)seed);

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

    [Benchmark]
    public byte[] GetHashCodeSha256()
    {
        var result = new byte[32];

        SHA256.HashData(MemoryMarshal.Cast<char, byte>(str.AsSpan()), result);

        return result;
    }
}
