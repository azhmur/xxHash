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

public class ByteBlockTests
{
    private ulong seed;

    [Params(/*1,7,15,*/1 << 20)]
    public int length;

    public byte[] buffer;

    [GlobalSetup]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public void GlobalSetup()
    {
        var random = new Random();
        this.seed = unchecked((ulong)random.NextInt64());
        this.buffer = new byte[length];
        random.NextBytes(buffer);
    }

    [Benchmark]
    public ulong K4osXXhash64() => K4os.Hash.xxHash.XXH64.DigestOf(buffer);

    [Benchmark]
    public ulong StandartXXHash64()
    {
        return Standart.Hash.xxHash.xxHash64.ComputeHash(buffer, buffer.Length, seed);
    }

    [Benchmark]
    public ulong StandartXXHash3()
    {
        return Standart.Hash.xxHash.xxHash3.ComputeHash(buffer, buffer.Length, seed);
    }

    [Benchmark]
    public Standart.Hash.xxHash.uint128 StandartXXHash3_128()
    {
        return Standart.Hash.xxHash.xxHash128.ComputeHash(buffer, buffer.Length, seed);
    }

    [Benchmark]
    public ulong Wyhash() => WyHash.WyHash64.ComputeHash64(buffer, seed);

    [Benchmark]
    public ulong xxh3_64_Native() => XXHashNative.XXHash3_64(buffer, seed);

    [Benchmark]
    public XXH128_hash_t xxh3_128_Native() => XXHashNative.XXHash3_128(buffer, seed);

    [Benchmark]
    public ulong Xxh3Net() => XXHash3NET.XXHash3.Hash64(buffer, seed);

    [Benchmark()]
    public XXH128Hash Xxh3_128_NewManaged() => XXHash3.XXH3_128(buffer, seed);

    [Benchmark(Baseline = true)]
    public ulong Xxh3_NewManaged() => XXHash3.XXH3_64(buffer, seed);

    [Benchmark()]
    public ulong Xxh64_NewManaged() => XXHash64.XXH64(buffer, seed);

    [Benchmark]
    public int HashCodeAddBytes()
    {
        var hashCode = new HashCode();
        hashCode.AddBytes(buffer);
        return hashCode.ToHashCode();
    }

    [Benchmark]
    public ulong SystemXXHash64() => System.IO.Hashing.XxHash64.HashToUInt64(buffer, (long)seed);

    [Benchmark]
    public ulong SystemXXHash3_64() => System.IO.Hashing.XxHash3.HashToUInt64(buffer, (long)seed);

    [Benchmark]
    public UInt128 SystemXXHash3_128() => System.IO.Hashing.XxHash128.HashToUInt128(buffer, (long)seed);

    [Benchmark]
    public byte[] GetHashCodeSha256()
    {
        var result = new byte[32];

        SHA256.HashData(buffer, result);

        return result;
    }
}
