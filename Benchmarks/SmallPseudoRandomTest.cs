using BenchmarkDotNet.Attributes;
using Standart.Hash.xxHash;
using System;
using System.Collections.Generic;
using System.IO.Hashing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using XXHash.Managed;
using XXHash.Native;

namespace XXHash.Benchmarks;

public class SmallPseudoRandomTest
{
    private const int itemsCount = 100000;
    private const int maxSize = 1 << 5;
    
    
    private ulong seed;
    private byte[][] data;

    [GlobalSetup]
    public void GlobalSetup()
    {
        var rand = new Random(42);
        this.seed = (ulong)rand.NextInt64();
        this.data = new byte[itemsCount][];

        for (int i = 0; i < itemsCount; i++) 
        {
            data[i] = new byte[rand.Next(maxSize)];
            rand.NextBytes(data[i]);
        }
    }

    [Benchmark(OperationsPerInvoke = itemsCount, Baseline = true)]
    public ulong Managed3_64()
    {
        ulong hash = 0;

        foreach (var item in data) 
        {
            hash ^= XXHash3.XXH3_64(item, seed);
        }

        return hash;
    }

    [Benchmark(OperationsPerInvoke = itemsCount)]
    public ulong System3_64()
    {
        ulong hash = 0;

        foreach (var item in data)
        {
            hash ^= XxHash3.HashToUInt64(item, (long)seed);
        }

        return hash;
    }

    [Benchmark(OperationsPerInvoke = itemsCount)]
    public ulong Native3_64()
    {
        ulong hash = 0;

        foreach (var item in data)
        {
            hash ^= XXHashNative.XXHash3_64(item, seed);
        }

        return hash;
    }

    //[Benchmark(OperationsPerInvoke = itemsCount)]
    public ulong Standart3_64()
    {
        ulong hash = 0;

        foreach (var item in data)
        {
            hash ^= xxHash3.ComputeHash(item, item.Length, seed);
        }

        return hash;
    }

    //[Benchmark(OperationsPerInvoke = itemsCount)]
    public UInt128 Managed3_128()
    {
        UInt128 hash = 0;

        foreach (var item in data)
        {
            var val = XXHash3.XXH3_128(item, seed).ToUInt128();
            hash ^= val;
        }

        return hash;
    }

    //[Benchmark(OperationsPerInvoke = itemsCount)]
    public UInt128 System3_128()
    {
        UInt128 hash = 0;

        foreach (var item in data)
        {
            var val = XxHash128.HashToUInt128(item, (long)seed);
            hash ^= val;
        }

        return hash;
    }

    //[Benchmark(OperationsPerInvoke = itemsCount)]
    public UInt128 Native3_128()
    {
        UInt128 hash = 0;

        foreach (var item in data)
        {
            var val = XXHashNative.XXHash3_128(item, seed).ToUInt128();
            hash ^= val;
        }

        return hash;
    }

    //[Benchmark(OperationsPerInvoke = itemsCount)]
    public UInt128 Standart3_128()
    {
        UInt128 hash = 0;

        foreach (var item in data)
        {
            var val = xxHash128.ComputeHash(item, item.Length, seed);
            hash ^= new UInt128(val.high64, val.low64);
        }

        return hash;
    }
}
