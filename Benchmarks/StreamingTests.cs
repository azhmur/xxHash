namespace XXHash.Benchmarks;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using XXHash.Managed;

public class StreamingTests
{
    private ulong seed;

    public byte[] data;

    [GlobalSetup]
    public void GlobalSetup()
    {
        this.data = new byte[512_000];
        var random = new Random(3442);
        this.seed = (ulong)random.NextInt64();
        random.NextBytes(this.data);
    }

    [Benchmark(Baseline = true)]
    public ulong Bulk() => XXHash3.XXH3_64(data, seed);

    [Benchmark()]
    public ulong Streaming()
    {
        var blockStart = 0;
        var blockEnd = 0;
        const int blockSize = 1 << 12;
        var state = new XXH3State(this.seed);

        while (blockEnd < data.Length) 
        {
            blockEnd = Math.Min(blockEnd + blockSize, this.data.Length);

            state.Append(this.data.AsSpan(blockStart..blockEnd));
            blockStart = blockEnd;
        }

        return state.GetXXH3_64();
    }
}
