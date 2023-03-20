namespace UnitTests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using XXHash.Managed;

public class StreamingTests
{
    [Fact]
    public void StreamingEmptyData()
    {
        var data = Array.Empty<byte>();
        var state = new XXH3State();
        state.Append(data);
        Assert.Equal(XXHash3.XXH3_64(data, 0), state.GetXXH3_64());
        Assert.Equal(XXHash3.XXH3_128(data, 0), state.GetXXH3_128());

        state.Reset(1);
        state.Append(data);
        Assert.Equal(XXHash3.XXH3_64(data, 1), state.GetXXH3_64());
        Assert.Equal(XXHash3.XXH3_128(data, 1), state.GetXXH3_128());
    }

    [Fact]
    public void RandomDataOneBlock()
    {
        var rand = new Random(1343);

        for (int i = 1; i < 1025; ++i)
        {
            var data = new byte[i];
            rand.NextBytes(data); 

            var state = new XXH3State();
            state.Append(data);
            Assert.Equal(XXHash3.XXH3_64(data, 0), state.GetXXH3_64());
            Assert.Equal(XXHash3.XXH3_128(data, 0), state.GetXXH3_128());

            var seed = (ulong)rand.NextInt64();
            state.Reset(seed);
            state.Append(data);
            Assert.Equal(XXHash3.XXH3_64(data, seed), state.GetXXH3_64());
            Assert.Equal(XXHash3.XXH3_128(data, seed), state.GetXXH3_128());
        }
    }

    [Fact]
    public void RandomDataMultipleBlocks()
    {
        var rand = new Random(1343);

        for (int i = 1; i < 16000; ++i)
        {
            var data = new byte[i];
            rand.NextBytes(data);
            var seed = (ulong)rand.NextInt64();

            var totalLength = 0;
            var lastLength = 0;
            var state = new XXH3State(seed);

            while (totalLength < data.Length)
            {
                var nextBlockSize = rand.Next(1024);
                totalLength += nextBlockSize;
                totalLength = Math.Min(totalLength, data.Length);

                state.Append(data[lastLength..totalLength]);
                Assert.Equal(XXHash3.XXH3_64(data.AsSpan(..totalLength), seed), state.GetXXH3_64());
                Assert.Equal(XXHash3.XXH3_128(data.AsSpan(..totalLength), seed), state.GetXXH3_128());
                lastLength = totalLength;
            }
        }
    }

    [Fact]
    public async ValueTask AppendStreamAsync()
    {
        var rand = new Random(1344);
        var data = new byte[123_123_123];
        rand.NextBytes(data);
        var seed = (ulong)rand.NextInt64();
        var stream = new MemoryStream(data);

        var state = new XXH3State(seed);
        await state.AppendAsync(stream);

        Assert.Equal(XXHash3.XXH3_64(data, seed), state.GetXXH3_64());
        Assert.Equal(XXHash3.XXH3_128(data, seed), state.GetXXH3_128());
    }
}
