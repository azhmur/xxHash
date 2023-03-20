namespace UnitTests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using XXHash.Managed;
using XXHash.Native;

public class ManagedvsNative
{
    [Fact]
    public void RandomDataOneBlock()
    {
        var rand = new Random(1343);

        for (int i = 0; i < 1025; ++i)
        {
            var data = new byte[i];
            rand.NextBytes(data);

            Assert.Equal(XXHash3.XXH3_64(data, 0), XXHashNative.XXHash3_64(data, 0));
            Assert.Equal(XXHash3.XXH3_128(data, 0).ToUInt128(), XXHashNative.XXHash3_128(data, 0).ToUInt128());

            var seed = (ulong)rand.NextInt64();
            Assert.Equal(XXHash3.XXH3_64(data, seed), XXHashNative.XXHash3_64(data, seed));
            Assert.Equal(XXHash3.XXH3_128(data, seed).ToUInt128(), XXHashNative.XXHash3_128(data, seed).ToUInt128());
        }
    }
}
