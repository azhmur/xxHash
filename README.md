# xxHash3
Fastest (2022-06-14) C#/NET implementation of Yan Collets XXHash64 and XXHash3_64 hash functions.

Nuget packets:

https://www.nuget.org/packages/XXHash.Native/ (Windows-x64, Linux-x64 SSE2)

https://www.nuget.org/packages/XXHash.Managed/

![Small strings](XXHash64%20vs%20XXHash3.png)
![Large string](XXHash64%20vs%20XXHash3%20Large.png)

Yan Collet reference C implementation: https://github.com/Cyan4973/xxHash

Alexander Melnik port: https://github.com/uranium62/xxHash

Milosz Krajewski port: https://github.com/MiloszKrajewski/K4os.Hash.xxHash

Microsoft port (recommended if you don't care that much about performance, XXH3 expected in .net 8): https://github.com/dotnet/runtime/tree/main/src/libraries/System.IO.Hashing/src/System/IO/Hashing

There are some others implementations available on nuget, but they are much slower or produce incorrect results.

# BloomFilter

BloomFilter avx2 optimized implementation is taken from Rocksdb. It can be hard to use as you should have good knowledge of your data in advance to tune number of parameters. Expect 1-2 bytes per key as good size estimation. 

# XXH3 Streaming mode

In case your input is larger than MaxArraySize in dotnet (~ 2 GiB), or it doesn't represented as continous block of memory at once you should use streaming mode.

```CSharp
var state = new XXH3State(seed: 10);
using var fileStream = File.OpenRead("largefile");
await state.AppendAsync(fileStream);
var hash64 = state.GetXXH3_64();
```

Calculating current hash value is non destructive and another portion of data can be added afterwise. Just keep in mind feeding very small blocks (like 1 byte) and repeatedly calculating hash value maybe slow.
Note: This isn't replacement for HashCode.Combne as far as XXH3State is rather big (>500 bytes).