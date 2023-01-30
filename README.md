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

There are some others implementations available on nuget, but they are much slower or produce incorrect results.

# BloomFilter

BloomFilter avx2 optimized implementation is taken from Rocksdb. It can be hard to use as you should have good knowledge of your data in advance to tune number of parameters. Expect 1-2 bytes per key as good size estimation. 