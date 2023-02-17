namespace UnitTests;

using XXHash.Managed;

public class BloomFilterTests
{
    private readonly BloomFilter bloomFilter;

    public BloomFilterTests()
    {
        const int elementCount = 10000;
        const double fpRate = 0.001;

        var (sizeInBytes, millibitsPerKey) = BloomFilter.GenericSizeEstimation(elementCount, fpRate);
        this.bloomFilter = new BloomFilter(millibitsPerKey, sizeInBytes);
    }

    [Fact]
    public void AddedAreMatched()
    {
        this.bloomFilter.AddHash("xxx");
        this.bloomFilter.AddHash("yyy");

        Assert.True(this.bloomFilter.HashMayMatch("xxx"));
        Assert.True(this.bloomFilter.HashMayMatch("yyy"));
    }

    [Fact]
    public void EmptyNonMatched()
    {
        Assert.False(this.bloomFilter.HashMayMatch("xxx"));
        Assert.False(this.bloomFilter.HashMayMatch("yyy"));
    }

    // this depends on bloom filter settings and can produce false positives
    [Fact]
    public void NotAddedNonMatched()
    {
        this.bloomFilter.AddHash("xxx");
        this.bloomFilter.AddHash("yyy");
        
        Assert.False(this.bloomFilter.HashMayMatch("xxx1"));
        Assert.False(this.bloomFilter.HashMayMatch("yyy2"));
    }

    // this depends on bloom filter settings and can produce false positives
    [Fact]
    public void Intersect()
    {
        var otherFilter = new BloomFilter(this.bloomFilter);

        this.bloomFilter.AddHash("xxx");
        otherFilter.AddHash("yyy");
        this.bloomFilter.AddHash("zzz");
        otherFilter.AddHash("zzz");

        bloomFilter.Intersect(otherFilter);

        Assert.True(bloomFilter.PopCount() <= otherFilter.PopCount());

        Assert.False(this.bloomFilter.HashMayMatch("xxx"));
        Assert.False(this.bloomFilter.HashMayMatch("yyy"));
        Assert.True(this.bloomFilter.HashMayMatch("zzz"));
    }

    [Fact]
    public void Union()
    {
        var otherFilter = new BloomFilter(this.bloomFilter);

        this.bloomFilter.AddHash("xxx");
        otherFilter.AddHash("yyy");
        this.bloomFilter.AddHash("zzz");
        otherFilter.AddHash("zzz");

        bloomFilter.Union(otherFilter);
        Assert.True(bloomFilter.PopCount() >= otherFilter.PopCount());

        Assert.True(this.bloomFilter.HashMayMatch("xxx"));
        Assert.True(this.bloomFilter.HashMayMatch("yyy"));
        Assert.True(this.bloomFilter.HashMayMatch("zzz"));
    }
}