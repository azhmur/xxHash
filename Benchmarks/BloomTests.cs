namespace XXHash.Benchmarks
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using BenchmarkDotNet.Attributes;
    using XXHash.Managed;

    public class BloomTests
    {
        private const int millibitsPerKey = 14000;
        private const int sizeInBytes = 64 * 200;
        private const int elementCount = 10000;

        private string[] nonExistingStrings;
        private string[] existingStrings;
        private BloomFilter bloomFilter;
        private HashSet<string> hashSet;


        [GlobalSetup]
        public void GlobalSetup()
        {
            this.bloomFilter = new BloomFilter(millibitsPerKey, sizeInBytes);
            this.hashSet = new HashSet<string>(elementCount);
            this.existingStrings = new string[elementCount];

            for (int i = 0; i < elementCount; ++i)
            {
                this.bloomFilter.AddHash($"hash{i}");
                this.hashSet.Add($"hash{i}");
                this.existingStrings[i] = $"hash{i}";
            }

            this.nonExistingStrings = new string[elementCount];
            for (int i = 0; i < elementCount; ++i)
            {
                this.nonExistingStrings[i] = $"non{i}";
            }
        }

        [Benchmark(OperationsPerInvoke = elementCount)]
        public bool MissingItemsBloomFilter() 
        {
            var result = false;
            for (int i = 0; i < elementCount; ++i)
            {
                result |= this.bloomFilter.HashMayMatch(this.nonExistingStrings[i]);
            }

            return result;
        }

        [Benchmark(OperationsPerInvoke = elementCount)]
        public bool MissingItemsHashSet()
        {
            var result = false;
            for (int i = 0; i < elementCount; ++i)
            {
                result |= this.hashSet.Contains(this.nonExistingStrings[i]);
            }

            return result;
        }

        [Benchmark(OperationsPerInvoke = elementCount)]
        public bool ExistingItemsBloomFilter()
        {
            var result = false;
            for (int i = 0; i < elementCount; ++i)
            {
                result |= this.bloomFilter.HashMayMatch(this.existingStrings[i]);
            }

            return result;
        }

        [Benchmark(OperationsPerInvoke = elementCount)]
        public bool ExistingItemsHashSet()
        {
            var result = false;
            for (int i = 0; i < elementCount; ++i)
            {
                result |= this.hashSet.Contains(this.existingStrings[i]);
            }

            return result;
        }
    }
}
