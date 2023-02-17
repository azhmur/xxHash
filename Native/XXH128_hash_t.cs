using System.Runtime.InteropServices;

namespace XXHash.Native
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct XXH128_hash_t : IEquatable<XXH128_hash_t>
    {
        public ulong low64;
        public ulong high64;

        public override bool Equals(object? obj)
        {
            return obj is XXH128_hash_t other &&
                   this.high64 == other.high64 &&
                   this.low64 == other.low64;
        }

        public static bool operator ==(XXH128_hash_t left, XXH128_hash_t right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(XXH128_hash_t left, XXH128_hash_t right)
        {
            return !left.Equals(right);
        }

        public UInt128 ToUInt128()
        {
            return new UInt128(high64, low64);
        }

        // SLOW AND UNSTABLE!
        public override int GetHashCode()
        {
            return HashCode.Combine(high64, low64);
        }

        public bool Equals(XXH128_hash_t other)
        {
            return this.high64 == other.high64 && this.low64 == other.low64;
        }

        public override string? ToString()
        {
            return $"{high64:X16}{low64:X16}";
        }

        public void Deconstruct(out ulong low64, out ulong high64)
        {
            low64 = this.low64;
            high64 = this.high64;
        }
    }
}
