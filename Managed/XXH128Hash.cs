using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XXHash.Managed;

public struct XXH128Hash : IEquatable<XXH128Hash>
{
    public ulong Low; 
    public ulong High;

    public XXH128Hash(ulong low, ulong high)
    {
        High = high; 
        Low = low;
    }

    public override bool Equals(object? obj)
    {
        return obj is XXH128Hash other &&
               this.High == other.High &&
               this.Low == other.Low;
    }

    public static bool operator ==(XXH128Hash left, XXH128Hash right) => left.Equals(right);

    public static bool operator !=(XXH128Hash left, XXH128Hash right) => !left.Equals(right);

    // SLOW AND UNSTABLE!
    public override int GetHashCode() => HashCode.Combine(High, Low);

    public bool Equals(XXH128Hash other) => this.High == other.High && this.Low == other.Low;

    public override string? ToString() => $"{High:X16}{Low:X16}";

    public UInt128 ToUInt128() => new (High, Low);

    public static implicit operator UInt128(XXH128Hash value) => new (value.High, value.Low);

    public void Deconstruct(out ulong low, out ulong high)
    {
        low = Low;
        high = High;
    }
}
