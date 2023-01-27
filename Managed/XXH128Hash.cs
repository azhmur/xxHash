using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XXHash.Managed;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct XXH128Hash : IEquatable<XXH128Hash>
{
    public ulong Low; 
    public ulong High;

    public override bool Equals(object? obj)
    {
        return obj is XXH128Hash other &&
               this.High == other.High &&
               this.Low == other.Low;
    }

    public static bool operator ==(XXH128Hash left, XXH128Hash right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(XXH128Hash left, XXH128Hash right)
    {
        return !(left == right);
    }

    // SLOW AND UNSTABLE!
    public override int GetHashCode()
    {
        return HashCode.Combine(High, Low);
    }

    public bool Equals(XXH128Hash other)
    {
        return this.High == other.High && this.Low == other.Low;
    }

    public override string? ToString()
    {
        return $"{High:X16}{Low:X16}";
    }

    public void Deconstruct(out ulong low, out ulong high)
    {
        low = Low;
        high = High;
    }
}
