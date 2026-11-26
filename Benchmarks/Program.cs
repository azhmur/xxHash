using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using XXHash.Benchmarks;

// 0xFFFF = logical processors 0-15, the P-cores of an i7-12700K.
BenchmarkRunner.Run<SmallPseudoRandomTest>(DefaultConfig.Instance.AddJob(Job.MediumRun.WithLaunchCount(1).WithAffinity((IntPtr)0xFFFF)).WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default.WithRatioStyle(RatioStyle.Value)));