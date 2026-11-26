using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using XXHash.Benchmarks;

// 0xFFFF = logical processors 0-15, the P-cores of an i7-12700K.
BenchmarkRunner.Run<ByteBlockTests>(DefaultConfig.Instance.AddJob(Job.MediumRun.WithLaunchCount(1).WithAffinity(0x1)).WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default.WithRatioStyle(RatioStyle.Value)));