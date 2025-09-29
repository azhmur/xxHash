using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using XXHash.Benchmarks;

BenchmarkRunner.Run<ByteBlockTests>(DefaultConfig.Instance.AddJob(Job.MediumRun.WithLaunchCount(1)).WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default.WithRatioStyle(RatioStyle.Value)));