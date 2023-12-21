using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using XXHash.Benchmarks;

BenchmarkRunner.Run<PseudoRandomTest>(DefaultConfig.Instance.AddJob(Job.MediumRun).WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default.WithRatioStyle(RatioStyle.Value)));