using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using XXHash.Benchmarks;

BenchmarkRunner.Run<BloomTests>(DefaultConfig.Instance.AddJob(Job.ShortRun
    .WithEnvironmentVariable("DOTNET_TieredPGO", "0")).WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default.WithRatioStyle(RatioStyle.Value)));