using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using XXHash.Benchmarks;

BenchmarkRunner.Run<StreamingTests>(DefaultConfig.Instance.AddJob(Job.MediumRun
    .WithEnvironmentVariable("DOTNET_TieredPGO", "0")).WithSummaryStyle(BenchmarkDotNet.Reports.SummaryStyle.Default.WithRatioStyle(RatioStyle.Value)));