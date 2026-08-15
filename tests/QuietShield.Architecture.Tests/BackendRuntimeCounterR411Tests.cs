using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class BackendRuntimeCounterR411Tests
{
    [TestMethod]
    public void ProductionDnsCountersUsePolicyResultsRatherThanDiagnosticDomainLogging()
    {
        var repositoryRoot = FindRepositoryRoot();
        var path = Path.Combine(repositoryRoot, "src", "QuietShield.Service", "ProductionBackendRuntimeR40.cs");
        var source = File.ReadAllText(path);

        StringAssert.Contains(source, "internal sealed class ProductionCountingDnsPolicyR40 : IDnsRuntimePolicyEvaluator");
        StringAssert.Contains(source, "if (result.Decision == DnsDecision.Block)");
        StringAssert.Contains(source, "_statistics.Record(result.Category);");
        StringAssert.Contains(source, "new LocalDnsRuntime(options, _countingDnsPolicy, upstream);");
        StringAssert.Contains(source, "DnsIndeterminatePolicy.FailOpenToConfiguredUpstream,\n                false)");

        Assert.IsFalse(source.Contains("ProductionDnsEventSinkR40", StringComparison.Ordinal),
            "Production DNS counters must not depend on the diagnostic event sink.");
        Assert.IsFalse(source.Contains("_statistics.Record(_policy.Classify(entry.Domain))", StringComparison.Ordinal),
            "Production DNS counters must not re-classify diagnostic domain-log entries.");
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln")))
                return directory.FullName;
            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("QuietShield repository root was not found from the test output directory.");
    }
}
