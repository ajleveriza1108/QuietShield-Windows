using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class BackendRuntimeDnsProbeR4011Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void ProductionDnsExternalProbeSuppliesAndValidatesRequiredProofOutput()
    {
        var serviceSource = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "ProductionBackendRuntimeR40.cs"));
        var probeSource = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.DnsHost",
            "DnsProbeCommand.cs"));

        var outputArgumentIndex = serviceSource.IndexOf(
            "ArgumentList.Add(\"--output\")",
            StringComparison.Ordinal);
        var processStartIndex = serviceSource.IndexOf(
            "if (!process.Start())",
            StringComparison.Ordinal);

        Assert.IsGreaterThanOrEqualTo(0, outputArgumentIndex, "Production DNS probe must supply the DnsHost-required --output argument.");
        Assert.IsGreaterThan(outputArgumentIndex, processStartIndex, "The proof-output argument must be configured before the external probe process starts.");
        Assert.IsTrue(serviceSource.Contains("DnsRehearsalRawProbe", StringComparison.Ordinal));
        Assert.IsTrue(serviceSource.Contains("validationSucceeded", StringComparison.Ordinal));
        Assert.IsTrue(serviceSource.Contains("responseCode.GetInt32() == 3", StringComparison.Ordinal));
        Assert.IsTrue(serviceSource.Contains("passed.ValueKind == JsonValueKind.True", StringComparison.Ordinal));
        Assert.IsTrue(serviceSource.Contains("File.Delete(probeOutputPath)", StringComparison.Ordinal));

        Assert.IsTrue(probeSource.Contains("RequirePath(\"output\")", StringComparison.Ordinal));
        Assert.IsTrue(probeSource.Contains("return passed ? 0 : 1", StringComparison.Ordinal));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln")))
                return directory.FullName;

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("QuietShield repository root was not found.");
    }
}
