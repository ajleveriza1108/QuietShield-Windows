namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class DnsRecoveryStaleAdapterR4211Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void MissingSavedAdapterCimLookupIsNarrowlyConvertedToNotLoopback()
    {
        var path = Path.Combine(RepositoryRoot, "src", "QuietShield.Service", "ProductionBackendRuntimeR40.cs");
        var source = File.ReadAllText(path);
        Assert.IsTrue(source.Contains("R4.2.11 stale adapter exception guard", StringComparison.Ordinal));
        Assert.IsTrue(source.Contains("catch (InvalidOperationException exception) when (", StringComparison.Ordinal));
        Assert.IsTrue(source.Contains("Get-DnsClientServerAddress", StringComparison.Ordinal));
        Assert.IsTrue(source.Contains("No matching MSFT_DNSClientServerAddress objects found", StringComparison.Ordinal));
        Assert.IsTrue(source.Contains("return false;", StringComparison.Ordinal));
    }

    [TestMethod]
    public void InterruptedRecoveryClearsOnlyStaleOriginalAndRetainsGuardedActivationOrder()
    {
        var path = Path.Combine(RepositoryRoot, "src", "QuietShield.Service", "ProductionBackendRuntimeR40.cs");
        var source = File.ReadAllText(path);
        var recovery = source.IndexOf("private async Task RecoverInterruptedDnsStateAsync", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, recovery);
        var nextMethod = source.IndexOf("\n    private ", recovery + 1, StringComparison.Ordinal);
        Assert.IsGreaterThan(recovery, nextMethod);
        var method = source.Substring(recovery, nextMethod - recovery);
        Assert.IsTrue(method.Contains("AdapterUsesLoopbackAsync", StringComparison.Ordinal));
        Assert.IsTrue(method.Contains("Original = null", StringComparison.Ordinal));
        var desiredDisabledCount = System.Text.RegularExpressions.Regex.Count(method, "DesiredEnabled = false");
        Assert.AreEqual(1, desiredDisabledCount,
            "Only the pre-existing invalid-null-state branch may disable desired protection; stale-adapter recovery must preserve it.");
        var udp = source.IndexOf("RunExternalProbeAsync(\"udp\"", StringComparison.Ordinal);
        var tcp = source.IndexOf("RunExternalProbeAsync(\"tcp\"", StringComparison.Ordinal);
        var mutation = source.IndexOf("SetAdapterDnsLoopbackAsync", StringComparison.Ordinal);
        Assert.IsTrue(udp >= 0 && tcp > udp && mutation > tcp, "External UDP then TCP proof must remain before adapter DNS mutation.");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("QuietShield repository root was not found.");
    }
}
