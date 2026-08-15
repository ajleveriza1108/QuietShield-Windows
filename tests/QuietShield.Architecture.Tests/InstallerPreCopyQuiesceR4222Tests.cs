namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class InstallerPreCopyQuiesceR4222Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void InnoSetupQuiescesOwnedServiceBeforeFileReplacement()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "QuietShield.iss"));
        StringAssert.Contains(source, "function PrepareToInstall(var NeedsRestart: Boolean): String;");
        StringAssert.Contains(source, "Prepare-QuietShieldProductionUpgrade.ps1");
        StringAssert.Contains(source, "ExtractTemporaryFile('Prepare-QuietShieldProductionUpgrade.ps1')");
        StringAssert.Contains(source, "-ApprovedInstallerServiceQuiesce");
        var prepare = source.IndexOf("function PrepareToInstall", StringComparison.Ordinal);
        var postInstall = source.IndexOf("procedure RunProductionServiceInstall();", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, prepare);
        Assert.IsGreaterThan(prepare, postInstall);
    }

    [TestMethod]
    public void PreCopyHelperValidatesOwnershipBeforeStoppingAndRequiresDnsRestore()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "Prepare-QuietShieldProductionUpgrade.ps1"));
        var ownership = source.IndexOf("Test-QuietShieldProductionOwnership", StringComparison.Ordinal);
        var stop = source.IndexOf("Stop-Service -Name 'QuietShieldService'", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, ownership);
        Assert.IsGreaterThan(ownership, stop);
        StringAssert.Contains(source, "Get-DnsClientServerAddress");
        StringAssert.Contains(source, "127.0.0.1");
        StringAssert.Contains(source, "refusing file replacement");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("QuietShield repository root not found.");
    }
}