namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class InstallerStableStartR4226Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void ProductionInstallerRequiresStableRunningStateAndOnlyOneRetry()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "Install-QuietShieldProductionService.ps1"));
        StringAssert.Contains(source, "R4.2.26 installer stable service start");
        StringAssert.Contains(source, "for ($attempt = 1; $attempt -le 2; $attempt++)");
        StringAssert.Contains(source, "Start-Sleep -Seconds 10");
        StringAssert.Contains(source, "if (-not $serviceStable)");
        StringAssert.Contains(source, "bounded start attempts=");
        Assert.AreEqual(1, Count(source, "for ($attempt = 1; $attempt -le 2; $attempt++)"));
    }

    [TestMethod]
    public void StableStartGatePrecedesInstalledSuccessResult()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "Install-QuietShieldProductionService.ps1"));
        var stableGate = source.IndexOf("if (-not $serviceStable)", StringComparison.Ordinal);
        var installed = source.IndexOf("status = 'Installed'", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, stableGate);
        Assert.IsGreaterThan(stableGate, installed);
    }

    private static int Count(string text, string value)
    {
        var count = 0;
        var offset = 0;
        while (true)
        {
            var index = text.IndexOf(value, offset, StringComparison.Ordinal);
            if (index < 0) return count;
            count++;
            offset = index + value.Length;
        }
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