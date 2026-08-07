namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase10BServicePackageRuntimeSafetyTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void PackageBuilderIncludesFirewallHelperCommonDependencies()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "New-QuietShieldServicePackage.ps1"));

        Assert.Contains("QuietShield.Script.Common.ps1", source);
        Assert.Contains("ServiceActivation.Script.Common.ps1", source);
        Assert.Contains("Invoke-ServiceFirewallPolicy.ps1", source);
    }

    [TestMethod]
    public void NonInteractiveFirewallConfirmationSuppressionIsBehindExplicitGates()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Invoke-ServiceFirewallPolicy.ps1"));

        var approval = source.IndexOf(
            "if (-not $ApprovedServiceEnforcement)",
            StringComparison.Ordinal);

        var admin = source.IndexOf(
            "if (-not (Test-QuietShieldAdministrator))",
            StringComparison.Ordinal);

        var confirm = source.IndexOf(
            "$ConfirmPreference = 'None'",
            StringComparison.Ordinal);

        Assert.IsGreaterThanOrEqualTo(0, approval);
        Assert.IsGreaterThan(approval, admin);
        Assert.IsGreaterThan(admin, confirm);

        Assert.Contains("SupportsShouldProcess = $true", source);
        Assert.Contains("ConfirmImpact = 'High'", source);
    }

    [TestMethod]
    public void DryGateExecutesPackagedFirewallHelperReadOnly()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Validate-Phase10B.ps1"));

        Assert.Contains(
            "packaged Firewall helper read-only runtime query",
            source);

        Assert.Contains("-Operation Query", source);
        Assert.Contains("-NonInteractive", source);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "QuietShield repository root could not be located.");
    }
}