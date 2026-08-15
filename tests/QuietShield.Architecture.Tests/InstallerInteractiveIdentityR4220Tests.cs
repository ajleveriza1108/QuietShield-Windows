namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class InstallerInteractiveIdentityR4220Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void InnoSetupDoesNotUseElevatedUserProfileAsServiceAuthorizationIdentity()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "QuietShield.iss"));
        Assert.IsFalse(source.Contains("{userinfosid}", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("ExpandConstant('{localappdata}\\Programs')", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("-AuthorizedUserSid", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("-AuthorizedUserProgramsRoot", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void ProductionInstallerDerivesInteractiveUserSidAndProfileFailClosed()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "Install-QuietShieldProductionService.ps1"));
        foreach (var required in new[] { "R4.2.20 interactive installer identity", "Win32_ComputerSystem", ".UserName", "ProfileList", "Translate([Security.Principal.SecurityIdentifier])", "AppData\\Local\\Programs", "$AuthorizedUserSid = ''", "$AuthorizedUserProgramsRoot = ''" })
            StringAssert.Contains(source, required);
        Assert.IsFalse(source.Contains("WindowsIdentity]::GetCurrent().User.Value", StringComparison.OrdinalIgnoreCase));
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
