namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase10BServiceAclSafetyTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void ServiceInstallUsesWindowsLocalSystemWellKnownSid()
    {
        var path = Path.Combine(
            RepositoryRoot,
            "scripts",
            "Install-QuietShieldService.ps1");

        var source = File.ReadAllText(path);

        Assert.DoesNotContain(
            "'*S-1-18:(OI)(CI)F'",
            source);

        Assert.Contains(
            "'*S-1-5-18:(OI)(CI)F'",
            source);
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