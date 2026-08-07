namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase10BRehearsalSafetyTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void Phase10BRehearsalCleanupUsesDirectScriptInvocationForConfirmFalse()
    {
        var path = Path.Combine(
            RepositoryRoot,
            "scripts",
            "Invoke-Phase10BServiceRehearsal.ps1");

        var source = File.ReadAllText(path);

        Assert.DoesNotContain(
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') -ApprovedEmergencyRestore -CleanupForUninstall -StateRoot 'D:\\QuietShield\\State' -Confirm:$false",
            source);

        Assert.DoesNotContain(
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') -ApprovedServiceUninstall -Confirm:$false",
            source);

        Assert.Contains(
            "& (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') -ApprovedEmergencyRestore -CleanupForUninstall -StateRoot 'D:\\QuietShield\\State' -Confirm:$false",
            source);

        Assert.Contains(
            "& (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') -ApprovedServiceUninstall -Confirm:$false",
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