using System.Diagnostics;
using System.Text.Json;

namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase12InstallerArchitectureTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void InstallerSourceKeepsExplicitUacAndSystemMutationBoundaries()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "QuietShield.iss"));
        var policy = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "phase12-security-policy.json"));
        foreach (var required in new[] { "PrivilegesRequired=admin", "ArchitecturesAllowed=x64compatible", "RunProductionServiceInstall", "RunProductionServiceUninstall", "RestartIfNeededByRun=no" })
            StringAssert.Contains(source, required);
        foreach (var forbidden in new[] { "Set-DnsClientServerAddress", "New-NetFirewallRule", "Remove-NetFirewallRule", "-Verb RunAs", "ShellExec(" })
        {
            StringAssert.Contains(policy, forbidden);
            Assert.IsFalse(source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), forbidden);
        }
    }

    [TestMethod]
    public void InstallerUsesVersionedProductionPathsAndStableUpgradeIdentity()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "QuietShield.iss"));
        StringAssert.Contains(source, "DefaultDirName={autopf}\\QuietShield");
        StringAssert.Contains(source, "{app}\\App\\{#AppVersion}");
        StringAssert.Contains(source, "{app}\\Service\\{#AppVersion}");
        StringAssert.Contains(source, "6D13D40D-0A66-49F7-A422-235A2B89DA61");
        StringAssert.Contains(source, "{commonappdata}\\QuietShield\\Service");
    }

    [TestMethod]
    public void LifecycleScriptsRequireExactOwnershipAndNeverCreateRulesOrChangeDns()
    {
        var install = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "Install-QuietShieldProductionService.ps1"));
        var uninstall = File.ReadAllText(Path.Combine(RepositoryRoot, "installer", "Uninstall-QuietShieldProductionService.ps1"));
        var combined = install + uninstall;
        foreach (var required in new[] { "Test-QuietShieldProductionOwnership", "Name='QuietShieldService'", "ApprovedInstallerServiceRegistration", "ApprovedInstallerServiceUninstall", "CleanupForUninstall" })
            StringAssert.Contains(combined, required);
        foreach (var forbidden in new[] { "Get-NetFirewallRule", "New-NetFirewallRule", "Remove-NetFirewallRule", "Set-DnsClientServerAddress", "-Verb RunAs" })
            Assert.IsFalse(combined.Contains(forbidden, StringComparison.OrdinalIgnoreCase), forbidden);
    }

    [TestMethod]
    public void AuthoritativeVersionAndSourceOnlyPackageValidationPass()
    {
        var project = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "QuietShield.App.csproj"));
        var properties = File.ReadAllText(Path.Combine(RepositoryRoot, "Directory.Build.props"));
        StringAssert.Contains(properties, "<QuietShieldVersion>0.12.0-beta.1</QuietShieldVersion>");
        Assert.IsFalse(project.Contains("<Version>", StringComparison.Ordinal));

        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(RepositoryRoot, "scripts", "Test-QuietShieldBetaInstaller.ps1"), "-SourceOnly" })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start);
        Assert.IsNotNull(process);
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        Assert.IsTrue(process.WaitForExit(30_000));
        process.WaitForExit();
        var output = outputTask.GetAwaiter().GetResult();
        var error = errorTask.GetAwaiter().GetResult();
        Assert.AreEqual(0, process.ExitCode, error);
        using var json = JsonDocument.Parse(output);
        Assert.AreEqual("Passed", json.RootElement.GetProperty("status").GetString());
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
