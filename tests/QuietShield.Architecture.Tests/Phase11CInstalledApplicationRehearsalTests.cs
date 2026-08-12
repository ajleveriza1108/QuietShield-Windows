namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase11CInstalledApplicationRehearsalTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void Phase11CSelectionRejectsSystemAndUnsafeTargets()
    {
        var common = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Phase11C.InstalledApp.Common.ps1"));

        foreach (var required in new[]
                 {
                     "Phase 11C refuses Windows-directory executables.",
                     @"\windowsapps\",
                     @"\.venv\",
                     @"\venv\",
                     @"\virtualenv\",
                     @"\quietshield\service\",
                     "ReparsePoint",
                     "QuietShield.Service.exe",
                     "QuietShield.App.exe",
                     "QuietShield.ConnectionProbe.exe",
                     "Program Files or LocalAppData\\Programs"
                 })
        {
            StringAssert.Contains(common, required);
        }
    }

    [TestMethod]
    public void Phase11CUsesOnlyDeterministicProbeAdapters()
    {
        var common = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Phase11C.InstalledApp.Common.ps1"));

        foreach (var required in new[]
                 {
                     "PythonBase",
                     "GitCurl",
                     "Node",
                     "Invoke-Phase11CNetworkProbe",
                     "example.com",
                     "--resolve",
                     "'-q'",
                     "--noproxy",
                     "proxy_used",
                     "remote_ip",
                     "directPathVerified",
                     "socket.create_connection",
                     "net.createConnection"
                 })
        {
            StringAssert.Contains(common, required);
        }
    }

    [TestMethod]
    public void Phase11CRehearsalBindsExactInstalledExecutableAndUsesServiceOnly()
    {
        var rehearsal = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Invoke-Phase11CInstalledApplicationRehearsal.ps1"));

        foreach (var required in new[]
                 {
                     "PHASE11C-SELECTION.json",
                     "Get-QuietShieldFileSha256",
                     "Get-QuietShieldApprovedProgramIdentity",
                     "Get-Phase11CRunningTargetProcesses",
                     "AuthorizedProgramPath",
                     "phase11c.installed-app",
                     "--control-request",
                     "Blocked",
                     "AllowedOnAll",
                     "Get-NetFirewallApplicationFilter",
                     "Uninstall-QuietShieldService.ps1",
                     "Compare-QuietShieldSafetySnapshots",
                     "PHASE-11C-INSTALLED-APP-REPORT.md"
                 })
        {
            StringAssert.Contains(rehearsal, required);
        }

        Assert.IsFalse(
            rehearsal.Contains(
                "New-NetFirewallRule",
                StringComparison.OrdinalIgnoreCase));

        Assert.IsFalse(
            rehearsal.Contains(
                "Set-DnsClientServerAddress",
                StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Phase11CStillKeepsCustomerEnforcementControlsAbsent()
    {
        var dashboard = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.App",
            "Pages",
            "DashboardPage.xaml"));

        var programLock = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.App",
            "Pages",
            "ProgramConnectionLockPage.xaml"));

        foreach (var prohibited in new[]
                 {
                     "Content=\"Install Service\"",
                     "Content=\"Start Service\"",
                     "Content=\"Apply\"",
                     "Content=\"Enforce\"",
                     "Content=\"Block Now\""
                 })
        {
            Assert.IsFalse(
                dashboard.Contains(prohibited, StringComparison.OrdinalIgnoreCase) ||
                programLock.Contains(prohibited, StringComparison.OrdinalIgnoreCase),
                $"Phase 11C exposed a customer enforcement action prematurely: {prohibited}");
        }
    }

    [TestMethod]
    public void ExistingInstallerStillRequiresExactAuthorizedProgramPath()
    {
        var installer = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Install-QuietShieldService.ps1"));

        foreach (var required in new[]
                 {
                     "AuthorizedProgramPath",
                     "Get-QuietShieldApprovedProgramIdentity",
                     "ReparsePoint",
                     "Windows-directory executables",
                     "QuietShield protection executables"
                 })
        {
            StringAssert.Contains(installer, required);
        }
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

        throw new InvalidOperationException(
            "QuietShield repository root could not be located.");
    }
}
