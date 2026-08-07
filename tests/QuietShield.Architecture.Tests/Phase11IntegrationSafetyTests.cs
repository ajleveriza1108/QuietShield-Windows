namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase11IntegrationSafetyTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void Phase11DesktopServiceIntegrationIsStatusOnlyAndNonElevating()
    {
        var serviceViewModel = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.App",
            "ViewModels",
            "Phase10AServiceStatusViewModel.cs"));

        foreach (var required in new[]
                 {
                     "RefreshServiceStatusCommand",
                     "RefreshPersistentServiceStatusAsync",
                     "validated service engine",
                     "Service endpoint unavailable"
                 })
        {
            StringAssert.Contains(serviceViewModel, required);
        }

        foreach (var prohibited in new[]
                 {
                     "Process.Start",
                     "sc.exe",
                     "New-NetFirewallRule",
                     "Remove-NetFirewallRule",
                     "Set-NetFirewallRule",
                     "RunAs"
                 })
        {
            Assert.IsFalse(
                serviceViewModel.Contains(prohibited, StringComparison.OrdinalIgnoreCase),
                $"Desktop service-status integration contains a prohibited mutation/elevation surface: {prohibited}");
        }
    }

    [TestMethod]
    public void Phase11GuiExposesRefreshButNoCustomerEnforcementAction()
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

        var validator = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.App",
            "Phase11GuiValidator.cs"));

        StringAssert.Contains(dashboard, "Refresh Service Status");
        StringAssert.Contains(dashboard, "Phase 10B validated");
        StringAssert.Contains(programLock, "Phase 11 connects");
        StringAssert.Contains(validator, "CustomerEnforcementControlsAbsent");

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
                $"Phase 11A exposed a customer enforcement action: {prohibited}");
        }
    }

    [TestMethod]
    public void Phase11KeepsProductionPipeLocalAndDnsActivationOutOfScope()
    {
        var app = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.App",
            "App.xaml.cs"));

        StringAssert.Contains(app, "QuietShieldServiceProtocol.ProductionPipeName");
        StringAssert.Contains(app, "--phase11-smoke");
        Assert.IsFalse(app.Contains("Set-DnsClientServerAddress", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(app.Contains("-Verb RunAs", StringComparison.OrdinalIgnoreCase));
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

        throw new InvalidOperationException("QuietShield repository root could not be located.");
    }
}
