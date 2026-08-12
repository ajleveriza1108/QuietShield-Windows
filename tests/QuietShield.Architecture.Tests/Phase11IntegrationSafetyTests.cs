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
    public void Phase11DGuiExposesCustomerWorkflowButNoDeveloperLifecycleOrRawEnforcementAction()
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
        StringAssert.Contains(programLock, "Persistent customer workflow");
        StringAssert.Contains(programLock, "Save protection policy");
        StringAssert.Contains(programLock, "Retry service connection");
        StringAssert.Contains(validator, "CustomerEnforcementControlsAbsent");
        StringAssert.Contains(validator, "CustomerWorkflowVisible");

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

    [TestMethod]
    public void Phase11DWorkflowUsesOnlySecureServiceIpcAndPreservesExactAuthorization()
    {
        var workflow = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Core", "ServiceFoundation", "DesktopProgramActivation.cs"));
        var viewModel = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "ViewModels", "Phase11DProgramActivationViewModel.cs"));
        foreach (var required in new[]
                 {
                     "RequestProgramRuleChange", "ProgramChangeAuthorizationId.Value", "TargetHashChanged",
                     "UnsupportedPersistentPolicy", "TransactionRolledBack", "RecoverySucceeded",
                     "Saved desktop state will not overwrite service recovery"
                 })
            StringAssert.Contains(workflow + viewModel, required);
        foreach (var prohibited in new[]
                 {
                     "Guid.Empty", "New-NetFirewallRule", "Remove-NetFirewallRule", "Set-DnsClientServerAddress",
                     "Process.Start", "sc.exe", "RunAs", "Start-Service", "New-Service"
                 })
            Assert.IsFalse((workflow + viewModel).Contains(prohibited, StringComparison.OrdinalIgnoreCase), prohibited);

        var discovery = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Windows", "Discovery", "WindowsStateDiscovery.cs"));
        StringAssert.Contains(discovery, "QuietShieldService");
    }

    [TestMethod]
    public void RepositoryToolchainPreflightHonorsCompatibleServicingPatchSemantics()
    {
        var scriptPath = Path.Combine(
            RepositoryRoot,
            "scripts",
            "Test-QuietShieldSdkCompatibility.ps1");
        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath })
            startInfo.ArgumentList.Add(argument);

        using var process = System.Diagnostics.Process.Start(startInfo);
        Assert.IsNotNull(process);
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        Assert.IsTrue(process.WaitForExit(15_000), "The SDK compatibility regression test timed out.");
        process.WaitForExit();
        var output = standardOutput.GetAwaiter().GetResult();
        var error = standardError.GetAwaiter().GetResult();
        Assert.AreEqual(0, process.ExitCode, error);

        using var result = System.Text.Json.JsonDocument.Parse(output);
        Assert.AreEqual("Passed", result.RootElement.GetProperty("status").GetString());
        var checks = result.RootElement.GetProperty("checks");
        foreach (var checkName in new[]
                 {
                     "exactRequestedPatchAccepted",
                     "laterSameFeatureBandPatchAccepted",
                     "earlierPatchRejected",
                     "nextFeatureBandRejected",
                     "prereleaseRejected",
                     "differentRollForwardPolicyRejected",
                     "visualStudioBaselinePatchAccepted",
                     "visualStudioNewerServicingPatchAccepted",
                     "visualStudioOlderServicingPatchRejected",
                     "visualStudioDifferentFeatureLineRejected",
                     "visualStudioIncompleteRejected",
                     "visualStudioUnlaunchableRejected",
                     "visualStudioPrereleaseRejected"
                 })
            Assert.IsTrue(checks.GetProperty(checkName).GetBoolean(), checkName);
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
