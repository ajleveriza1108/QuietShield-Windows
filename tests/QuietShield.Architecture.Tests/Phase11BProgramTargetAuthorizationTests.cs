namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase11BProgramTargetAuthorizationTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void ProgramTargetIdentityIsPathDerivedAndDeterministic()
    {
        var models = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Core",
            "ServiceFoundation",
            "ServiceActivationModels.cs"));

        foreach (var required in new[]
                 {
                     "ApprovedProgramTargetIdentity",
                     "windows-exe:",
                     "Path.GetFullPath",
                     "ToUpperInvariant",
                     "SHA256.HashData"
                 })
        {
            StringAssert.Contains(models, required);
        }
    }

    [TestMethod]
    public void CoordinatorAuthorizesOnlyActivationBoundPathHashAndIdentity()
    {
        var coordinator = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "PersistentProgramPolicyCoordinator.cs"));

        foreach (var required in new[]
                 {
                     "ApprovedProgramTargetIdentity.FromExecutablePath",
                     "_activation.ProbePath",
                     "_activation.ProbeSha256",
                     "requestedProgramPath",
                     "expectedStableIdentity",
                     "Only the currently approved program target may be changed"
                 })
        {
            StringAssert.Contains(coordinator, required);
        }

        Assert.IsFalse(
            coordinator.Contains(
                "Only QuietShield.ConnectionProbe is approved for the controlled rehearsal.",
                StringComparison.Ordinal));
    }

    [TestMethod]
    public void InstallerSupportsExplicitApprovedProgramWithoutBreakingLegacyProbeInput()
    {
        var installer = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Install-QuietShieldService.ps1"));

        foreach (var required in new[]
                 {
                     "AuthorizedProgramPath",
                     "ProbePath",
                     "Get-QuietShieldApprovedProgramIdentity",
                     "ReparsePoint",
                     "QuietShield.Service.exe",
                     "QuietShield.App.exe",
                     "authorizedStableApplicationIdentity"
                 })
        {
            StringAssert.Contains(installer, required);
        }

        StringAssert.Contains(
            installer,
            "Only one of -AuthorizedProgramPath or -ProbePath may be supplied.");
    }

    [TestMethod]
    public void Phase11BRehearsalUsesRelocatedRuntimeCompleteTargetAndExactCleanup()
    {
        var rehearsal = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "scripts",
            "Invoke-Phase11BProgramTargetRehearsal.ps1"));

        foreach (var required in new[]
                 {
                     "QuietShield.ConnectionProbe.dll",
                     "$sourceProbeDirectory",
                     "Copy-Item -Path (Join-Path $sourceProbeDirectory '*')",
                     "$sourceIdentity",
                     "$targetIdentity -ceq $sourceIdentity",
                     "Get-QuietShieldApprovedProgramIdentity",
                     "AuthorizedProgramPath",
                     "--control-request",
                     "AllowedOnAll",
                     "Restore-QuietShieldServiceState.ps1",
                     "Uninstall-QuietShieldService.ps1",
                     "QuietShield.ProgramLock.*"
                 })
        {
            StringAssert.Contains(rehearsal, required);
        }

        Assert.IsFalse(
            rehearsal.Contains(
                "stableApplicationIdentity = 'quietshield.connection-probe'",
                StringComparison.Ordinal));

        Assert.IsFalse(
            rehearsal.Contains(
                "QuietShield.CustomerProgramTarget.exe",
                StringComparison.Ordinal));
    }

    [TestMethod]
    public void HistoricalTransactionProgramIdentityIsRelaxedOnlyForCleanup()
    {
        var common = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "ServiceActivation.Script.Common.ps1"));
        var restore = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Restore-QuietShieldServiceState.ps1"));
        var firewall = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Invoke-ServiceFirewallPolicy.ps1"));

        StringAssert.Contains(common, "AllowHistoricalProgramIdentityForCleanup");
        StringAssert.Contains(common, "if (-not $AllowHistoricalProgramIdentityForCleanup)");
        StringAssert.Contains(
            restore,
            "-AllowHistoricalProgramIdentityForCleanup:$CleanupForUninstall");
        StringAssert.Contains(
            firewall,
            "-AllowHistoricalProgramIdentityForCleanup:($Operation -eq 'Cleanup')");

        Assert.IsFalse(
            firewall.Contains(
                "-AllowHistoricalProgramIdentityForCleanup:$true",
                StringComparison.Ordinal));
    }

    [TestMethod]
    public void CustomerFacingEnforcementControlsRemainAbsent()
    {
        var page = File.ReadAllText(Path.Combine(
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
                page.Contains(prohibited, StringComparison.OrdinalIgnoreCase),
                $"Phase 11B exposed a customer enforcement control prematurely: {prohibited}");
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
