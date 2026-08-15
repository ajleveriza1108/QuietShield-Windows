// QuietShield Backend Integration 01 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.DataSaving;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendIntegration01Tests
{
    [TestMethod]
    public void DataSavingProfileBuildsProtectedSystemPlan()
    {
        var state = new OperatingModeState(
            QuietShieldOperatingMode.WiFi,
            "Phone Hotspot",
            NetworkClassification.Limited,
            ["browser"]);

        var apps = new[]
        {
            new DataSavingApplicationDescriptor("browser", false),
            new DataSavingApplicationDescriptor("game", false),
            new DataSavingApplicationDescriptor("windows-core", true)
        };

        var health = Enum.GetValues<IntegratedProtectionModule>()
            .Select(static module => new ProtectionModuleHealth(module, true, false, "Ready"))
            .ToArray();

        var plan = IntegratedProtectionOrchestrator.Build(
            new(
                ProtectionProfilePreset.DataSaving,
                state,
                apps,
                health));

        Assert.IsTrue(plan.CanActivate);
        Assert.IsFalse(plan.MachineMutationRequested);
        Assert.AreEqual(
            DataSavingAccessDecision.SystemProtected,
            plan.DataSavingPlan.Applications.Single(item => item.Id == "windows-core").Decision);
        Assert.AreEqual(
            DataSavingAccessDecision.Blocked,
            plan.DataSavingPlan.Applications.Single(item => item.Id == "game").Decision);
    }

    [TestMethod]
    public void MissingRequiredModuleBlocksActivation()
    {
        var health = new[]
        {
            new ProtectionModuleHealth(
                IntegratedProtectionModule.ProgramConnectionLock,
                false,
                false,
                "Unavailable")
        };

        var plan = IntegratedProtectionOrchestrator.Build(
            new(
                ProtectionProfilePreset.Balanced,
                OperatingModeState.Default,
                Array.Empty<DataSavingApplicationDescriptor>(),
                health));

        Assert.IsFalse(plan.CanActivate);
        Assert.IsNotEmpty(plan.BlockingReasons);
    }
}
