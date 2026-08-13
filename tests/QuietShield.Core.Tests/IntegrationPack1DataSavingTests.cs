using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.DataSaving;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class IntegrationPack1DataSavingTests
{
    private static readonly DataSavingApplicationDescriptor[] Applications =
    [
        new("browser", false),
        new("sync-client", false),
        new("windows-core", true)
    ];

    [TestMethod]
    public void DataSavingBlocksUnselectedUserApplication()
    {
        var state = new OperatingModeState(
            QuietShieldOperatingMode.DataSaving,
            "Hotspot",
            NetworkClassification.Limited,
            ["browser"]);

        var plan = DataSavingPolicyPlanner.Build(Applications, state);
        var sync = plan.Applications.Single(static item => item.Id == "sync-client");

        Assert.AreEqual(DataSavingAccessDecision.Blocked, sync.Decision);
        Assert.IsFalse(plan.MachineEnforcementApplied);
    }

    [TestMethod]
    public void DataSavingAllowsSelectedUserApplication()
    {
        var state = new OperatingModeState(
            QuietShieldOperatingMode.DataSaving,
            "Hotspot",
            NetworkClassification.Limited,
            ["browser"]);

        var plan = DataSavingPolicyPlanner.Build(Applications, state);
        var browser = plan.Applications.Single(static item => item.Id == "browser");

        Assert.AreEqual(DataSavingAccessDecision.Allowed, browser.Decision);
    }

    [TestMethod]
    public void DataSavingProtectsWindowsSystemComponent()
    {
        var state = new OperatingModeState(
            QuietShieldOperatingMode.DataSaving,
            "Hotspot",
            NetworkClassification.Limited,
            Array.Empty<string>());

        var plan = DataSavingPolicyPlanner.Build(Applications, state);
        var system = plan.Applications.Single(static item => item.Id == "windows-core");

        Assert.AreEqual(DataSavingAccessDecision.SystemProtected, system.Decision);
    }

    [TestMethod]
    public void WiFiModeLeavesUserApplicationsAllowed()
    {
        var state = new OperatingModeState(
            QuietShieldOperatingMode.WiFi,
            "Home Wi-Fi",
            NetworkClassification.Unlimited,
            Array.Empty<string>());

        var plan = DataSavingPolicyPlanner.Build(Applications, state);
        var sync = plan.Applications.Single(static item => item.Id == "sync-client");

        Assert.AreEqual(DataSavingAccessDecision.Allowed, sync.Decision);
    }
}
