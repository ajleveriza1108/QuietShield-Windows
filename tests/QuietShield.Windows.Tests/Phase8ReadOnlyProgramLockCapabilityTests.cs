using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Windows.Integration;
using QuietShield.Windows.Planning;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class Phase8ReadOnlyProgramLockCapabilityTests
{
    [TestMethod]
    public void WindowsCapabilityIsReadOnlyAndReportsServicesAndOwnedCount()
    {
        var firewall = new FirewallStateSnapshot(true, Array.Empty<FirewallProfileState>(), 2, DateTimeOffset.UtcNow);
        var services = new ServiceStateSnapshot(
            new("QuietShield", false, false, "Absent"),
            new("BFE", true, true, "Running"),
            new("MpsSvc", true, true, "Running"),
            new("NlaSvc", true, true, "Running"),
            DateTimeOffset.UtcNow);
        var result = new ReadOnlyProgramLockWindowsCapability().Inspect(firewall, services);
        Assert.IsTrue(result.WindowsFirewallServiceAvailable);
        Assert.IsTrue(result.BaseFilteringEngineAvailable);
        Assert.AreEqual(2, result.ExistingQuietShieldOwnedRuleCount);
        Assert.IsFalse(result.ModifyingImplementationRegistered);
    }

    [TestMethod]
    public void ReadOnlyCapabilityReportsAllSevenPolicies()
    {
        var matrix = new ReadOnlyProgramLockWindowsCapability().GetPolicySupportMatrix();
        Assert.HasCount(7, matrix);
        Assert.AreEqual(2, matrix.Count(static item => item.Support == PolicyEnforcementSupport.WindowsFirewallStatic));
        Assert.AreEqual(5, matrix.Count(static item => item.Support == PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement));
    }
}
