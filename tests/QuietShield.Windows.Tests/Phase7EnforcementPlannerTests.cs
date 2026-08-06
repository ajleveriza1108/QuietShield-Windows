using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Protection;
using QuietShield.Windows.Planning;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class Phase7EnforcementPlannerTests
{
    private static readonly string[] AmbiguousEvidence = { "one", "two" };

    [TestMethod]
    public void PlannerIsDeterministicAndAlwaysIncludesRollback()
    {
        var planner = new WindowsProgramEnforcementPlanner();
        var first = planner.Plan(Rule(ProgramConnectionPolicy.WiFiOnly));
        var second = planner.Plan(Rule(ProgramConnectionPolicy.WiFiOnly));
        Assert.AreEqual(first, second);
        Assert.IsGreaterThanOrEqualTo(first.RollbackSteps.Count, 3);
        Assert.AreEqual(WindowsProposedEnforcementStrategy.UserModeWindowsFilteringPlatform, first.Strategy);
        Assert.IsFalse(first.CanExecute);
    }

    [TestMethod]
    public void PlannerRefusesMissingMovedAndAmbiguousTargets()
    {
        var planner = new WindowsProgramEnforcementPlanner();
        foreach (var identity in new[] { Win32(false), Win32(true).MarkMoved(@"D:\Moved\browser.exe"), ProgramIdentity.Ambiguous("Browser", AmbiguousEvidence) })
        {
            var plan = planner.Plan(new ConnectionLockProgramRule(identity, ProgramConnectionPolicy.Blocked));
            Assert.AreEqual(WindowsProposedEnforcementStrategy.Unsupported, plan.Strategy);
            Assert.IsNotNull(plan.UnsupportedOrAmbiguousReason);
            Assert.IsFalse(plan.CanExecute);
        }
    }

    [TestMethod]
    public void PlannerProposesWindowsFirewallForSimpleBlockButCannotExecute()
    {
        var plan = new WindowsProgramEnforcementPlanner().Plan(Rule(ProgramConnectionPolicy.Blocked));
        Assert.AreEqual(WindowsProposedEnforcementStrategy.WindowsFirewall, plan.Strategy);
        Assert.IsFalse(plan.CanExecute);
        StringAssert.Contains(plan.RequiredPrivilege, "Administrator");
    }

    private static ConnectionLockProgramRule Rule(ProgramConnectionPolicy policy) => new(Win32(true), policy);
    private static ProgramIdentity Win32(bool exists) => ProgramIdentity.CreateWin32("inventory:browser", "Browser", @"D:\Apps\Browser\browser.exe", "Contoso", exists);
}
